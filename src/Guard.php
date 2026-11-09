<?php

/*
 -------------------------------------------------------------------------
 MFA plugin for GLPI
 Copyright (C) 2022-2026 by the TICGAL Team.
 https://www.tic.gal
 -------------------------------------------------------------------------
 LICENSE
 This file is part of the MFA plugin.
 MFA plugin is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 3 of the License, or
 (at your option) any later version.
 MFA plugin is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 You should have received a copy of the GNU General Public License
 along with MFA. If not, see <http://www.gnu.org/licenses/>.
 --------------------------------------------------------------------------
 @package   MFA
 @author    the TICGAL team
 @copyright Copyright (c) 2026 TICGAL team
 @license   AGPL License 3.0 or (at your option) any later version
                http://www.gnu.org/licenses/agpl-3.0-standalone.html
 @link      https://www.tic.gal
 @since     2022
 ----------------------------------------------------------------------
*/

namespace GlpiPlugin\Mfa;

use Glpi\DBAL\QueryExpression;
use Glpi\Exception\Http\AccessDeniedHttpException;
use Glpi\Security\TOTPManager;
use Session;
use Symfony\Component\HttpFoundation\Response;
use Safe\Exceptions\UrlException;
use User;

use function Safe\parse_url;
use function Safe\preg_match;

/**
 * Server-side enforcement of the one-time code.
 *
 * Whatever endpoint created the session (the login form, `front/login.php`, a
 * remember-me cookie...), the first request that reaches this guard decides whether
 * a code is required. Until it is verified, every request is redirected to the code
 * form (or refused when it is not a page navigation).
 */
final class Guard
{
    private const SESSION_KEY = 'plugin_mfa';

    private const STATE_PENDING      = 'pending';
    private const STATE_VERIFIED     = 'verified';
    private const STATE_NOT_REQUIRED = 'not_required';

    /**
     * Session keys that identify the logged-in user. While a code is pending they are moved out
     * of the session (see stashIdentity()), so that nothing that trusts them, such as the
     * legacy API (`Session-Token`), the high-level API cookie authentication or any plugin,
     * sees an authenticated user before the code has been verified.
     */
    private const IDENTITY_KEYS = [
        'glpiID',
        'glpiname',
        'glpifriendlyname',
        'glpirealname',
        'glpifirstname',
        'glpiactiveprofile',
        'glpiprofiles',
        'glpiactiveentities',
        'glpiactiveentities_string',
        'glpiactive_entity',
        'glpiactive_entity_recursive',
        'glpiparententities',
        'glpigroups',
        'glpi_use_mode',
    ];

    /** Cache key prefix: the user went through the native 2FA enrolment during the current login. */
    private const ENROLLMENT_FLAG = 'plugin_mfa_enrolling_';

    private const ENROLLMENT_FLAG_TTL = 1800;

    /** The end-of-request evaluation of a freshly opened session is registered only once. */
    private static bool $shutdown_registered = false;

    /**
     * Set while serving the "stop impersonating" request of a session that already passed the guard.
     * Never persisted: it only lives until the session is rebuilt, inside the same request.
     */
    private static bool $carry_verification = false;

    /** Scripts reachable while the code is pending (paths relative to the GLPI root). */
    private const EXEMPT_PATHS = [
        '/plugins/mfa/front/mfa.form.php',
        '/front/logout.php',
    ];

    /**
     * Hooked on `post_init`: runs on every request, before any controller.
     */
    public static function enforce(): void
    {
        global $CFG_GLPI;

        if (isCommandLine()) {
            return;
        }

        self::refusePasswordGrant();

        if (isAPI()) {
            return;
        }

        self::trackEnrollment();

        $state = $_SESSION[self::SESSION_KEY]['state'] ?? null;
        if ($state === self::STATE_PENDING) {
            $users_id = self::getPendingUserId();
        } else {
            $users_id = (int) Session::getLoginUserID();
            if ($users_id <= 0) {
                return;
            }
        }

        if ($state === self::STATE_VERIFIED || $state === self::STATE_NOT_REQUIRED) {
            // Ending an impersonation makes the core rebuild the session (Session::init()), which
            // drops this plugin's state. The request comes from a session that already passed the
            // guard, so its verification is handed to the rebuilt session by onSessionInit().
            self::$carry_verification = self::isStopImpersonationRequest();

            return;
        }

        if ($state === null) {
            if (self::isExemptRequest() && !self::isCodeFormRequest()) {
                // Logging out must stay possible before the first evaluation.
                return;
            }
            if (self::isOpenedBeforeActivation()) {
                // Whoever was already signed in when the plugin was activated is not thrown
                // out to a code form nobody announced; the plugin applies to new sessions.
                $_SESSION[self::SESSION_KEY] = ['state' => self::STATE_NOT_REQUIRED];

                return;
            }
            // Normally the session was already evaluated when it was opened (see
            // evaluateOpenedSession()); this covers the sessions that could not be.
            self::evaluateSession($users_id);
            if (!self::isPending()) {
                return;
            }
        }

        if ($_SESSION[self::SESSION_KEY]['send_pending'] ?? false) {
            $_SESSION[self::SESSION_KEY]['send_pending'] = false;
            self::sendCode($users_id);
        }

        if (self::isExemptRequest()) {
            return;
        }

        if (!self::isPageNavigation()) {
            throw new AccessDeniedHttpException();
        }

        $_SESSION[self::SESSION_KEY]['redirect'] ??= self::getRequestedUri();
        // Html::redirect() throws a RedirectException, which is only handled once the request
        // is being routed; this guard runs earlier, at kernel boot. Any other exception would
        // be logged as CRITICAL by the core (only 4xx are not) on every login, so the redirect
        // is sent directly. The session is written by PHP's shutdown handler.
        header('Location: ' . $CFG_GLPI['root_doc'] . '/plugins/mfa/front/mfa.form.php', true, Response::HTTP_FOUND);
        exit;
    }

    /**
     * Remember when the plugin was activated (database clock), see isOpenedBeforeActivation().
     */
    public static function markActivation(): void
    {
        global $DB;

        $row = $DB->request([
            'SELECT' => [new QueryExpression('NOW()', 'now')],
            'FROM'   => 'glpi_configs',
            'LIMIT'  => 1,
        ])->current();
        if (is_array($row) && isset($row['now'])) {
            \Config::setConfigurationValues('plugin:mfa', ['activated_at' => (string) $row['now']]);
        }
    }

    /**
     * Was the session opened before the plugin was last activated? Compared in SQL, against the
     * clock of the database that recorded both moments.
     */
    private static function isOpenedBeforeActivation(): bool
    {
        $activated_at = \Config::getConfigurationValue('plugin:mfa', 'activated_at');
        $login_session_uid = $_SESSION['login_session_uid'] ?? null;
        if (!is_string($activated_at) || $activated_at === '' || !is_string($login_session_uid)) {
            return false;
        }

        return countElementsInTable('glpi_users_sessions', [
            'login_session_uid' => $login_session_uid,
            'created_at'        => ['<', $activated_at],
        ]) > 0;
    }

    /**
     * The high-level API token endpoint validates a login and password without opening a
     * session (no init_session hook, no code form), so the OAuth "password" grant is refused
     * for the accounts that need a code. The other grants do not take the password.
     */
    private static function refusePasswordGrant(): void
    {
        if (
            ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
            || preg_match('#^/api\.php(/v[\d.]+)?/token/?$#', self::requestPath()) !== 1
            || ($_POST['grant_type'] ?? null) !== 'password'
            || !is_string($_POST['username'] ?? null)
        ) {
            return;
        }

        $user = new User();
        if ($user->getFromDBbyName($_POST['username']) && self::isCodeRequired((int) $user->getID(), false)) {
            throw new AccessDeniedHttpException(
                __('This account needs a one-time security code and cannot sign in with a password only.', 'mfa'),
            );
        }
    }

    /**
     * Decide whether the session of this request needs a code and, if so, leave it pending.
     */
    private static function evaluateSession(int $users_id): void
    {
        if (isset($_SESSION['impersonator_info']) || !self::isCodeRequired($users_id)) {
            // Impersonation can only be started from a session that already passed this guard.
            $_SESSION[self::SESSION_KEY] = ['state' => self::STATE_NOT_REQUIRED];

            return;
        }

        $identity = [];
        foreach (self::IDENTITY_KEYS as $key) {
            if (array_key_exists($key, $_SESSION)) {
                $identity[$key] = $_SESSION[$key];
                unset($_SESSION[$key]);
            }
        }

        // The debug bar fires requests the pending session cannot answer, and it would expose
        // data of a session nobody has verified: the page is rendered in normal mode meanwhile.
        $_SESSION['glpi_use_mode'] = Session::NORMAL_MODE;

        $_SESSION[self::SESSION_KEY] = [
            'state'        => self::STATE_PENDING,
            'users_id'     => $users_id,
            'identity'     => $identity,
            'redirect'     => null,
            'issued'       => false,
            'notice'       => null,
            'send_pending' => true,
        ];
    }

    /**
     * Registered (through init_session) when the core opens a session: evaluates it when the
     * request ends, once the core has finished filling it, and before PHP writes it. That way
     * a pending session is already stripped of its identity when the browser (or anybody who
     * obtained the cookie) makes its next request, whatever endpoint that request reaches,
     * including the ones that start their session after `post_init`.
     */
    public static function evaluateOpenedSession(): void
    {
        if (
            session_status() !== PHP_SESSION_ACTIVE
            || isset($_SESSION[self::SESSION_KEY]['state'])
        ) {
            return;
        }

        $users_id = (int) Session::getLoginUserID();
        if ($users_id > 0) {
            self::evaluateSession($users_id);
        }
    }

    /**
     * Send a code unless it cannot be delivered or too many were sent recently; in that case the
     * reason is kept in the session as a notice for the user.
     */
    private static function sendCode(int $users_id): void
    {
        $problem = Mfa::deliveryProblem($users_id);
        if ($problem === null && !Mfa::consumeIssue($users_id)) {
            $problem = __('Too many security codes were requested recently. Use the last code you received or try again later.', 'mfa');
        }

        if ($problem !== null) {
            $_SESSION[self::SESSION_KEY]['notice'] = $problem;

            return;
        }

        $mfa_id = Mfa::issueCode($users_id);
        if (Mfa::isSendFailed($mfa_id)) {
            // The mail server refused it: the page is reloaded to try again once it is fixed.
            $_SESSION[self::SESSION_KEY]['notice'] = __('The security code could not be sent: the mail server did not accept the message. Contact your administrator.', 'mfa');

            return;
        }

        $_SESSION[self::SESSION_KEY]['issued'] = true;
        $_SESSION[self::SESSION_KEY]['notice'] = null;
    }

    /**
     * While no code was sent for this session, try again: the reason it was not sent (for
     * instance disabled notifications) may have been fixed since the session started.
     */
    public static function retryDelivery(): void
    {
        if (!self::isPending() || ($_SESSION[self::SESSION_KEY]['issued'] ?? false)) {
            return;
        }

        self::sendCode(self::getPendingUserId());
    }

    /**
     * Message explaining why no code was sent for this session, if any.
     */
    public static function getNotice(): ?string
    {
        $notice = $_SESSION[self::SESSION_KEY]['notice'] ?? null;

        return is_string($notice) ? $notice : null;
    }

    /**
     * Hooked on `init_session`, which the core fires from Session::init() once it has rebuilt
     * the session and set the user in it.
     *
     * - Ending an impersonation: restores the verification, only for the request flagged by enforce().
     * - A session opened by CalDAV or by the legacy API with login and password never goes
     *   through the code form, so it is refused when the account needs a code.
     * - Any other session is evaluated at the end of the request (see evaluateOpenedSession()).
     */
    public static function onSessionInit(): void
    {
        if (self::$carry_verification) {
            self::$carry_verification = false;
            $_SESSION[self::SESSION_KEY] = ['state' => self::STATE_VERIFIED];

            return;
        }

        if (isCommandLine()) {
            return;
        }

        $is_api = isAPI();
        if ($is_api || str_starts_with(self::requestPath(), '/caldav.php')) {
            // These entry points never show the code form. The legacy API opens a session with
            // login and password (a `user_token` is a different credential) and CalDAV always
            // authenticates with the password alone; both are refused when a code is required.
            $password_only = !$is_api || !isset($_REQUEST['user_token']);
            $users_id = (int) Session::getLoginUserID();
            if ($password_only && $users_id > 0 && !isset($_SESSION['impersonator_info']) && self::isCodeRequired($users_id)) {
                // Fail closed: leave nothing usable behind.
                foreach (self::IDENTITY_KEYS as $key) {
                    unset($_SESSION[$key]);
                }
                throw new AccessDeniedHttpException(
                    __('This account needs a one-time security code and cannot sign in with a password only.', 'mfa'),
                );
            }

            return;
        }

        if (!self::$shutdown_registered) {
            self::$shutdown_registered = true;
            register_shutdown_function([self::class, 'evaluateOpenedSession']);
        }
    }

    /**
     * Identifier of the user whose code is pending (the session has no user while it is pending).
     */
    public static function getPendingUserId(): int
    {
        return (int) ($_SESSION[self::SESSION_KEY]['users_id'] ?? Session::getLoginUserID());
    }

    private static function isStopImpersonationRequest(): bool
    {
        return ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST'
            && self::requestPath() === '/front/user.form.php'
            && isset($_POST['impersonate'])
            && !$_POST['impersonate']
            && Session::isImpersonateActive();
    }

    /**
     * Is the current session waiting for a verified code?
     */
    public static function isPending(): bool
    {
        return ($_SESSION[self::SESSION_KEY]['state'] ?? null) === self::STATE_PENDING;
    }

    /**
     * Mark the session as verified; returns the URL originally requested, if any.
     */
    public static function markVerified(): ?string
    {
        $redirect = $_SESSION[self::SESSION_KEY]['redirect'] ?? null;
        $identity = $_SESSION[self::SESSION_KEY]['identity'] ?? [];
        if (is_array($identity)) {
            foreach ($identity as $key => $value) {
                if (in_array($key, self::IDENTITY_KEYS, true)) {
                    $_SESSION[$key] = $value;
                }
            }
        }
        $_SESSION[self::SESSION_KEY] = ['state' => self::STATE_VERIFIED];

        return is_string($redirect) ? $redirect : null;
    }

    /**
     * Does this user have to enter a code?
     *
     * Users with GLPI's native 2FA enabled are not asked twice: the core already required a
     * TOTP code before the session existed. Only a TOTP that already existed when this login
     * started counts: one enrolled during the login itself (core's /MFA/Setup step) was
     * created by whoever typed the password, so it proves nothing (see trackEnrollment()).
     * A mandatory 2FA policy (global, entity, profile or group) with no TOTP set up yet, as
     * in a grace period where the user skipped the setup, has verified no second factor,
     * so the plugin still asks for its code.
     */
    private static function isCodeRequired(int $users_id, bool $consume_enrollment_flag = true): bool
    {
        global $GLPI_CACHE;

        $user = new User();
        if (!$user->getFromDB($users_id)) {
            return false;
        }

        $enrolled_during_login = (bool) $GLPI_CACHE->get(self::ENROLLMENT_FLAG . $users_id, false);
        if ($consume_enrollment_flag) {
            $GLPI_CACHE->delete(self::ENROLLMENT_FLAG . $users_id);
        }

        if (!$enrolled_during_login && (new TOTPManager())->is2FAEnabled($users_id)) {
            return false;
        }

        return (bool) (new Config())->needCode($user->fields['authtype']);
    }

    /**
     * While a login waits in the core's pre-authentication state without a TOTP (the user is
     * being sent to, or is on, the enrolment step), remember it for this user. A user who
     * already had a TOTP is never sent there, so the flag only exists for logins that created
     * their TOTP themselves. It is consumed when the session is evaluated.
     */
    private static function trackEnrollment(): void
    {
        global $GLPI_CACHE;

        $users_id = (int) ($_SESSION['mfa_pre_auth']['user_id'] ?? 0);
        if ($users_id > 0 && !(new TOTPManager())->is2FAEnabled($users_id)) {
            $GLPI_CACHE->set(self::ENROLLMENT_FLAG . $users_id, true, self::ENROLLMENT_FLAG_TTL);
        }
    }

    /**
     * The requested URI relative to the GLPI root, which is how the core expects redirections
     * (it prepends the root itself).
     */
    private static function getRequestedUri(): ?string
    {
        global $CFG_GLPI;

        $uri = $_SERVER['REQUEST_URI'] ?? null;
        $root = (string) ($CFG_GLPI['root_doc'] ?? '');
        if (is_string($uri) && $root !== '' && str_starts_with($uri, $root . '/')) {
            return substr($uri, strlen($root));
        }

        return $uri;
    }

    private static function requestPath(): string
    {
        global $CFG_GLPI;

        try {
            $path = (string) parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
        } catch (UrlException) {
            // Malformed URI: no known path, so it is never exempt.
            return '';
        }
        $root = (string) ($CFG_GLPI['root_doc'] ?? '');

        return ($root !== '' && str_starts_with($path, $root)) ? substr($path, strlen($root)) : $path;
    }

    private static function isExemptRequest(): bool
    {
        return in_array(self::requestPath(), self::EXEMPT_PATHS, true);
    }

    private static function isCodeFormRequest(): bool
    {
        return self::requestPath() === '/plugins/mfa/front/mfa.form.php';
    }

    /**
     * A top-level GET a browser can follow a redirect for (not AJAX, not a fetch/XHR).
     */
    private static function isPageNavigation(): bool
    {
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
            return false;
        }
        if (($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') === 'XMLHttpRequest') {
            return false;
        }

        return ($_SERVER['HTTP_SEC_FETCH_MODE'] ?? 'navigate') === 'navigate'
            && !str_contains($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json');
    }
}
