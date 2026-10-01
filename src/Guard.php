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

use Glpi\Exception\Http\AccessDeniedHttpException;
use Profile;
use Session;
use Symfony\Component\HttpFoundation\Response;
use Safe\Exceptions\UrlException;
use User;

use function Safe\parse_url;

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

        if (isCommandLine() || isAPI()) {
            return;
        }

        $users_id = (int) Session::getLoginUserID();
        if ($users_id <= 0) {
            return;
        }

        $state = $_SESSION[self::SESSION_KEY]['state'] ?? null;
        if ($state === self::STATE_VERIFIED || $state === self::STATE_NOT_REQUIRED) {
            return;
        }

        if ($state === null) {
            if (self::isExemptRequest() && !self::isCodeFormRequest()) {
                // Logging out must stay possible before the first evaluation.
                return;
            }
            if (isset($_SESSION['impersonator_info']) || !self::isCodeRequired($users_id)) {
                // Impersonation can only be started from a session that already passed this guard.
                $_SESSION[self::SESSION_KEY] = ['state' => self::STATE_NOT_REQUIRED];
                return;
            }
            $_SESSION[self::SESSION_KEY] = [
                'state'    => self::STATE_PENDING,
                'redirect' => null,
                'issued'   => false,
                'notice'   => null,
            ];
            self::sendCode($users_id);
        }

        if (self::isExemptRequest()) {
            return;
        }

        if (!self::isPageNavigation()) {
            throw new AccessDeniedHttpException();
        }

        $_SESSION[self::SESSION_KEY]['redirect'] ??= $_SERVER['REQUEST_URI'] ?? null;
        // Html::redirect() throws a RedirectException, which is only handled once the request
        // is being routed; this guard runs earlier, at kernel boot. Any other exception would
        // be logged as CRITICAL by the core (only 4xx are not) on every login, so the redirect
        // is sent directly. The session is written by PHP's shutdown handler.
        header('Location: ' . $CFG_GLPI['root_doc'] . '/plugins/mfa/front/mfa.form.php', true, Response::HTTP_FOUND);
        exit;
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

        Mfa::issueCode($users_id);
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

        self::sendCode((int) Session::getLoginUserID());
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
        $_SESSION[self::SESSION_KEY] = ['state' => self::STATE_VERIFIED];

        return is_string($redirect) ? $redirect : null;
    }

    /**
     * Does this user have to enter a code? Users covered by GLPI's native 2FA are not
     * asked twice: the core already required its own second factor to create the session.
     */
    private static function isCodeRequired(int $users_id): bool
    {
        $user = new User();
        if (!$user->getFromDB($users_id)) {
            return false;
        }

        if (!empty($user->fields['2fa_secret'])) {
            return false;
        }

        $profile = new Profile();
        $profiles_id = $_SESSION['glpiactiveprofile']['id'] ?? null;
        if ($profiles_id && $profile->getFromDB($profiles_id) && (int) ($profile->fields['2fa_enforced'] ?? 0) === 1) {
            return false;
        }

        return (bool) (new Config())->needCode($user->fields['authtype']);
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
