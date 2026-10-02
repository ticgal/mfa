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

use Glpi\Application\View\TemplateRenderer;
use Glpi\DBAL\QueryExpression;
use Glpi\Security\TOTPManager;
use Symfony\Component\Cache\Adapter\Psr16Adapter;
use Symfony\Component\RateLimiter\LimiterInterface;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\RateLimiter\Storage\CacheStorage;

if (!defined('GLPI_ROOT')) {
    die("Sorry. You can't access directly to this file");
}

class PluginMfaMfa extends CommonDBTM
{
    /** Failed verifications allowed per user before lock-out. */
    public const MAX_ATTEMPTS = 5;

    /** Sliding window over which MAX_ATTEMPTS is counted. */
    public const LOCKOUT_INTERVAL = '15 minutes';

    /** Codes that can be issued per user before issuance is throttled. */
    public const MAX_ISSUES = 3;

    /** Sliding window over which MAX_ISSUES is counted. */
    public const ISSUE_INTERVAL = '10 minutes';

    /** Minutes a security code stays valid. Enforced at verification time. */
    public const CODE_TTL_MINUTES = 10;

    public static function getTypeName($nb = 0)
    {
        return 'MFA';
    }

    /**
     * Sliding-window rate limiter keyed per user. Mirrors the core 2FA limiter
     * (TOTPManager::getMFARateLimiter) but under its own id so the counters never
     * interfere. A distinct $id is used for verification and for issuance.
     */
    private static function getRateLimiter(string $id, int $limit, string $interval, int $users_id): LimiterInterface
    {
        global $GLPI_CACHE;

        $factory = new RateLimiterFactory(
            [
                'id'       => $id,
                'policy'   => 'sliding_window',
                'limit'    => $limit,
                'interval' => $interval,
            ],
            new CacheStorage(new Psr16Adapter($GLPI_CACHE))
        );

        return $factory->create('user_' . $users_id);
    }

    /**
     * Run $fn while holding an exclusive per-user lock.
     *
     * The Symfony rate limiter is built without a LockFactory (the Lock component
     * is not shipped with GLPI), so its read-modify-write of the sliding window is
     * not atomic: concurrent requests could each read the same counter and let more
     * than MAX_ATTEMPTS through. An flock() on a per-user file serialises those
     * requests on a single node. A multi-node deployment needs a shared lock
     * (Redis/PDO) or a shared cache backend; see README.
     */
    private static function withUserLock(int $users_id, callable $fn)
    {
        $handle = @fopen(GLPI_TMP_DIR . '/plugin_mfa_user_' . $users_id . '.lock', 'c');
        if ($handle === false) {
            // Best effort: never block authentication because the lock file cannot
            // be opened. The limiter still runs, just without the extra guarantee.
            return $fn();
        }

        try {
            flock($handle, LOCK_EX);
            return $fn();
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    /**
     * Consume one verification attempt for the user.
     *
     * @return bool true if the attempt is allowed, false if the user is locked out.
     */
    public static function consumeAttempt(int $users_id): bool
    {
        return self::withUserLock(
            $users_id,
            static fn(): bool => self::getRateLimiter('plugin_mfa_verify', self::MAX_ATTEMPTS, self::LOCKOUT_INTERVAL, $users_id)
                ->consume(1)->isAccepted()
        );
    }

    /**
     * Reset the failure counter after a successful verification.
     */
    public static function clearAttempts(int $users_id): void
    {
        self::getRateLimiter('plugin_mfa_verify', self::MAX_ATTEMPTS, self::LOCKOUT_INTERVAL, $users_id)->reset();
    }

    /**
     * Consume one issuance slot for the user. Prevents a password holder from
     * flooding the mailbox and repeatedly invalidating the legitimate code by
     * triggering a fresh send on every request.
     *
     * @return bool true if a new code may be issued, false if issuance is throttled.
     */
    public static function consumeIssue(int $users_id): bool
    {
        return self::withUserLock(
            $users_id,
            static fn(): bool => self::getRateLimiter('plugin_mfa_issue', self::MAX_ISSUES, self::ISSUE_INTERVAL, $users_id)
                ->consume(1)->isAccepted()
        );
    }

    public static function cronInfo($name)
    {
        switch ($name) {
            case 'expiredSecurityCode':
                return [
                    'description' => __('One-Time Security Code expiration', 'mfa'),
                    'parameter'   => __('Duration (in minutes)', 'mfa')
                ];
        }
        return [];
    }

    public static function cronExpiredSecurityCode($task)
    {
        global $CFG_GLPI, $DB;

        $duration = (int)$task->fields['param'];

        $query = [
            'FROM' => self::getTable(),
            'WHERE' => [
                new \Glpi\DBAL\QueryExpression(
                    sprintf(
                        'ADDDATE(%s, INTERVAL %s MINUTE) <= NOW()',
                        $DB->quoteName('date_creation'),
                        $duration
                    )
                ),
            ]
        ];
        $iterator = $DB->request($query);
        foreach ($iterator as $row) {
            $task->addVolume(1);
            $task->log(
                sprintf(
                    __('Deleted the One-Time Security Code of the user %s', 'mfa'),
                    getUserName($row['users_id'])
                )
            );

            $mfa = new self();
            $mfa->delete(['id' => $row['id']]);
        }

        return 1;
    }

    public static function showCodeForm()
    {
        $template = '@mfa/mfa.html.twig';
        $template_options = [
            'url' => Toolbox::getItemTypeFormURL(__CLASS__),
            'csrf_token' => Session::getNewCSRFToken(),
        ];
        TemplateRenderer::getInstance()->display($template, $template_options);
    }

    /**
     * Whether the currently authenticated user still has to pass this plugin's
     * second factor in the current session.
     *
     * Shared by the request-time enforcement hook and the challenge endpoint so
     * both decide identically. Returns false when: the code was already verified
     * in this session; the user is covered by GLPI native 2FA (handled by the core
     * at login, so adding the plugin code would be a redundant double factor); or
     * the authentication type used for this session is not configured to require a
     * code. It fails closed on a missing configuration (see PluginMfaConfig::needCode).
     */
    public static function userMustVerify(int $users_id): bool
    {
        if ($users_id <= 0) {
            return false;
        }

        if (self::isVerified()) {
            return false;
        }

        // An impersonated session is driven by an operator who has already
        // authenticated (and passed their own MFA); the impersonated user's code
        // would be delivered to that user, not the operator, so never challenge it.
        if (Session::isImpersonateActive()) {
            return false;
        }

        // Native 2FA takes precedence: the core already prompted/enforced it during
        // Auth::login(), so the plugin must not require a second, separate code.
        $totp = new TOTPManager();
        if (
            $totp->is2FAEnabled($users_id)
            || $totp->get2FAEnforcement($users_id) !== TOTPManager::ENFORCEMENT_OPTIONAL
        ) {
            return false;
        }

        $authtype = $_SESSION['glpiauthtype'] ?? 0;
        return PluginMfaConfig::getConfig()->needCode($authtype);
    }

    /**
     * Whether the current session has already cleared this plugin's second factor.
     *
     * Bound to the authenticated user id (not the PHP session id): the flag lives
     * in $_SESSION, which GLPI rebuilds from scratch on every Session::init() (login,
     * impersonation), so it cannot leak into another session; binding to the user id
     * additionally survives a mid-session id regeneration without forcing a spurious
     * re-challenge, and still forces verification if the session somehow serves a
     * different user.
     */
    public static function isVerified(): bool
    {
        return isset($_SESSION['plugin_mfa_verified'])
            && (int) $_SESSION['plugin_mfa_verified'] === (int) Session::getLoginUserID();
    }

    /**
     * Mark the current session as having passed the second factor and drop the
     * pending challenge state.
     */
    public static function markVerified(): void
    {
        $_SESSION['plugin_mfa_verified'] = (int) Session::getLoginUserID();
        unset($_SESSION['plugin_mfa_pending']);
    }

    /**
     * Paths that must stay reachable while the user is authenticated but has not
     * yet passed the second factor, so the challenge page can render and the user
     * can always escape by logging out.
     *
     * POST_INIT runs before the static-asset listener, so real static files (any
     * non-PHP extension) are let through here; otherwise the challenge page would
     * load without styles. The compiled CSS is served by the PHP endpoint
     * /front/css.php, which is allow-listed explicitly.
     */
    public static function isAllowedWhileUnverified(string $path): bool
    {
        $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        if ($extension !== '' && preg_match('/^php\d*$/', $extension) !== 1) {
            return true;
        }

        $allowed_suffixes = [
            '/plugins/mfa/front/mfa.form.php',
            '/front/logout.php',
            '/front/css.php',
            '/front/locale.php',
        ];
        foreach ($allowed_suffixes as $suffix) {
            if (str_ends_with($path, $suffix)) {
                return true;
            }
        }

        return false;
    }

    public static function getRandomInt($length)
    {
        $keyspace = '0123456789';
        $str = '';
        $max = mb_strlen($keyspace, '8bit') - 1;
        for ($i = 0; $i < $length; ++$i) {
            $str .= $keyspace[random_int(0, $max)];
        }
        // No cross-table uniqueness check: codes are bound to users_id and stored
        // hashed, so a plaintext collision across users is neither detectable here
        // nor relevant to security.
        return $str;
    }

    /**
     * Issue a fresh security code for the user and send it by notification.
     *
     * Any previous pending code is discarded first, so a code can never be reused
     * across login attempts. The code is stored hashed (only the notification
     * carries the plaintext), so a read of the table during its validity window
     * does not hand over a usable second factor.
     */
    public static function issueCode(int $users_id): int
    {
        global $DB;

        $mfa = new self();
        foreach ($DB->request(['SELECT' => 'id', 'FROM' => self::getTable(), 'WHERE' => ['users_id' => $users_id]]) as $row) {
            $mfa->delete(['id' => $row['id']]);
        }

        $plain = self::getRandomInt(6);
        $mfa->add([
            'users_id' => $users_id,
            'code'     => password_hash($plain, PASSWORD_DEFAULT),
        ]);
        $mfa_id = (int) $mfa->getID();

        // Stamp date_creation with the DB clock. CommonDBTM::add() would write it from
        // $_SESSION['glpi_currenttime'], which follows GLPI's configured timezone and
        // can differ from the DB clock by the server's UTC offset; verifyCode compares
        // against NOW(), so both ends must use the same clock or the TTL is meaningless.
        $DB->update(
            self::getTable(),
            ['date_creation' => new QueryExpression('NOW()')],
            ['id' => $mfa_id]
        );

        // The e-mail must carry the plaintext, not the stored hash. The notification
        // target reads it straight from this in-memory object (getObjectItem does not
        // reload from DB), so overriding the field here is enough.
        $mfa->fields['code'] = $plain;
        NotificationEvent::raiseEvent('securitycodegenerate', $mfa, ['entities_id' => 0]);

        return $mfa_id;
    }

    /**
     * Whether the given challenge row is the user's own pending code and still
     * within its validity window. Used to decide whether a fresh code must be
     * issued or the existing one can be reused, so navigating while unverified
     * does not re-send a code on every request.
     */
    public static function isPendingValid(int $users_id, int $mfa_id): bool
    {
        if ($users_id <= 0 || $mfa_id <= 0) {
            return false;
        }

        return countElementsInTable(self::getTable(), [
            'id'       => $mfa_id,
            'users_id' => $users_id,
            new QueryExpression(
                'date_creation >= (NOW() - INTERVAL ' . self::CODE_TTL_MINUTES . ' MINUTE)'
            ),
        ]) > 0;
    }

    /**
     * Verify a submitted code against a specific pending challenge of the user.
     * Consumes (deletes) the pending code on success. Fails closed on a missing,
     * expired or non-matching code.
     *
     * The challenge is identified by $mfa_id, which the caller holds in the server
     * side session (never from the request). This binds the code to the session
     * that was issued it: a code generated for one pending session cannot be used
     * to complete another, and a stale pending that points at an already-consumed
     * row simply fails.
     */
    public static function verifyCode(int $users_id, string $code, int $mfa_id): bool
    {
        global $DB;

        if ($code === '' || $users_id <= 0 || $mfa_id <= 0) {
            return false;
        }

        $mfa = new self();
        if (!$mfa->getFromDBByCrit(['id' => $mfa_id, 'users_id' => $users_id])) {
            return false;
        }

        // Reject a code older than its TTL, regardless of whether the cleanup cron
        // has run yet. Done in SQL against the DB clock so it stays correct whatever
        // the timezone offset between PHP and the database (see issueCode). TTL is an
        // int class constant, so the expression carries no user input.
        $still_valid = countElementsInTable(self::getTable(), [
            'id' => $mfa_id,
            new QueryExpression(
                'date_creation >= (NOW() - INTERVAL ' . self::CODE_TTL_MINUTES . ' MINUTE)'
            ),
        ]) > 0;

        if (!$still_valid) {
            $DB->delete(self::getTable(), ['id' => $mfa_id]);
            return false;
        }

        if (!password_verify($code, (string) $mfa->fields['code'])) {
            return false;
        }

        // Atomic consume: the DELETE is the serialization point. If two concurrent
        // requests both pass password_verify for the same row, only one DELETE
        // affects a row; the other sees 0 affected rows and is rejected. This
        // guarantees a single winner without an application lock, and a failed
        // delete can never be reported as success.
        $DB->delete(self::getTable(), ['id' => $mfa_id]);
        return $DB->affectedRows() === 1;
    }

    public static function install(Migration $migration)
    {
        global $DB;

        $default_charset = DBConnection::getDefaultCharset();
        $default_collation = DBConnection::getDefaultCollation();
        $default_key_sign = DBConnection::getDefaultPrimaryKeySignOption();

        $table = self::getTable();

        if (!$DB->tableExists($table)) {
            $migration->displayMessage("Installing $table");
            $query = "CREATE TABLE IF NOT EXISTS $table (
				`id` int {$default_key_sign} NOT NULL auto_increment,
				`users_id` int {$default_key_sign} NOT NULL DEFAULT '0',
				`code` varchar(255) DEFAULT NULL,
				`date_creation` timestamp NULL DEFAULT NULL,
				PRIMARY KEY (`id`),
                KEY `users_id` (`users_id`)
			) ENGINE=InnoDB  DEFAULT CHARSET={$default_charset} COLLATE={$default_collation} ROW_FORMAT=DYNAMIC;";

            $DB->doQuery($query);
        }
    }

    public static function uninstall(Migration $migration)
    {
        $table = self::getTable();
        $migration->displayMessage("Uninstalling $table");
        $migration->dropTable($table);
    }
}
