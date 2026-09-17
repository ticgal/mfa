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

    /** Minutes a security code stays valid. Enforced at verification time. */
    public const CODE_TTL_MINUTES = 10;

    public static function getTypeName($nb = 0)
    {
        return 'MFA';
    }

    /**
     * Rate limiter for code verification, keyed per user. Mirrors the core 2FA
     * limiter (TOTPManager::getMFARateLimiter) but under its own id so the two
     * counters never interfere.
     */
    private static function getRateLimiter(int $users_id): LimiterInterface
    {
        global $GLPI_CACHE;

        $factory = new RateLimiterFactory(
            [
                'id'       => 'plugin_mfa_verify',
                'policy'   => 'sliding_window',
                'limit'    => self::MAX_ATTEMPTS,
                'interval' => self::LOCKOUT_INTERVAL,
            ],
            new CacheStorage(new Psr16Adapter($GLPI_CACHE))
        );

        return $factory->create('user_' . $users_id);
    }

    /**
     * Consume one verification attempt for the user.
     *
     * @return bool true if the attempt is allowed, false if the user is locked out.
     */
    public static function consumeAttempt(int $users_id): bool
    {
        return self::getRateLimiter($users_id)->consume(1)->isAccepted();
    }

    /**
     * Reset the failure counter after a successful verification.
     */
    public static function clearAttempts(int $users_id): void
    {
        self::getRateLimiter($users_id)->reset();
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
            'redirect' => $_POST["redirect"] ?? '',
            'csrf_token' => Session::getNewCSRFToken()
        ];
        TemplateRenderer::getInstance()->display($template, $template_options);
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
    public static function issueCode(int $users_id): void
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

        // Stamp date_creation with the DB clock. CommonDBTM::add() would write it from
        // $_SESSION['glpi_currenttime'], which follows GLPI's configured timezone and
        // can differ from the DB clock by the server's UTC offset; verifyCode compares
        // against NOW(), so both ends must use the same clock or the TTL is meaningless.
        $DB->update(
            self::getTable(),
            ['date_creation' => new \Glpi\DBAL\QueryExpression('NOW()')],
            ['id' => $mfa->getID()]
        );

        // The e-mail must carry the plaintext, not the stored hash. The notification
        // target reads it straight from this in-memory object (getObjectItem does not
        // reload from DB), so overriding the field here is enough.
        $mfa->fields['code'] = $plain;
        NotificationEvent::raiseEvent('securitycodegenerate', $mfa, ['entities_id' => 0]);
    }

    /**
     * Verify a submitted code for the user. Consumes (deletes) the pending code on
     * success. Fails closed on a missing, expired or non-matching code.
     */
    public static function verifyCode(int $users_id, string $code): bool
    {
        if ($code === '') {
            return false;
        }

        $mfa = new self();
        if (!$mfa->getFromDBByCrit(['users_id' => $users_id])) {
            return false;
        }

        // Reject a code older than its TTL, regardless of whether the cleanup cron
        // has run yet. Done in SQL against the DB clock so it stays correct whatever
        // the timezone offset between PHP and the database (see issueCode). TTL is an
        // int class constant, so the expression carries no user input.
        $still_valid = countElementsInTable(self::getTable(), [
            'id' => $mfa->getID(),
            new \Glpi\DBAL\QueryExpression(
                'date_creation >= (NOW() - INTERVAL ' . self::CODE_TTL_MINUTES . ' MINUTE)'
            ),
        ]) > 0;

        if (!$still_valid) {
            $mfa->delete(['id' => $mfa->getID()]);
            return false;
        }

        if (!password_verify($code, (string) $mfa->fields['code'])) {
            return false;
        }

        $mfa->delete(['id' => $mfa->getID()]);
        return true;
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
}
