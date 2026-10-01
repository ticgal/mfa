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

use Auth;
use CommonDBTM;
use CommonGLPI;
use DBConnection;
use Glpi\Application\View\TemplateRenderer;
use Migration;
use Session;

class Config extends CommonDBTM
{
    public static string $rightname = 'config';

    private static $instance = null;

    public function __construct()
    {
        global $DB;
        if ($DB->tableExists($this->getTable())) {
            $this->getFromDB(1);
        }
    }

    /**
     * Changing which authentication types require a code can weaken the whole
     * instance, so it is protected by GLPI's sudo mode like the core config page.
     */
    protected static function itemTypeRequiresReauthentication(): bool
    {
        return true;
    }

    public static function canCreate(): bool
    {
        return Session::haveRight(self::$rightname, UPDATE);
    }

    public static function canView(): bool
    {
        return Session::haveRight(self::$rightname, READ);
    }

    public static function canUpdate(): bool
    {
        return Session::haveRight(self::$rightname, UPDATE);
    }

    public static function getTypeName($nb = 0)
    {
        return "MFA";
    }

    public static function getInstance()
    {
        if (!isset(self::$instance)) {
            self::$instance = new self();
            if (!self::$instance->getFromDB(1)) {
                self::$instance->getEmpty();
            }
        }
        return self::$instance;
    }

    public static function getConfig($update = false)
    {
        $config = new self();
        if ($update) {
            $config->getFromDB(1);
        }
        return $config;
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if ($item->getType() == 'Config') {
            return self::createTabEntry('MFA', 0, null, 'ti ti-device-mobile-message');
        }
        return '';
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        if ($item->getType() == 'Config') {
            self::showConfigForm();
        }
        return true;
    }

    public static function showConfigForm(): bool
    {
        $config = new self();

        TemplateRenderer::getInstance()->display('@mfa/config.html.twig', [
            'config'   => $config->fields,
            'form_url' => self::getFormURL(),
            'canedit'  => self::canUpdate(),
            'warning'  => Mfa::globalDeliveryProblem(),
        ]);

        return true;
    }

    public function needCode($authtype)
    {
        switch ($authtype) {
            case Auth::DB_GLPI:
                return $this->fields['local'];
            case Auth::LDAP:
                return $this->fields['ldap'];
            case Auth::MAIL:
                return $this->fields['mail'];
            case Auth::EXTERNAL:
                return $this->fields['external'];
            default:
                return false;
        }
    }

    public static function install(Migration $migration)
    {
        global $DB;

        $default_charset = DBConnection::getDefaultCharset();
        $default_collation = DBConnection::getDefaultCollation();
        $default_key_sign = DBConnection::getDefaultPrimaryKeySignOption();

        $table = self::getTable();
        $config = new self();
        if (!$DB->tableExists($table)) {
            $migration->displayMessage("Installing $table");
            $query = "CREATE TABLE IF NOT EXISTS $table (
				`id` int {$default_key_sign} NOT NULL auto_increment,
				`local` tinyint NOT NULL default '1',
				`mail` tinyint NOT NULL default '0',
				`ldap` tinyint NOT NULL default '0',
				`external` tinyint NOT NULL default '0',
				PRIMARY KEY (`id`)
				) ENGINE=InnoDB DEFAULT CHARSET={$default_charset} COLLATE={$default_collation} ROW_FORMAT=DYNAMIC;";
            $DB->doQuery($query);

            $config->add([
                'id'       => 1,
                'local'    => 1,
                'mail'     => 0,
                'ldap'     => 0,
                'external' => 0,
            ]);
        }
    }

    public static function uninstall(Migration $migration)
    {
        $table = self::getTable();
        $migration->displayMessage("Uninstalling $table");
        $migration->dropTable($table);
    }
}
