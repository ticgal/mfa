<?php
/*
 -------------------------------------------------------------------------
 MFA plugin for GLPI
 Copyright (C) 2022 by the TICgal Team.
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
 @author    the TICgal team
 @copyright Copyright (c) 2022 TICgal team
 @license   AGPL License 3.0 or (at your option) any later version
				http://www.gnu.org/licenses/agpl-3.0-standalone.html
 @link      https://www.tic.gal
 @since     2022
 ----------------------------------------------------------------------
*/

if (!defined('GLPI_ROOT')) {
	die("Sorry. You can't access directly to this file");
}

class PluginMfaConfig extends CommonDBTM
{
	static private $_instance = null;

	public function __construct()
	{
		global $DB;
		if ($DB->tableExists($this->getTable())) {
			$this->getFromDB(1);
		}
	}

	static function canCreate()
	{
		return Session::haveRight('config', UPDATE);
	}

	static function canView()
	{
		return Session::haveRight('config', READ);
	}

	static function canUpdate()
	{
		return Session::haveRight('config', UPDATE);
	}

	static function getTypeName($nb = 0)
	{
		return "MFA";
	}

	static function getInstance()
	{
		if (!isset(self::$_instance)) {
			self::$_instance = new self();
			if (!self::$_instance->getFromDB(1)) {
				self::$_instance->getEmpty();
			}
		}
		return self::$_instance;
	}

	static function getConfig($update = false)
	{
		static $config = null;
		if (is_null(self::$config)) {
			$config = new self();
		}
		if ($update) {
			$config->getFromDB(1);
		}
		return $config;
	}

	function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
	{
		if ($item->getType() == 'Config') {
			return self::getTypeName();
		}
		return '';
	}

	static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
	{
		if ($item->getType() == 'Config') {
			self::showConfigForm($item);
		}
		return true;
	}

	static function showConfigForm()
	{
		$config = new self();

		$config->showFormHeader(['colspan' => 2]);

		echo "<tr class='tab_bg_1'>";
		echo "<td><label for='local'>".__('GLPI Database Authentication','mfa')."</label></td>";
		echo "<td>";
		Dropdown::showYesNo("local", $config->fields['local']);
		echo "</td>";
		echo "</tr>";

		echo "<tr class='tab_bg_1'>";
		echo "<td><label for='mail'>".__('Mail Server Authentication','mfa')."</label></td>";
		echo "<td>";
		Dropdown::showYesNo("mail", $config->fields['mail']);
		echo "</td>";
		echo "</tr>";

		echo "<tr class='tab_bg_1'>";
		echo "<td><label for='ldap'>".__('LDAP Directory Authentication','mfa')."</label></td>";
		echo "<td>";
		Dropdown::showYesNo("ldap", $config->fields['ldap']);
		echo "</td>";
		echo "</tr>";

		echo "<tr class='tab_bg_1'>";
		echo "<td><label for='external'>".__('External Authentication','mfa')."</label></td>";
		echo "<td>";
		Dropdown::showYesNo("external", $config->fields['external']);
		echo "</td>";
		echo "</tr>";

		$config->showFormButtons(['candel' => false]);
		return false;
	}

	public function needCode($authtype) {

		switch ($authtype) {
			case Auth::DB_GLPI:
				return $this->fields['local'];
				break;
			case Auth::LDAP:
				return $this->fields['ldap'];
				break;
			case Auth::MAIL:
				return $this->fields['mail'];
				break;
			case Auth::EXTERNAL:
				return $this->fields['external'];
				break;
			default:
				return false;
				break;
		}
	}

	static function install(Migration $migration)
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
			$DB->query($query) or die($DB->error());

			$config->add([
				'id' => 1,
			]);
		}
	}
}
