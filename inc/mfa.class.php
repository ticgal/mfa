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

class PluginMfaMfa extends CommonDBTM
{

	public static function getTypeName($nb = 0)
	{
		return 'MFA';
	}

	static function cronInfo($name)
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

	static function cronExpiredSecurityCode($task)
	{
		global $CFG_GLPI, $DB;

		$duration = (int)$task->fields['param'];

		$query = [
			'FROM' => self::getTable(),
			'WHERE' => [
				new QueryExpression(
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
		//Html::includeHeader();

		echo "<div class='page-anonymous'>
			<div class='flex-fill d-flex flex-column justify-content-center py-4 mt-4'>
				<div class='container-tight py-6' style='max-width: 60rem'>
					<div class='text-center'>
						<div class='col-md'>
							<span class='glpi-logo mb-4' title='GLPI'></span>
						</div>
					</div>
					<div class='card card-md'>
						<div class='card-body'>
							<form action='" . Toolbox::getItemTypeFormURL(__CLASS__) . "' method='post' autocomplete='off' data-submit-once>
								<div class='row justify-content-center'>
									<div class='col-md-5'>
										<h2 class='card-header text-center mb-4'>" . __('One-Time Security Code', 'mfa') . "</h2>
										<div class='col-mb-3'>
											<label class='form-label'>" . __('Your account requires an additional authentication code.', 'mfa') . "</label>
											<input type='password' class='form-control' name='code' placeholder autocomplete='off'>
										</div>
										<div class='form-footer'>
											<button type='submit' name='submit' class='btn btn-primary w-100' tabindex='3'>" . __('Sign in') . "</button>
										</div>
									</div>
								</div>";
		Html::closeForm();
		echo "</div>
					</div>
				</div>
			</div>
		</div>";
	}

	public static function getRandomInt($length)
	{
		$keyspace = '0123456789';
		$str = '';
		$max = mb_strlen($keyspace, '8bit') - 1;
		for ($i = 0; $i < $length; ++$i) {
			$str .= $keyspace[random_int(0, $max)];
		}
		if (countElementsInTable(self::getTable(), ['code' => $str]) > 0) {
			$str = self::getRandomInt($length);
		}
		return $str;
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
				PRIMARY KEY (`id`)
			) ENGINE=InnoDB  DEFAULT CHARSET={$default_charset} COLLATE={$default_collation} ROW_FORMAT=DYNAMIC;";

			$DB->query($query) or die($DB->error());
		}
	}
}
