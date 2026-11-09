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

global $CFG_GLPI;

// Check if plugin is activated...
$plugin = new Plugin();
if (!$plugin->isInstalled('mfa') || !$plugin->isActivated('mfa')) {
	throw new Symfony\Component\HttpKernel\Exception\NotFoundHttpException();
}

Session::checkRight('config', UPDATE);

$config = new PluginMfaConfig();
if (isset($_POST["update"])) {
	$config->check($_POST['id'], UPDATE);

	// The one-time code is sent by e-mail. Refuse to switch a source on while e-mail
	// notifications are off: every user of that source (the administrator included)
	// would be locked out at the next request. Switching sources off, or leaving the
	// ones already on, is always allowed so the situation can be repaired.
	$config->getFromDB((int) $_POST['id']);
	if (!PluginMfaConfig::isMailAvailable() && !empty($config->getNewlyEnabledSources($_POST))) {
		Session::addMessageAfterRedirect(
			__('The configuration was not saved: E-mail notifications are not operative (disabled, or the "Send mails in queue" automatic action is disabled), so the one-time code could not be sent and the users of the enabled sources would be locked out. Make e-mail notifications work first.', 'mfa'),
			false,
			ERROR
		);
		Html::back();
	}

	$config->update($_POST);
	Html::back();
}

Html::redirect($CFG_GLPI["root_doc"] . "/front/config.form.php?forcetab=" . urlencode('PluginMfaConfig$1'));
