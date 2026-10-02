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

function plugin_mfa_install()
{
	$migration = new Migration(PLUGIN_MFA_VERSION);

	foreach (glob(dirname(__FILE__) . '/inc/*') as $filepath) {
		if (preg_match("/inc.(.+)\.class.php/", $filepath, $matches)) {
			$classname = 'PluginMfa' . ucfirst($matches[1]);
			include_once($filepath);
			if (method_exists($classname, 'install')) {
				$classname::install($migration);
			}
		}
	}
	$migration->executeMigration();

	return true;
}

function plugin_mfa_uninstall()
{
	$migration = new Migration(PLUGIN_MFA_VERSION);

	foreach (glob(dirname(__FILE__) . '/inc/*') as $filepath) {
		if (preg_match("/inc.(.+)\.class.php/", $filepath, $matches)) {
			$classname = 'PluginMfa' . ucfirst($matches[1]);
			include_once($filepath);
			if (method_exists($classname, 'uninstall')) {
				$classname::uninstall($migration);
			}
		}
	}
	$migration->executeMigration();

	return true;
}

/**
 * Request-time enforcement of the second factor.
 *
 * Runs on POST_INIT for every request, after the session has been started (the
 * SessionStart listener runs before plugin initialization) and before any page is
 * rendered. If the current user is authenticated but has not yet passed this
 * plugin's code in the current session, every request is redirected to the
 * challenge except the challenge itself, logout and the static assets the
 * challenge page needs. This is what makes the control effective for /front/login.php
 * and for SSO/CAS/x509/remember-me logins, none of which post to the plugin.
 */
function plugin_mfa_enforce()
{
	global $CFG_GLPI;

	// The API and CLI do not go through this interactive challenge; the plugin
	// does not cover them (see README).
	if (isCommandLine() || isAPI()) {
		return;
	}

	$users_id = (int) Session::getLoginUserID();
	if ($users_id <= 0) {
		// Not authenticated yet: the login page and its assets must work normally.
		return;
	}

	if (!PluginMfaMfa::userMustVerify($users_id)) {
		return;
	}

	$path = (string) parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
	if (PluginMfaMfa::isAllowedWhileUnverified($path)) {
		return;
	}

	// Remember where the user was heading so the challenge can send them back.
	// Only a local path from the server is stored; it is never taken from a
	// user-supplied parameter, so it cannot become an open redirect.
	if (empty($_SESSION['plugin_mfa_pending']['redirect'])) {
		$_SESSION['plugin_mfa_pending']['redirect'] = $_SERVER['REQUEST_URI'] ?? '';
	}

	// This runs during the kernel boot phase (POST_INIT), before the controller is
	// dispatched, so Html::redirect()'s RedirectException would not be caught by the
	// kernel. Emit the redirect directly and stop the request. Headers have not been
	// sent yet at this point; the session is flushed so the pending state persists.
	if (!headers_sent()) {
		session_write_close();
		header('Location: ' . $CFG_GLPI['root_doc'] . '/plugins/mfa/front/mfa.form.php', true, 302);
		exit();
	}
}
