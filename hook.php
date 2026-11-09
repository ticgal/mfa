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
	// The CLI never goes through this interactive challenge.
	if (isCommandLine()) {
		return;
	}

	$request = PluginMfaRequestpath::getCurrentRequest();

	// API paths are token-based and stateless: the enforcement hook must not open a
	// cookie session for them (it would break token authentication), and the plugin
	// does not cover the token/credential API channels (see README). The single
	// exception is the OAuth authorization endpoint, which completes an interactive
	// login from the browser's web-session cookie and is therefore a real bypass of
	// the second factor if left alone.
	if (isAPI()) {
		if (PluginMfaRequestpath::isOAuthAuthorizePath($request)) {
			plugin_mfa_enforce_oauth_authorize();
		}
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

	if (PluginMfaMfa::isAllowedWhileUnverified($request)) {
		return;
	}

	// Remember where the user was heading so the challenge can send them back.
	// Only a local path from the server is stored; it is never taken from a
	// user-supplied parameter, so it cannot become an open redirect.
	if (empty($_SESSION['plugin_mfa_pending']['redirect'])) {
		$_SESSION['plugin_mfa_pending']['redirect'] = $_SERVER['REQUEST_URI'] ?? '';
	}

	plugin_mfa_redirect_to_challenge();
}

/**
 * Enforce the second factor on the HL API OAuth authorization endpoint.
 *
 * `/api.php/.../authorize` is a stateless route, so no session was started during
 * boot. Core's CookieAuthMiddleware opens the web session from the browser cookie
 * and treats the logged-in user as authenticated; without this, an attacker holding
 * the password could log in, skip the e-mailed code and still obtain an OAuth
 * authorization code for the victim. We open the same session, and if the user still
 * owes the plugin code we send them to the challenge instead of letting the endpoint
 * issue a code. A verified session is left exactly as the middleware expects (active,
 * cookies enabled), so the normal OAuth consent flow is unaffected.
 */
function plugin_mfa_enforce_oauth_authorize()
{
	// Mirror Glpi\Api\HL\Middleware\CookieAuthMiddleware: start the web session from
	// the cookie so getLoginUserID() can see a cookie-authenticated user.
	if (session_status() !== PHP_SESSION_ACTIVE) {
		$use_cookies = filter_var(ini_get('session.use_cookies'), FILTER_VALIDATE_BOOLEAN);
		if ($use_cookies !== true) {
			ini_set('session.use_cookies', '1');
		}
		Session::start();
	}

	$users_id = (int) Session::getLoginUserID();
	if ($users_id <= 0) {
		// Not authenticated by cookie: the OAuth flow redirects to login by itself.
		return;
	}

	if (!PluginMfaMfa::userMustVerify($users_id)) {
		return;
	}

	// Come back to the authorize request (with its OAuth parameters) after the code
	// is verified, so the consent flow continues where it left off.
	if (empty($_SESSION['plugin_mfa_pending']['redirect'])) {
		$_SESSION['plugin_mfa_pending']['redirect'] = $_SERVER['REQUEST_URI'] ?? '';
	}

	plugin_mfa_redirect_to_challenge();
}

/**
 * Send the current request to the challenge page and stop it.
 *
 * Runs during the kernel boot phase (POST_INIT), before the controller is
 * dispatched, so Html::redirect()'s RedirectException would not be caught by the
 * kernel. Emit the redirect directly and stop the request; the session is flushed so
 * the pending state persists.
 *
 * Fails closed: if output has already started we cannot redirect, so the request is
 * stopped rather than allowed to render the protected page without the code.
 */
function plugin_mfa_redirect_to_challenge()
{
	global $CFG_GLPI;

	if (headers_sent()) {
		Toolbox::logInFile(
			'mfa',
			"Unable to redirect to the MFA challenge: output already started; request stopped.\n"
		);
		exit();
	}

	session_write_close();
	header('Location: ' . $CFG_GLPI['root_doc'] . '/plugins/mfa/front/mfa.form.php', true, 302);
	exit();
}
