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

require_once('../../../front/_check_webserver_config.php');

global $CFG_GLPI;

if (isset($_POST['code'])) {
    // ---------------------------------------------------------------------
    // Step 2: verify the one-time code.
    // At this point the user is NOT logged in: only the `mfa_pre_auth` data
    // stashed by step 1 identifies him.
    // ---------------------------------------------------------------------
    $pre_auth = $_SESSION['mfa_pre_auth'] ?? null;
    $users_id = (int) ($pre_auth['user_id'] ?? 0);

    if ($users_id <= 0) {
        // No pending authentication: nothing to verify.
        Html::redirect($CFG_GLPI["root_doc"] . "/index.php");
    }

    // Rate-limit verification attempts per user: the code is only 6 digits, so
    // without a lock-out it is brute-forceable by anyone who has the password.
    if (!PluginMfaMfa::consumeAttempt($users_id)) {
        Html::nullHeader("Login", $CFG_GLPI["root_doc"] . '/index.php');
        echo '<div class="center b" style="color:red">' . __('Too many failed attempts. Please try again later.', 'mfa') . '</div>';
        echo '<div class="center"><br><a class="btn btn-primary" href="' . $CFG_GLPI["root_doc"] . '/front/logout.php?noAUTO=1">' . __('Log in again') . '</a></div>';
        Html::nullFooter();
        exit();
    }

    // Force the code to a scalar string. If it arrives as an array, GLPI's criteria
    // parser could read `['LIKE', '%']` as an operator+value pair and match any code.
    $code = is_scalar($_POST['code']) ? (string) $_POST['code'] : '';

    // Verify against the user's own pending code (bound to users_id, stored hashed,
    // rejected if expired). Consumes the code on success.
    if (PluginMfaMfa::verifyCode($users_id, $code)) {
        // Correct code
        PluginMfaMfa::clearAttempts($users_id);

        // Hand the login back to the core: `mfa_success` makes Auth::login() resume
        // from `mfa_pre_auth` and only now call Session::init(), which is what
        // actually creates the authenticated session.
        $_SESSION['mfa_success'] = true;

        $url = $CFG_GLPI["root_doc"] . "/front/login.php";
        if (!empty($pre_auth['redirect'])) {
            $url .= '?redirect=' . rawurlencode($pre_auth['redirect']);
        }
        Html::redirect($url);
    } else {
        // Incorrect code
        Html::nullHeader("Login", $CFG_GLPI["root_doc"] . '/index.php');
        echo '<div class="center b" style="color:red">' . __('Incorrect One-Time Security Code', 'mfa') . '</div>';
        echo '<div class="center"><br><a class="btn btn-primary" href="' . $CFG_GLPI["root_doc"] . '/front/logout.php?noAUTO=1">' . __('Log in again') . '</a></div>';
        Html::nullFooter();
        exit();
    }
} else {
    // ---------------------------------------------------------------------
    // Step 1: validate the credentials.
    // ---------------------------------------------------------------------
    // Restore POST data
    $login    = $_POST['login_name'] ?? '';
    $password = $_POST['login_password'] ?? '';
    $remember = ($_POST['login_remember'] ?? 0) && $CFG_GLPI["login_remember_time"];
    $noauto   = (bool) ($_REQUEST['noAUTO'] ?? false);

    $auth = new Auth();

    // Auth::login() performs every side effect of a normal login (deny rules, LDAP
    // restore, last_login, user auto-add, event log). If the user has native 2FA
    // pending, it never returns: the core redirects to /MFA/Prompt on its own.
    //
    // `remember me` is deliberately forced to false here: Auth::login() issues the
    // auto-login cookie right after Session::init(), and that cookie would survive
    // the session teardown below, letting anyone log in from the login page without
    // ever entering the code. The real value travels in `mfa_pre_auth` and the core
    // issues the cookie once the code has been verified.
    if ($auth->login($login, $password, $noauto, false)) {
        // Check if native 2FA is active
        $profile = new Profile();
        $active_profile_id = $_SESSION['glpiactiveprofile']['id'] ?? null;

        $native_2fa_active = false;
        if ($active_profile_id && $profile->getFromDB($active_profile_id)) {
            if (isset($profile->fields['2fa_enforced']) && $profile->fields['2fa_enforced'] == 1) {
                $native_2fa_active = true;
            }
        }

        // Check if user has native 2FA secret. If does, does not launch the plugin
        if (!empty($auth->user->fields['2fa_secret'])) {
            $native_2fa_active = true;
        }

        if ($native_2fa_active) {
            Auth::redirectIfAuthenticated();
            Html::redirect($CFG_GLPI["root_doc"] . "/index.php");
        }

        // If native 2FA is not active, continue with MFA plugin
        $config = new PluginMfaConfig();
        if (!$config->needCode($auth->user->fields["authtype"])) {
            Auth::redirectIfAuthenticated();
            Html::redirect($CFG_GLPI["root_doc"] . "/index.php");
        } else {
            $users_id = (int) Session::getLoginUserID();

            // Issue a fresh code (invalidating any previous one) and send it while the
            // session is still available: the notification needs the user and entity
            // context.
            PluginMfaMfa::issueCode($users_id);

            // Everything the core needs to resume this login once the code is verified.
            // Same shape as the one the core builds for its own 2FA (see Auth::login()).
            $pre_auth = [
                'user_id'     => $users_id,
                'username'    => $auth->user->fields['name'],
                'remember_me' => $remember,
                'noauto'      => $noauto,
                'redirect'    => $_POST['redirect'] ?? null,
            ];

            // Auth::login() has already opened an authenticated session. Tear it down:
            // until the code is verified the user must not be able to reach any page.
            // Keep the same keys the core preserves when it restarts a session.
            $preserved = [];
            foreach (['glpi_plugins', 'glpicookietest', 'phpCAS', 'glpiskipMaintenance', 'glpi_remote_user'] as $key) {
                if (isset($_SESSION[$key])) {
                    $preserved[$key] = $_SESSION[$key];
                }
            }

            Session::destroy();
            Session::start();

            $_SESSION = $preserved + $_SESSION;
            $_SESSION['mfa_pre_auth'] = $pre_auth;

            Html::nullHeader("Login", $CFG_GLPI["root_doc"] . '/index.php');
            PluginMfaMfa::showCodeForm();
            Html::nullFooter();
            exit();
        }
    } else {
        Html::redirect($CFG_GLPI["root_doc"] . "/index.php?error=1");
    }
}
