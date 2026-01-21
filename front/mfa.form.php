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
    $mfa = new PluginMfaMfa();

    if ($mfa->getFromDBByCrit(['code' => $_POST['code']])) {
        // Correct code
        $mfa->delete(['id' => $mfa->getID()]);
        
        unset($_SESSION['mfa_pending_user_id']);
        
        Html::redirect($CFG_GLPI["root_doc"] . "/index.php");
    } else {
        // Incorrect code
        Html::nullHeader("Login", $CFG_GLPI["root_doc"] . '/index.php');
        echo '<div class="center b" style="color:red">' . __('Incorrect One-Time Security Code', 'mfa') . '</div>';
        echo '<div class="center"><br><a class="btn btn-primary" href="' . $CFG_GLPI["root_doc"] . '/front/logout.php?noAUTO=1">' . __('Log in again') . '</a></div>';
        Html::nullFooter();
        exit();
    }
} else {
    if (!isset($_SESSION['glpicookietest']) || $_SESSION['glpicookietest'] != 'OK') {
        $_SESSION['glpicookietest'] = 'OK';
    }

    // Restore POST data
    $login    = $_POST['login_name'] ?? '';
    $password = $_POST['login_password'] ?? '';
    $remember   = ($_POST['login_remember'] ?? 0) && $CFG_GLPI["login_remember_time"];

    $auth = new Auth();

    Toolbox::logInFile('login', $login . ", " . $password . ", " . $remember . PHP_EOL, true);
    if ($auth->login($login, $password, false, $remember)) {
        $config = new PluginMfaConfig();
        
        if (!$config->needCode($auth->user->fields["authtype"])) {
            Html::redirect($CFG_GLPI["root_doc"] . "/front/central.php");
        } else {
            $_SESSION['mfa_pending_user_id'] = Session::getLoginUserID();

            // Generate code
            $mfa = new PluginMfaMfa();

            if (countElementsInTable($mfa->getTable(), ['users_id' => $_SESSION['mfa_pending_user_id']]) <= 0) {
                $mfa->add([
                    'users_id' => $_SESSION['mfa_pending_user_id'], 
                    'code'     => PluginMfaMfa::getRandomInt(6)
                ]);

                NotificationEvent::raiseEvent('securitycodegenerate', $mfa, ['entities_id' => 0]);
            }

            // MFA screen
            Html::nullHeader("Login", $CFG_GLPI["root_doc"] . '/index.php');
            PluginMfaMfa::showCodeForm();
            Html::nullFooter();
            exit();
        }
    } else {
        // Failed login
        Html::redirect($CFG_GLPI["root_doc"] . "/index.php?error=1");
    }
}
