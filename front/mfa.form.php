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

use Glpi\Toolbox\Sanitizer;

include('../../../inc/includes.php');

if (isset($_POST['code'])) {
    $mfa = new PluginMfaMfa();
    if ($mfa->getFromDBByCrit(['code' => $_POST['code']])) {
        $auth = new Auth();
        $user = new User();
        $user->getFromDB($mfa->fields['users_id']);
        $auth->auth_succeded = true;
        $auth->user = $user;
        Session::init($auth);
        $mfa->delete(['id' => $mfa->getID()]);
        Auth::redirectIfAuthenticated();
    } else {
        // we have done at least a good login? No, we exit.
        Html::nullHeader("Login", $CFG_GLPI["root_doc"] . '/index.php');
        echo '<div class="center b">' . __('Incorrect One-Time Security Code', 'mfa') . '<br><br>';
        // Logout whit noAUto to manage auto_login with errors
        echo '<a href="' . $CFG_GLPI["root_doc"] . '/front/logout.php?noAUTO=1">' . __('Log in again') . '</a></div>';
        Html::nullFooter();
        exit();
    }
} else {

    if (!isset($_SESSION["glpicookietest"]) || ($_SESSION["glpicookietest"] != 'testcookie')) {
        if (!is_writable(GLPI_SESSION_DIR)) {
            Html::redirect($CFG_GLPI['root_doc'] . "/index.php?error=2");
        } else {
            Html::redirect($CFG_GLPI['root_doc'] . "/index.php?error=1");
        }
    }
    //Do login and checks
    //$user_present = 1;
    if (isset($_SESSION['namfield']) && isset($_POST[$_SESSION['namfield']])) {
        $login = $_POST[$_SESSION['namfield']];
    } else {
        $login = '';
    }
    if (isset($_SESSION['pwdfield']) && isset($_POST[$_SESSION['pwdfield']])) {
        $password = Sanitizer::unsanitize($_POST[$_SESSION['pwdfield']]);
    } else {
        $password = '';
    }
    // Manage the selection of the auth source (local, LDAP id, MAIL id)
    if (isset($_POST['auth'])) {
        $login_auth = $_POST['auth'];
    } else {
        $login_auth = '';
    }

    $remember = isset($_SESSION['rmbfield']) && isset($_POST[$_SESSION['rmbfield']]) && $CFG_GLPI["login_remember_time"];

    // Redirect management
    $REDIRECT = "";
    if (isset($_POST['redirect']) && (strlen($_POST['redirect']) > 0)) {
        $REDIRECT = "?redirect=" . rawurlencode($_POST['redirect']);
    } elseif (isset($_GET['redirect']) && strlen($_GET['redirect']) > 0) {
        $REDIRECT = "?redirect=" . rawurlencode($_GET['redirect']);
    }

    $auth = new Auth();

    if ($auth->login($login, $password, (isset($_REQUEST["noAUTO"]) ? $_REQUEST["noAUTO"] : false), $remember, $login_auth)) {
        $config = new PluginMfaConfig();
        if (!$config->needCode($auth->user->fields["authtype"])) {
            Auth::redirectIfAuthenticated();
        } else {
            if (countElementsInTable(PluginMfaMfa::getTable(), ['users_id' => Session::getLoginUserID()]) <= 0) {
                $mfa = new PluginMfaMfa();
                $mfa->add(['users_id' => Session::getLoginUserID(), 'code' => PluginMfaMfa::getRandomInt(6)]);
                NotificationEvent::raiseEvent('securitycodegenerate', $mfa, ['entities_id' => 0]);
                QueuedNotification::forceSendFor($mfa->getType(), $mfa->fields['id']);
            }
            Session::destroy();
            Auth::setRememberMeCookie('');
            Session::setPath();
            Session::start();
            Session::loadLanguage('', false);
            $_SESSION['glpi_use_mode'] = Session::NORMAL_MODE;
            Html::nullHeader("Login", $CFG_GLPI["root_doc"] . '/index.php');
            PluginMfaMfa::showCodeForm();
        }
    } else {
        // we have done at least a good login? No, we exit.
        Html::nullHeader("Login", $CFG_GLPI["root_doc"] . '/index.php');
        echo '<div class="center b">' . $auth->getErr() . '<br><br>';
        // Logout whit noAUto to manage auto_login with errors
        echo '<a href="' . $CFG_GLPI["root_doc"] . '/front/logout.php?noAUTO=1' .
            str_replace("?", "&", $REDIRECT) . '">' . __('Log in again') . '</a></div>';
        Html::nullFooter();
        exit();
    }
}
