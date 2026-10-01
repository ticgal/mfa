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

use GlpiPlugin\Mfa\Guard;
use GlpiPlugin\Mfa\Mfa;

global $CFG_GLPI;

// The guard (post_init) has already evaluated this session. Anyone who is not waiting
// for a code has nothing to do here.
if (!Guard::isPending()) {
    Auth::redirectIfAuthenticated();
    Html::redirect($CFG_GLPI['root_doc'] . '/index.php');
}

$users_id = (int) Session::getLoginUserID();
$error    = null;

if (isset($_POST['code'])) {
    if (!Mfa::consumeAttempt($users_id)) {
        // The code is only 6 digits: without a lock-out it is brute-forceable by anyone
        // who has the password.
        Html::nullHeader('Login', $CFG_GLPI['root_doc'] . '/index.php');
        echo '<div class="center b" style="color:red">' . __('Too many failed attempts. Please try again later.', 'mfa') . '</div>';
        echo '<div class="center"><br><a class="btn btn-primary" href="' . $CFG_GLPI['root_doc'] . '/front/logout.php?noAUTO=1">' . __('Log in again') . '</a></div>';
        Html::nullFooter();
        return;
    }

    // Force the code to a scalar string. If it arrives as an array, GLPI's criteria
    // parser could read `['LIKE', '%']` as an operator+value pair and match any code.
    $code = is_scalar($_POST['code']) ? (string) $_POST['code'] : '';

    // Verify against the user's own pending code (bound to users_id, stored hashed,
    // rejected if expired). Consumes the code on success.
    if (Mfa::verifyCode($users_id, $code)) {
        Mfa::clearAttempts($users_id);
        $redirect = Guard::markVerified();

        if ($redirect !== null) {
            // Validated by the core: only local destinations are followed.
            Toolbox::manageRedirect($redirect);
        }
        Auth::redirectIfAuthenticated();
        Html::redirect($CFG_GLPI['root_doc'] . '/index.php');
    }

    $error = __('Incorrect One-Time Security Code', 'mfa');
}

Guard::retryDelivery();

Html::nullHeader('Login', $CFG_GLPI['root_doc'] . '/index.php');
Mfa::showCodeForm($error, Guard::getNotice());
Html::nullFooter();
