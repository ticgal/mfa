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

// ---------------------------------------------------------------------------
// Second-factor challenge (step-up).
//
// The user reaches this page AFTER GLPI has authenticated the credentials: the
// login itself goes through the normal /front/login.php. The request-time
// enforcement hook (plugin_mfa_enforce) redirects an authenticated-but-unverified
// user here and blocks every other page until the code is verified. This page
// therefore never handles credentials and never writes the native `mfa_pre_auth`
// / `mfa_success` session keys, which the core 2FA setup/verify routes would
// otherwise accept as proof of the first factor.
// ---------------------------------------------------------------------------

$users_id = (int) Session::getLoginUserID();

if ($users_id <= 0) {
    // Not authenticated (e.g. direct hit): nothing to step up.
    Html::redirect($CFG_GLPI["root_doc"] . "/index.php");
}

// Already cleared, or this session does not require the plugin code: send the
// user on to where they were going.
if (!PluginMfaMfa::userMustVerify($users_id)) {
    $redirect = $_SESSION['plugin_mfa_pending']['redirect'] ?? '';
    unset($_SESSION['plugin_mfa_pending']);
    if (is_string($redirect) && $redirect !== '' && str_starts_with($redirect, '/')) {
        Html::redirect($redirect);
    }
    Html::redirect($CFG_GLPI["root_doc"] . "/front/central.php");
}

if (isset($_POST['code'])) {
    // -----------------------------------------------------------------------
    // Verify the one-time code against this session's own pending challenge.
    // -----------------------------------------------------------------------
    $mfa_id = (int) ($_SESSION['plugin_mfa_pending']['mfa_id'] ?? 0);

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

    // Verify against this session's pending code (bound to users_id and the challenge
    // id held server side, stored hashed, rejected if expired, consumed atomically).
    if (PluginMfaMfa::verifyCode($users_id, $code, $mfa_id)) {
        $redirect = $_SESSION['plugin_mfa_pending']['redirect'] ?? '';

        PluginMfaMfa::clearAttempts($users_id);
        PluginMfaMfa::markVerified();

        if (is_string($redirect) && $redirect !== '' && str_starts_with($redirect, '/')) {
            Html::redirect($redirect);
        }
        Html::redirect($CFG_GLPI["root_doc"] . "/front/central.php");
    } else {
        // Incorrect code
        Html::nullHeader("Login", $CFG_GLPI["root_doc"] . '/index.php');
        echo '<div class="center b" style="color:red">' . __('Incorrect One-Time Security Code', 'mfa') . '</div>';
        echo '<div class="center"><br><a class="btn btn-primary" href="' . $CFG_GLPI["root_doc"] . '/plugins/mfa/front/mfa.form.php">' . __('Try again', 'mfa') . '</a></div>';
        echo '<div class="center"><br><a class="btn btn-secondary" href="' . $CFG_GLPI["root_doc"] . '/front/logout.php?noAUTO=1">' . __('Log in again') . '</a></div>';
        Html::nullFooter();
        exit();
    }
}

// -----------------------------------------------------------------------
// Render the challenge. Reuse a still-valid pending code, otherwise issue a
// fresh one (subject to the per-user issuance throttle) so that navigating
// while unverified does not re-send a code on every request.
// -----------------------------------------------------------------------
$mfa_id = (int) ($_SESSION['plugin_mfa_pending']['mfa_id'] ?? 0);

if (!PluginMfaMfa::isPendingValid($users_id, $mfa_id)) {
    if (!PluginMfaMfa::consumeIssue($users_id)) {
        Html::nullHeader("Login", $CFG_GLPI["root_doc"] . '/index.php');
        echo '<div class="center b" style="color:red">' . __('Too many codes requested. Please wait a moment and try again.', 'mfa') . '</div>';
        echo '<div class="center"><br><a class="btn btn-primary" href="' . $CFG_GLPI["root_doc"] . '/plugins/mfa/front/mfa.form.php">' . __('Try again', 'mfa') . '</a></div>';
        echo '<div class="center"><br><a class="btn btn-secondary" href="' . $CFG_GLPI["root_doc"] . '/front/logout.php?noAUTO=1">' . __('Log in again') . '</a></div>';
        Html::nullFooter();
        exit();
    }

    // Any failure while issuing (DB, notification, template) must leave the user
    // unverified, not grant access. The enforcement hook keeps blocking an
    // unverified session, so a thrown exception here is fail-closed by design.
    $mfa_id = PluginMfaMfa::issueCode($users_id);
    $_SESSION['plugin_mfa_pending']['mfa_id'] = $mfa_id;
    $_SESSION['plugin_mfa_pending']['users_id'] = $users_id;
}

Html::nullHeader("Login", $CFG_GLPI["root_doc"] . '/index.php');
PluginMfaMfa::showCodeForm();
Html::nullFooter();
exit();
