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

define('PLUGIN_MFA_VERSION', '2.1.0');
define('PLUGIN_MFA_MIN_GLPI', '11.0');
define('PLUGIN_MFA_MAX_GLPI', '12.0');

use Glpi\Http\SessionManager;
use Glpi\Plugin\Hooks;

function plugin_version_mfa()
{
    return [
        'name' => 'MFA',
        'version' => PLUGIN_MFA_VERSION,
        'author' => '<a href="https://tic.gal">TICGAL</a>',
        'homepage' => 'https://tic.gal',
        'license' => 'GPLv3+',
        'requirements' => [
            'glpi' => [
                'min' => PLUGIN_MFA_MIN_GLPI,
                'max' => PLUGIN_MFA_MAX_GLPI
            ]
        ]
    ];
}

function plugin_init_mfa()
{
    SessionManager::registerPluginStatelessPath('mfa', '#^/front/mfa.form.php$#');

    $has_mfa = isset($_SESSION['mfa_pending_user_id']);

    if ($has_mfa) {
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        
        $allowed_files = ['mfa.form.php', 'logout.php', 'login.php', 'pwa.php'];
        $is_allowed = false;

        foreach ($allowed_files as $file) {
            if (str_contains($uri, $file)) {
                $is_allowed = true;
                break;
            }
        }

        if (!$is_allowed) {
            global $CFG_GLPI;

            if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest') {
                http_response_code(403);
                exit();
            }

            $mfa_url = ($CFG_GLPI["root_doc"] ?? '') . "/plugins/mfa/front/mfa.form.php";

            if (!headers_sent()) {
                header("Location: " . $mfa_url);
                exit();
            } else {
                echo "<script>window.location.href='$mfa_url';</script>";
                exit();
            }
        }
    }

    global $PLUGIN_HOOKS;

    $plugin = new Plugin();
    if ($plugin->isActivated('mfa')) {
        Plugin::registerClass('PluginMfaConfig', ['addtabon' => 'Config']);
        $PLUGIN_HOOKS[Hooks::CONFIG_PAGE]['mfa'] = 'front/config.form.php';

        Plugin::registerClass('PluginMfaMfa', [
            'notificationtemplates_types' => true,
        ]);
        $PLUGIN_HOOKS[Hooks::DISPLAY_LOGIN]['mfa'] = 'plugin_mfa_displayLogin';

        CronTask::Register('PluginMfaMfa', 'expiredSecurityCode', HOUR_TIMESTAMP, [
            'param' => 5,
            'state' => 1,
            'mode'  => CronTask::MODE_EXTERNAL
        ]);
    }
}
