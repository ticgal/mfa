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

define('PLUGIN_MFA_VERSION', '2.0.3-beta.1');
define('PLUGIN_MFA_MIN_GLPI', '11.0');
define('PLUGIN_MFA_MAX_GLPI', '12.0');

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
    global $PLUGIN_HOOKS;

    $plugin = new Plugin();
    if ($plugin->isActivated('mfa')) {
        Plugin::registerClass('PluginMfaConfig', ['addtabon' => 'Config']);
        $PLUGIN_HOOKS[Hooks::CONFIG_PAGE]['mfa'] = 'front/config.form.php';

        Plugin::registerClass('PluginMfaMfa', [
            'notificationtemplates_types' => true,
        ]);

        // Enforce the second factor on the server, on every request, after the
        // core has authenticated the user. This covers all login paths (form,
        // SSO/CAS/x509, remember-me cookie) instead of relying on a client-side
        // redirect of the login form, which /front/login.php bypassed.
        $PLUGIN_HOOKS[Hooks::POST_INIT]['mfa'] = 'plugin_mfa_enforce';

        // Keep the TTL of the cleanup cron aligned with the verification TTL.
        CronTask::Register('PluginMfaMfa', 'expiredSecurityCode', HOUR_TIMESTAMP, [
            'param' => PluginMfaMfa::CODE_TTL_MINUTES,
            'state' => 1,
            'mode'  => CronTask::MODE_EXTERNAL
        ]);
    }
}
