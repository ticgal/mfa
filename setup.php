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

define('PLUGIN_MFA_VERSION', '2.0.1-beta.2');
define('PLUGIN_MFA_MIN_GLPI', '11.0');
define('PLUGIN_MFA_MAX_GLPI', '12.0');

use Glpi\Http\Firewall;
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
        // The login form is posted here before the user is authenticated, so the
        // firewall must not require a session. This is the same strategy the core
        // applies to /front/login.php. It must NOT be declared stateless: the flow
        // needs the session to carry `mfa_pre_auth` between both steps, and
        // stateless resources are also exempt from CSRF checks.
        Firewall::addPluginStrategyForLegacyScripts(
            'mfa',
            '#^/front/mfa.form.php$#',
            Firewall::STRATEGY_NO_CHECK
        );

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
