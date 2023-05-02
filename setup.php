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

define('PLUGIN_MFA_VERSION', '1.0.2');
define('PLUGIN_MFA_MIN_GLPI', '10.0.0');
define('PLUGIN_MFA_MAX_GLPI', '10.1.99');

function plugin_version_mfa()
{
    return [
        'name' => 'MFA',
        'version' => PLUGIN_MFA_VERSION,
        'author' => '<a href="https://tic.gal">TICgal</a>',
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

    $PLUGIN_HOOKS['csrf_compliant']['mfa'] = true;

    $plugin = new Plugin();
    if ($plugin->isActivated('mfa')) {
        Plugin::registerClass('PluginMfaConfig', ['addtabon' => 'Config']);
        $PLUGIN_HOOKS['config_page']['mfa'] = 'front/config.form.php';

        Plugin::registerClass('PluginMfaMfa', [
            'notificationtemplates_types' => true,
        ]);
        $PLUGIN_HOOKS['display_login']['mfa'] = 'plugin_mfa_displayLogin';

        Crontask::Register('PluginMfaMfa', 'expiredSecurityCode', HOUR_TIMESTAMP, [
            'param' => 5,
            'state' => 1,
            'mode'  => CronTask::MODE_EXTERNAL
        ]);
    }
}
