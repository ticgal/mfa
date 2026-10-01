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

use GlpiPlugin\Mfa\Config;
use GlpiPlugin\Mfa\Guard;
use GlpiPlugin\Mfa\Mfa;
use GlpiPlugin\Mfa\NotificationTargetMfa;

/**
 * Classes taking part in install/uninstall, in install order.
 *
 * @return class-string[]
 */
function plugin_mfa_get_classes(): array
{
    return [
        Config::class,
        Mfa::class,
        NotificationTargetMfa::class,
    ];
}

/**
 * Itemtypes were renamed when the classes moved to `src/` (v3.0.0). Rewrite the
 * ones stored in the database so existing notifications, templates and cron
 * tasks keep pointing to the plugin classes.
 */
function plugin_mfa_migrate_itemtypes(): void
{
    global $DB;

    $old = 'PluginMfaMfa';
    $new = Mfa::class;

    // Cron tasks are unique per (itemtype, name): when the new class has already
    // registered its task, drop the old row instead of renaming it.
    if ($DB->tableExists('glpi_crontasks')) {
        $cron = new CronTask();
        foreach ($DB->request(['FROM' => 'glpi_crontasks', 'WHERE' => ['itemtype' => $old]]) as $row) {
            if (countElementsInTable('glpi_crontasks', ['itemtype' => $new, 'name' => $row['name']]) > 0) {
                $cron->delete(['id' => $row['id']], true);
            }
        }
    }

    foreach (['glpi_notificationtemplates', 'glpi_notifications', 'glpi_crontasks'] as $table) {
        if (!$DB->tableExists($table)) {
            continue;
        }
        $DB->update($table, ['itemtype' => $new], ['itemtype' => $old]);
    }
}

function plugin_mfa_install()
{
    $migration = new Migration(PLUGIN_MFA_VERSION);

    plugin_mfa_migrate_itemtypes();

    foreach (plugin_mfa_get_classes() as $classname) {
        if (method_exists($classname, 'install')) {
            $classname::install($migration);
        }
    }
    $migration->executeMigration();

    return true;
}

function plugin_mfa_uninstall()
{
    $migration = new Migration(PLUGIN_MFA_VERSION);

    foreach (plugin_mfa_get_classes() as $classname) {
        if (method_exists($classname, 'uninstall')) {
            $classname::uninstall($migration);
        }
    }
    $migration->executeMigration();

    return true;
}

function plugin_mfa_post_init(): void
{
    Guard::enforce();
}
