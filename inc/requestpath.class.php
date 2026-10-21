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

use Glpi\Http\RequestRouterTrait;
use Symfony\Component\HttpFoundation\Request;

if (!defined('GLPI_ROOT')) {
    die("Sorry. You can't access directly to this file");
}

/**
 * Resolves a request the same way the GLPI router does, so the enforcement hook
 * decides on the resource that will actually run and not on the raw URL.
 *
 * The raw URL cannot be trusted for this: the router accepts a PATH_INFO suffix
 * after a script (`/front/central.php/a.css` runs `/front/central.php`), so any
 * decision based on the URL extension or suffix can be steered by the client.
 */
class PluginMfaRequestpath
{
    use RequestRouterTrait;

    public function __construct()
    {
        $this->glpi_root = GLPI_ROOT;
        $this->plugin_directories = GLPI_PLUGINS_DIRECTORIES;
    }

    public static function getCurrentRequest(): Request
    {
        global $kernel;

        $request = $kernel?->getMainRequest();
        return $request ?? Request::createFromGlobals();
    }

    /**
     * Path of the resource the router will execute or serve, relative to the GLPI
     * root (no base URL, no PATH_INFO suffix, `/marketplace/` mapped to `/plugins/`).
     */
    public function getResolvedPath(Request $request): string
    {
        return $this->normalizePath($request);
    }

    /**
     * Whether the router will answer this request with a static file, i.e. no PHP
     * script or controller runs. Same test as the core FrontEndAssetsListener.
     */
    public function isStaticFile(Request $request): bool
    {
        $path = $this->normalizePath($request);

        return $this->getTargetFile($path) !== null
            && !$this->isTargetAPhpScript($path)
            && !$this->isHiddenFile($path);
    }
}
