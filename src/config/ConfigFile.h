/*
 *  Copyright (C) 2020 CZ.NIC, z.s.p.o
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations including
 *  the two.
 */

#pragma once

#include <string>
#include <yaml-cpp/yaml.h>

#include "Config.h"

namespace DDP {
    /**
     * @brief Parse YAML configuration file and fill Config structure
     */
    struct ConfigFile
    {
        /**
         * @brief Parses "default" and user given instances from YAML configuration file.
         * @param cfg Config structure to fill
         * @param conf_file Path to YAML configuration file
         * @param instance Unique ID of DNS Probe instance
         */
        static void load_configuration(Config& cfg, std::string conf_file, std::string instance = "default");

        /**
         * @brief Parses DNS Probe instance given in YAML::Node object
         * @param cfg Config structure to fill
         * @param node YAML Node with configuration for specific DNS Probe instance
         */
        static void load_instance(Config& cfg, YAML::Node node);
    };
}
