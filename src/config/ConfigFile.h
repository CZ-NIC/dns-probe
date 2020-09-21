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

#include <iostream>
#include <memory>
#include <unistd.h>
#include <yaml-cpp/yaml.h>

#include "ConfigItem.h"
#include "Config.h"
#include "core/Statistics.h"
#include "utils/Poll.h"
#include "utils/FileDescriptor.h"
#include "utils/Logger.h"

namespace DDP {
    class ConfigFile : public PollAble
    {
        public:
        explicit ConfigFile(Config& cfg, std::string conf_file, std::string instance = "default");

        ~ConfigFile() override = default;

        /**
         * Process request from config file when associated file descriptor is ready to read.
         */
        void ready_read() override;

        /**
         * When connection between application and config file is broken process the error.
         */
        void error() override;

        /**
         * Process closed connection from config file.
         */
        void hup() override;

        /**
         * Provides access to underlying file descriptor.
         * @return Associated file descriptor.
         */
        int fd() override { return m_fd; }

    private:
        void load_instance(YAML::Node node);

        Config& m_cfg; //!< Associated config.
        Logger m_logger; //!< Logger for logging events.
        int m_fd;
    };
}
