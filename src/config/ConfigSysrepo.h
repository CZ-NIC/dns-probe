/*
 *  Copyright (C) 2018 Brno University of Technology
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
#include <functional>
#include <unistd.h>
#include <sysrepo-cpp/Session.hpp>

#include "ConfigItem.h"

#include "Config.h"
#include "core/Statistics.h"
#include "utils/Poll.h"
#include "utils/FileDescriptor.h"
#include "utils/Logger.h"

namespace DDP {
    /**
     * Provides interface for communicating with sysrepo. Class can be used inside DDP::Poll otherwise
     * user has to call manually DDP::ConfigSysrepo::ready_read when there are some data on associated descriptor.
     */
    class ConfigSysrepo : public PollAble
    {
    public:
        /**
         * Constructor
         * @param cfg Reference to config of the application.
         */
        explicit ConfigSysrepo(std::string instance, Config& cfg);

        /**
         * Destructor
         */
        ~ConfigSysrepo() override = default;

        /**
         * Process request from sysrepo when associated file descriptor is ready to read.
         */
        void ready_read() override;

        /**
         * When connection between application and sysrepo is broken process the error.
         */
        void error() override;

        /**
         * Process closed connection from sysrepo.
         */
        void hup() override;

        /**
         * Provides access to underlying file descriptor.
         * @return Associated file descriptor.
         */
        int fd() override { return m_fd; }

    private:
        const std::string m_instance; //!< Name of running instance;
        const std::string m_module{"cznic-dns-probe"}; //!< Name of sysrepo module
        const std::string m_root; //!< root config for sysrepo module

        Config& m_cfg; //!< Associated config.
        std::unordered_map<std::string, ConfigItemBase&> m_path_map; //!< Maps model config names to values from config.
        sysrepo::S_Session m_sysrepo_session; //!< Sysrepo session.
        sysrepo::S_Subscribe m_sysrepo_subscribe; //!< Sysrepo subscribe instance.
        sysrepo::FdRegistration m_sysrepo_register; //!< Callback for registering Sysrepo in Probe's poll object
        sysrepo::FdUnregistration m_sysrepo_unregister; //!< Callback for unregistering Sysrepo from Probe's poll object (empty)
        std::function<void()> m_sysrepo_callback; //!< Sysrepo callback for processing event.
        int m_fd; //!< Underlying file descriptor used for communication with sysrepo.
        Logger m_logger; //!< Logger for logging events.


    };
}
