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
        /**
         * Class used for processing callbacks from sysrepo.
         */
        class SysrepoCallback : public sysrepo::Callback
        {
        public:

            /**
             * Constructor
             * @param cfg Reference to instance of DDP::ConfigSysrepo maintains this object.
             */
            explicit SysrepoCallback(DDP::ConfigSysrepo& cfg) : m_cfg(cfg) {};

            /**
             * Callback called for new configuration request from sysrepo.
             * @param session Managed session.
             * @param module_name Module name where change was triggered.
             * @param xpath Modified object in sysrepo.
             * @param event Event from sysrepo.
             * @param request_id Request ID from sysrepo.
             * @param private_data Make no sense in C++ but ok.
             * @return Inform that operation was successful.
             */
            int module_change(sysrepo::S_Session session, const char* module_name, const char* xpath, sr_event_t event,
                              uint32_t request_id, void* private_data) override;

            /**
             * Callback called when sysrepo requests operational data
             * @param session Managed session.
             * @param module_name Module name where change was triggered.
             * @param path No idea.
             * @param request_xpath Path to requested data.
             * @param request_id Request ID from sysrepo.
             * @param parent Parent node used as return value.
             * @param private_data Make no sense in C++ but ok.
             * @return Inform that operation was successful.
             */
            int oper_get_items(sysrepo::S_Session session, const char* module_name, const char* path,
                               const char* request_xpath, uint32_t request_id, libyang::S_Data_Node& parent,
                               void* private_data) override;

            /**
             * Callback called when rpc action is required
             * @param session Managed session.
             * @param op_path Path to triggered RPC
             * @param input Input parameters.
             * @param event Type of the callback event that has occurred.
             * @param request_id Request ID unique for the specific op_path.
             * @param output Output parameters for RPC call.
             * @param private_data Make no sense in C++ but ok.
             * @return Informs that operation was successful or not.
             */
            int rpc(sysrepo::S_Session session, const char* op_path, const sysrepo::S_Vals input, sr_event_t event,
                    uint32_t request_id, sysrepo::S_Vals_Holder output, void* private_data) override;

        private:
            DDP::ConfigSysrepo& m_cfg; //!< Reference to DDP::ConfigSysrepo maintains this object.
        };

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
        sysrepo::S_Callback m_sysrepo_callback; //!< Sysrepo callback class instance.
        int m_fd; //!< Underlying file descriptor used for communication with sysrepo.
        Logger m_logger; //!< Logger for logging events.


    };
}
