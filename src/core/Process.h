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
 */

#pragma once

#include "config/Config.h"
#include "communication/CommLink.h"
#include "Statistics.h"
#include "utils/Logger.h"

namespace DDP {

    class Process {

    public:
        /**
         * Instructions if process should terminate when it receives new message in communication queue
         */
        enum class processState : uint8_t {
            CONTINUE,
            BREAK,
            ROTATE_OUTPUT
        };

        /**
         * @brief Constructor
         * @param cfg Dynamic configuration
         * @param stats Container for gathering runtime statistics
         * @param comm_link Communication queue to configuration lcore
         */
        explicit Process(Config cfg, Statistics& stats, CommLink::CommLinkWorkerEP& comm_link) :
                m_cfg(cfg),
                m_comm_link(comm_link),
                m_stats(stats) {}

        virtual ~Process() {};

        /**
         * @brief Main lcore loop.
         * @return Returns 0 because DPDK
         */
        virtual int run() = 0;

        /**
         * @brief Check communication queue for new messages and handle them
         * @param cfg Callback for necessary configuration updates on given process
         * the statistics to communication queue
         * @return BREAK if message to stop the application was received, CONTINUE otherwise
         */
        template<typename CB1>
        processState check_comm_link(CB1 cfg) {
            auto msg = m_comm_link.recv();
            if (msg != nullptr) {
                if (msg->type() == DDP::Message::Type::STOP) {
                    return processState::BREAK;
                }
                else if (msg->type() == DDP::Message::Type::NEW_CONFIG) {
                    m_cfg = dynamic_cast<DDP::MessageNewConfig*>(msg.get())->cfg;
                    cfg();
                }
                else if (msg->type() == DDP::Message::Type::ROTATE_OUTPUT) {
                    return processState::ROTATE_OUTPUT;
                }
            }

            return processState::CONTINUE;
        }

    protected:
        Config m_cfg; //!< Copy of application configuration
        CommLink::CommLinkWorkerEP& m_comm_link; //!< Link to master core.
        Statistics& m_stats; //!< Statistics structure
    };
}