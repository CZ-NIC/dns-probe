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
    private:
        class CommLinkPollAble : public PollAble {
        public:
            explicit CommLinkPollAble(Process& p) :
                PollAble(PollEvents::READ), m_process(p) {}

            int fd() override { return m_process.m_comm_link.fd(); }

            void ready_read() override {
                auto msg = m_process.m_comm_link.recv();
                if (msg != nullptr) {
                    if (msg->type() == DDP::Message::Type::STOP) {
                        m_process.stop();
                    }
                    else if (msg->type() == DDP::Message::Type::NEW_CONFIG) {
                        m_process.new_config(dynamic_cast<DDP::MessageNewConfig*>(msg.get())->cfg);
                    }
                    else if (msg->type() == DDP::Message::Type::ROTATE_OUTPUT) {
                        m_process.rotate_output();
                    }
                }
            }

        private:
            Process& m_process;
        };
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
        explicit Process(Config cfg, Statistics& stats, CommLink::CommLinkEP& comm_link) :
            m_poll(),
            m_cfg(std::move(cfg)),
            m_comm_link(comm_link),
            m_stats(stats)
        {
            m_poll.emplace<CommLinkPollAble>(*this);
        }

        virtual ~Process() = default;

        /**
         * @brief Main lcore loop.
         * @return Returns 0 because DPDK
         */
        virtual int run() = 0;


    protected:
        virtual void stop() {m_poll.disable();};
        virtual void new_config([[gnu::unused]] Config& cfg) {};
        virtual void rotate_output() {};

        Poll m_poll;
        Config m_cfg; //!< Copy of application configuration
        CommLink::CommLinkEP& m_comm_link; //!< Link to master core.
        Statistics& m_stats; //!< Statistics structure
    };
}