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

#include <atomic>
#include <utility>
#include <memory>
#include <stdexcept>

#include "utils/RingFwdDecl.h"
#include "utils/FileDescriptor.h"
#include "Message.h"
#include "utils/Poll.h"

namespace DDP {
    /**
     * Communication links between threads. This implementation allows send object inherited from DDP::Message. Message
     * is send over DDP::Ring. After instantiation object provides worker endpoint and config endpoint. Both endpoints
     * are represented with own class but with a similar interface. Both endpoint can use non-blocking send and recv
     * methods.
     *
     * Config endpoints have also assigned file descriptor which can be used for select. When the read is ready on the
     * file descriptor then you can obtain message from this endpoint. Worker's endpoint has to be polled.
     */
    class CommLink
    {
    public:
        /**
         * Implementation for config endpoint allowing sending and receiving messages from config thread.
         */
        class CommLinkEP
        {
        public:
            /**
             * Constructor
             * @param link Reference to main  DDP::CommLink owning this endpoint.
             */
            CommLinkEP(CommLink& link, int ep) :
                m_cl_owner(link), m_read_ep(ep), m_write_ep((ep + 1) % 2) {}

            /**
             * Send given message to worker EP.
             * @param msg Send message.
             */
            void send(Message& msg);

            /**
             * Send given message to worker EP.
             * @param msg Send message.
             */
            void send(Message&& msg) { send(msg); }

            /**
             * Receive message from worker. Receiving is non blocking.
             * @return Received message from worker.
             */
            std::unique_ptr<Message> recv();

            /**
             * Provides file descriptor which can be used for select (and others) call. When the descriptor is ready for
             * read then DDP::CommLink::CommLinkEP::recv is ready to provide message.
             * @return File descriptor for select
             */
            int fd() { return m_cl_owner.m_event_fd[m_read_ep]; }

        private:
            CommLink& m_cl_owner; //!<  Instance of DDP::CommLink owning instance of this class
            int m_read_ep;
            int m_write_ep;
        };

        /**
         * Constructor
         * @param size Maximal number of items in communication ring
         * @param single_producer Enable sending messages from multiple threads.
         */
        explicit CommLink(unsigned size = 32, bool single_producer = true);

        /**
         * Destructor
         */
        virtual ~CommLink();

        /**
         * Disable copy constructor
         */
        CommLink(const CommLink&) = delete;

        /**
         * Disable move constructor
         */
        CommLink(CommLink&& cl) = delete;

        /**
         * Disable assign operator
         */
        CommLink& operator=(CommLink&&) = delete;

        /**
         * Provides access to config endpoint instance
         * @return Config endpoint instance
         */
        CommLinkEP& config_endpoint() { return m_ep[0]; }

        /**
         * Provides access to worker endpoint instance
         * @return Worker endpoint instance
         */
        CommLinkEP& worker_endpoint() { return m_ep[1]; }

    private:
        std::array<std::unique_ptr<Ring<DDP::Message*>>, 2> m_rings; //!< Rings used for sending messages
        std::array<FileDescriptor, 2> m_event_fd; //!< File descriptors used for informing about new messages
        std::array<CommLinkEP, 2> m_ep; //!< Endpoints
    };
}
