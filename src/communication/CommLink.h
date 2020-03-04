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
        class CommLinkConfigEP
        {
        public:
            /**
             * Constructor
             * @param link Reference to main  DDP::CommLink owning this endpoint.
             */
            explicit CommLinkConfigEP(CommLink& link) : m_cl_owner(link) {}

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
             * read then DDP::CommLink::CommLinkConfigEP::recv is rady to provide message.
             * @return File descriptor for select
             */
            int fd() { return m_cl_owner.m_event_fd; }

        private:
            CommLink& m_cl_owner; //!<  Instance of DDP::CommLink owning instance of this class
        };

        /*
         * Implementation for worker endpoint allowing sending and receiving messages from worker thread.
         */
        class CommLinkWorkerEP
        {
        public:

            /**
             * Constructor
             * @param link Reference to main  DDP::CommLink owning this endpoint.
             */
            explicit CommLinkWorkerEP(CommLink& link) : m_cl_owner(link) {}

            /**
             * Send given message to config EP.
             * @param msg Send message.
             */
            void send(Message& msg);

            /**
             * Send given message to config EP.
             * @param msg Send message.
             */
            void send(Message&& msg) { send(msg); }

            /**
             * Receive message from worker. Receiving is non blocking.
             * @return Received message from worker.
             */
            std::unique_ptr<Message> recv();

        private:
            CommLink& m_cl_owner; //!<  Instance of DDP::CommLink owning instance of this class
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
        CommLinkConfigEP& config_endpoint() { return m_config_ep; }

        /**
         * Provides access to worker endpoint instance
         * @return Worker endpoint instance
         */
        CommLinkWorkerEP& worker_endpoint() { return m_worker_ep; }

    private:
        /**
         * Constants identifying correct ring from m_rings.
         */
        enum class RingDirection
        {
            TO_CONFIG = 0,
            FROM_WORKER = 0,
            TO_WORKER = 1,
            FROM_CONFIG = 1,
        };


        std::array<std::unique_ptr<Ring<DDP::Message*>>, 2> m_rings; //!< Rings used for sending messages
        FileDescriptor m_event_fd; //!< File descriptor used for informing config endpoint about new messages

        CommLinkWorkerEP m_worker_ep; //!< Worker endpoint
        CommLinkConfigEP m_config_ep; //!< Config endpoint
    };
}
