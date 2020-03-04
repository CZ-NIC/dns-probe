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

#include <sstream>

#include "config/Config.h"
#include "core/Statistics.h"

namespace DDP {
    /**
     * @brief Wrapper for messages send over CommLink
     *
     * This class can contain simple type. If is required to carry more information than type then it can be achieved
     * by inheriting from the Message class. Based on method `Message::type` it can be `Message` converted through
     * dynamic cast into derived type.
     */
    class Message
    {
    public:
        /**
         * @brief Types of available messages
         */
        enum class Type
        {
            NEW_CONFIG, //!< Message contains new configuration for workers
            LOG, //!< Message with log message
            STOP, //!< Message informing workers to exit
            WORKER_STOPPED, //!< Message informing main thread that worker exited and it is ready to join
            ROTATE_OUTPUT //!< Message instructing workers and exporter to rotate current output file
        };

        /**
         * Creates new Message
         * @param type Type of new message
         */
        explicit Message(Type type) : m_type(type) {}

        /**
         * Return type of message
         * @return Type of message
         */
        Type type() { return m_type; }

        /**
         * Default destructor
         */
        virtual ~Message() = default;

        /**
         * Creates copy of current message. This should be overriden by derived classes.
         * @return Copyied message
         */
        virtual Message* clone() { return new Message(m_type); };

    protected:
        Type m_type; //!< Type of message
    };

    /**
     * Message containing new configuration
     */
    class MessageNewConfig : public Message
    {
    public:
        /**
         * Creates new message with configuration
         * @param cfg Configuration passed to receiving client
         */
        explicit MessageNewConfig(Config cfg) : Message(Type::NEW_CONFIG), cfg(std::move(cfg)) {}

        /**
         * Creates copy of current message. This should be overriden by derived classes.
         * @return Copyied message
         */
        Message* clone() override { return new MessageNewConfig(cfg); }

        Config cfg;
    };

    /**
     * Message confining log message
     */
    class MessageLog : public Message
    {
    public:
        /**
         * Creates message with log message
         * @param msg Log message passed to main thread
         */
        explicit MessageLog(std::ostringstream&& msg) : Message(Type::LOG), msg(std::move(msg)) {}

        /**
         * Creates copy of current message. This should be overriden by derived classes.
         * @return Copyied message
         */
        Message* clone() override { return new MessageLog(std::move(msg)); }

        std::ostringstream msg; //!< Carried message
    };

    /**
     * Message informing main thread that worker stopped and it is ready to join
     */
    class MessageWorkerStopped : public Message
    {
    public:
        /**
         * Creates message with lcore id of exited thread
         * @param lcore Lcore ID of thread waiting for join
         */
        explicit MessageWorkerStopped(unsigned lcore) : Message(Type::WORKER_STOPPED), lcore(lcore) {}

        /**
         * Creates copy of current message. This should be overriden by derived classes.
         * @return Copyied message
         */
        Message* clone() override { return new MessageWorkerStopped(lcore); }

        unsigned lcore; //<! LCore of stopped thread
    };
}