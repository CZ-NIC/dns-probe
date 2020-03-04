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

#include <iostream>
#include <sstream>

#include "core/Probe.h"

namespace DDP {
    /**
     * Define category for log record.
     */
    enum class LogLevel
    {
        DEBUG,
        INFO,
        WARNING,
        ERROR
    };

    /**
     * Proxy object for concatenating log messages. This object allows creates log messages with the operatror <<.
     * When the object is destroyed its content is send to master core for writing the log message itself.
     * @tparam level Category of created log record.
     */
    template<LogLevel level>
    class EntryAssembler
    {
    public:
        /**
         * Construtctor.
         * @param name Name of the subsystem creating a log message.
         */
        explicit EntryAssembler(const char* name) : m_msg()
        {
            if constexpr (level == LogLevel::DEBUG) {
                m_msg << "[DEBUG] ";
            } else if (level == LogLevel::INFO) {
                m_msg << "[INFO] ";
            } else if (level == LogLevel::WARNING) {
                m_msg << "[WARNING] ";
            } else if (level == LogLevel::ERROR) {
                m_msg << "[ERROR] ";
            } else {
                m_msg << "[UNKNOWN] ";
            }

            m_msg << name << ": ";
        }

        /**
         * When the object is destroyed its content is send to master core for creating log message.
         */
        ~EntryAssembler()
        {
            m_msg << std::endl;
            Probe::getInstance().log_link().send(MessageLog(std::move(m_msg)));
        }

        /**
         * Allows concatenating messages with the operator <<.
         * @tparam T Type of input text (will be deduced)
         * @param msg Input text which will be concatenated with previous text holding by this object.
         * @return Reference to itself so it can be used for another concatenation.
         */
        template<typename T>
        EntryAssembler& operator<<(T&& msg)
        {
            m_msg << std::forward<T>(msg);
            return *this;
        }

    private:
        std::ostringstream m_msg; //!< Text message processed by this object.
    };

#ifndef PRINT_DEBUG
    /**
     * Disable debug messages for DDP::EntryAssembler.
     */
    template<>
    class EntryAssembler<LogLevel::DEBUG>
    {
    public:
        /**
         * Constructor has no effect.
         * @param name Kept only for compatibility.
         */
        explicit EntryAssembler(const char* name) {}

        /**
         * Optimize out debug messages.
         * @tparam T Type of message
         * @param msg Message whic will be discarded.
         * @return Reference to itself so it can be used for another concatenation.
         */
        template<typename T>
        EntryAssembler& operator<<([[maybe_unused]] T&& msg)
        {
            return *this;
        }
    };
#endif

    /**
     * Provides interface for thread-safe logging messages.
     */
    class Logger
    {
    public:
        /**
         * Creates new logger.
         * @param name Name of the subsystem. The name will be part of all messages produced by instance of this object.
         */
        explicit Logger(const char* name) : m_name(name) {}

        /**
         * Provides access to proxy object which will creates debug record.
         * @return Proxy object for concatenation messages.
         */
        auto debug() { return EntryAssembler<LogLevel::DEBUG>(m_name); }

        /**
         * Provides access to proxy object which will creates info record.
         * @return Proxy object for concatenation messages.
         */
        auto info() { return EntryAssembler<LogLevel::INFO>(m_name); }

        /**
         * Provides access to proxy object which will creates warning record.
         * @return Proxy object for concatenation messages.
         */
        auto warning() { return EntryAssembler<LogLevel::WARNING>(m_name); }

        /**
         * Provides access to proxy object which will creates error record.
         * @return Proxy object for concatenation messages.
         */
        auto error() { return EntryAssembler<LogLevel::ERROR>(m_name); }

    private:
        const char* m_name; //!< Name of associated subsystem.
    };
}