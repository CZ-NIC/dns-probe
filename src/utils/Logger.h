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
#include <sstream>
#include <fstream>
#include <iomanip>
#include <cstdio>
#include <time.h>

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
            if (level == LogLevel::DEBUG) {
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
         * @brief Move constructor. Moves the std::ostringstream member variable.
         * @param other Source EntryAssembler
         */
        EntryAssembler(EntryAssembler&& other)
        {
            this->m_msg = std::move(other.m_msg);
        }

        /**
         * When the object is destroyed its content is send to master core for creating log message.
         */
        ~EntryAssembler()
        {
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
        explicit EntryAssembler(const char*) {}

        /**
         * Optimize out debug messages.
         * @tparam T Type of message
         * @param msg Message whic will be discarded.
         * @return Reference to itself so it can be used for another concatenation.
         */
        template<typename T>
        EntryAssembler& operator<<(T&&)
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

    /**
     * Log output stream. NOT thread-safe, use one object per thread.
     */
    class LogWriter {
        using expander = int[];
    public:
        /**
         * @brief Creates new logging output. Default to stdout.
         */
        explicit LogWriter() : m_out(std::cout.rdbuf()), m_os(std::make_unique<std::ostream>(m_out)) {}

        ~LogWriter() {
            m_of.close();
        }
        /**
         * @brief Set new output target for the logs
         * @param outfile New output target
         */
        void set_output(const std::string&& outfile) {
            m_of.close();
            m_of.open(outfile, std::ofstream::out | std::ofstream::app);
            m_out = m_of.rdbuf();
            m_os = std::make_unique<std::ostream>(m_out);
        }

        /**
         * @brief Set new output target for the logs
         * @param outbuf New output target
         */
        void set_output(std::ostream& outbuf) {
            m_of.close();
            m_out = outbuf.rdbuf();
            m_os = std::make_unique<std::ostream>(m_out);
        }

        /**
         * @brief Write given arguments to log output
         * @tparam Args Arguments list
         * @param args List of arguments to print as one log message
         */
        template<typename... Args>
        void log(Args&&... args) {
            pid_t pid = getpid();
            *m_os << "[" << get_timestamp() << "] [0x" << std::setw(8) << std::hex
                  << std::setfill('0') << pid << std::setfill(' ') << "] ";
            (void)expander{0, (void(*m_os << std::forward<Args>(args)), 0)...};
            *m_os << std::endl;
        }

        /**
         * @brief Write given arguments to log output
         * @tparam Args Arguments list
         * @param lvl Importance level of log message
         * @param args List of arguments to print as one log message
         */
        template<class... Args>
        void log_lvl(const char* lvl, Args&&... args) {
            pid_t pid = getpid();
            *m_os << "[" << get_timestamp() << "] [0x" << std::setw(8) << std::hex
                  << std::setfill('0') << pid << std::setfill(' ') << "] [" << lvl << "] ";
            (void)expander{0, (void(*m_os << std::forward<Args>(args)), 0)...};
            *m_os << std::endl;
        }

    protected:
        /**
         * @brief Get current timestamp as formated string
         * @return Formated timestamp
         */
        std::string get_timestamp() {
            timespec timestamp;
            char time[30];
            tm tmp_tm;
            clock_gettime(CLOCK_REALTIME, &timestamp);
            localtime_r(&timestamp.tv_sec, &tmp_tm);
            auto pos = strftime(time, 30, "%Y-%m-%d %H:%M:%S.", &tmp_tm);
            std::snprintf(time + pos, sizeof(time) - pos, "%06lu", timestamp.tv_nsec / 1000);
            return std::string(time);
        }

        std::ofstream m_of;
        std::streambuf* m_out;
        std::unique_ptr<std::ostream> m_os;
    };
}

extern DDP::LogWriter logwriter; //!< NOT thread-safe, use only on configuration thread
