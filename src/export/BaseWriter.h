/*
 *  Copyright (C) 2020 Brno University of Technology
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

#include <string>
#include <cstdint>
#include <vector>
#include <future>

#include "config/Config.h"

struct ssl_ctx_st;
typedef struct ssl_ctx_st SSL_CTX;
struct ssl_st;
typedef struct ssl_st SSL;

namespace DDP {
    /**
     * @brief Send local file to remote server via TLS connection
     * @param cfg Configuration (server IP, port)
     * @param filename Name of the file to send WITHOUT the ".part" sufix
     */
    void send_file(Config cfg, std::string filename);

    /**
     * @brief Singleton RAII wrapper around SSL_CTX structure from OpenSSL library
     */
    class TlsCtx {
        public:

        TlsCtx(const TlsCtx&) = delete;
        TlsCtx& operator=(const TlsCtx&) = delete;

        /**
         * @brief Get the singleton intance of TlsCtx
         * @return Singleton instance
         */
        static TlsCtx& getInstance() {
            static TlsCtx instance;
            return instance;
        }

        /**
         * @brief Initialize SSL/TLS context. Needs to be called before using the context
         * @param ca_cert CA certificate to verify server for TLS connection
         */
        void init(std::string ca_cert);

        SSL_CTX* get() { return m_ctx; }

        private:
        TlsCtx() : m_ctx(nullptr) {}

        /**
         * @brief Free the SSL/TLX context
         */
        ~TlsCtx();

        SSL_CTX* m_ctx;
    };

    /**
     * @brief RAII wrapper around TLS connection using OpenSSL library
     */
    class TlsConnection {
        public:

        /**
         * @brief Construct a new TLS connection from given configuration
         * @param cfg Configuration to use for new TLS connection
         */
        TlsConnection(Config& cfg) : m_fd(-1), m_ssl(nullptr), m_ctx(nullptr),
                                     m_ip(cfg.export_ip.value()),
                                     m_port(cfg.export_port.value()) { open(); }

        /**
         * @brief Destructor. Closes the TLS connection if it's still opened
         */
        ~TlsConnection() { close(); }

        /**
         * @brief Gracefully close the TLS connection
         */
        void close();

        /**
         * @brief Send given data through the TLS connection
         * @param data Buffer with data to send
         * @param n_bytes Length of the data buffer
         * @return Number of bytes successfully sent through the TLS connection
         */
        int write(const void* data, int64_t n_bytes);

        /**
         * @brief Check if the TLS connection is already closed
         * @return TRUE if the connection is closed, FALSE otherwise
         */
        bool closed() const { return m_ssl ? false : true; }

        private:
        /**
         * @brief Open new TLS connection
         */
        void open();

        int m_fd;
        SSL* m_ssl;
        SSL_CTX* m_ctx;
        std::string m_ip;
        uint16_t m_port;
    };

    /**
     * @brief Abstract class serving as interface for output writing classes
     */
    class BaseWriter {
        public:
        /**
         * @brief Construct a new BaseWriter object
         * @param cfg Configuration of the output
         * @param process_id Process ID used for generating names of the output files
         * @param sufix Sufix of the generated names for export files
         */
        explicit BaseWriter(Config& cfg, uint32_t process_id, std::string sufix = "") :
            m_cfg(cfg),
            m_id("_p" + std::to_string(process_id)),
            m_sufix(sufix),
            m_filename_counter(0),
            m_filename(),
            m_threads() {}

        virtual ~BaseWriter() {}

        /**
         * @brief Write given item with buffered DNS records to output
         * @param item Item with DNS records ready for export to output
         * @return Number of DNS records written to output
         */
        virtual int64_t write(boost::any item) = 0;

        /**
         * @brief Close current output and open a new one
         */
        virtual void rotate_output() = 0;

        /**
         * @brief Update configuration of the output
         * @param cfg New configuration of the output
         */
        void update_configuration(Config& cfg) {
            m_cfg = cfg;
        }

        /**
         * @brief Generate filename for given parameters
         * @param sufix Filename sufix after the last dot
         * @param invalid TRUE only for PCAP files with invalid packets
         * @return Newly generated filename
         */
        std::string filename(std::string sufix, bool invalid);

        protected:
        Config m_cfg;
        std::string m_id;
        std::string m_sufix;
        uint8_t m_filename_counter;
        std::string m_filename;
        std::vector<std::future<void>> m_threads;
    };
}