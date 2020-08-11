/*
 *  Copyright (C) 2020 CZ.NIC, z.s.p.o.
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

#include <string>
#include <cstdint>
#include <vector>
#include <future>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/ssl.h>

namespace DDP {
    /**
     * @brief Class for handling one incoming SSL connection
     */
    class ConnectionHandler {
        public:
        /**
         * @brief Enum describing possible states of connection on application layer
         */
        enum ConnectionStates : uint8_t {
            FILE_LENGTH = 0,
            FILE_NAME,
            DATA,
            FINISHED
        };

        /**
         * @brief Handler constructor. Initializes new SSL connection and performs handshake.
         * @param conn New incoming connection's socket
         * @param ctx SSL context (READ ONLY)
         * @throw std::runtime_error
         */
        ConnectionHandler(int conn, SSL_CTX* ctx);

        /**
         * @brief Destructor gracefuly closes SSL connection.
         */
        ~ConnectionHandler() {
            if (m_ssl) {
                SSL_shutdown(m_ssl);
                SSL_free(m_ssl);
            }

            if (m_fd >= 0)
                ::close(m_fd);

            struct stat buffer;
            if (stat((m_file_name + ".part").c_str(), &buffer) == 0) {
                std::remove((m_file_name + ".part").c_str());
            }
        }

        /**
         * @brief Main connection loop. Polls socket for new data and writes it to output file.
         * @throw std::runtime_error
         */
        void run();

        private:
        /**
         * @brief Reads new data from socket and writes it to output file.
         * @throw std::runtime_error
         */
        void read_data();

        int m_fd;
        SSL_CTX* m_ctx;
        SSL* m_ssl;
        ConnectionStates m_state;
        uint8_t m_file_length;
        std::string m_file_name;
        std::ofstream m_out;
    };

    /**
     * @brief Incoming connection handler function. This is the function given to async thread.
     * @param conn New incoming connection's socket
     * @param ctx SSL context (READ ONLY)
     */
    void connection_handler(int conn, SSL_CTX* ctx);

    /**
     * @brief Main server accepting incoming connections and spawning async threads
     * for handling them. Can handle multiple clients at once.
     */
    class Collector {
        public:
        static constexpr uint8_t TIMEOUT_LIMIT = 128; //!< Connection limit after which m_threads vector is checked for already finished threads

        /**
         * @brief Server constructor. Creates socket for listening for incoming connections and
         * initializes SSL library and SSL context.
         * @param cert Location of server certificate
         * @param key Location of server's private key
         * @param ip Collector's IP address to listen on
         * @param port Collector's transport protocol port to listen on
         * @throw std::runtime_error
         */
        Collector(std::string& cert, std::string& key, std::string& ip, uint16_t port);

        /**
         * @brief Destructor frees SSL context and closes socket
         */
        ~Collector() { close(); }

        /**
         * @brief Main server loop. Accepts incoming connections and spawns async threads for handling them.
         * @throw std::runtime_error
         */
        void run();

        private:
        /**
         * @brief Clean up method. Frees SSL context and closes socket.
         */
        void close() {
            if (m_ctx)
                SSL_CTX_free(m_ctx);

            if (m_fd >= 0)
                ::close(m_fd);
        }

        std::string m_cert;
        std::string m_key;
        std::string m_ip;
        uint16_t m_port;
        int m_fd;
        SSL_CTX* m_ctx;
        std::vector<std::future<void>> m_threads;
    };
}