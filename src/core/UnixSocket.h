/*
 *  Copyright (C) 2021 CZ.NIC, z. s. p. o.
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

#include <cstdint>
#include <vector>
#include <string>
#include "core/Port.h"

namespace DDP {
    /**
     * @brief Class representing AF_UNIX socket on which incoming connections are
     * accepted and returned by the read(Packet*, unsigned) method.
     * Each UnixSocket object should be processed by a single thread.
     */
    class UnixSocket : public Port {
    public:
        /**
         * @brief Constructor. Creates AF_UNIX socket in location given by "socket"
         * parameter and starts listening on it.
         * @param sock_path Location where to create the socket
         * @param sock_group User group under which to create the socket
         * @throw std::runtime_error
         */
        explicit UnixSocket(const char* sock_path, const std::string sock_group);

        /**
         * @brief Destructor. Closes the socket and deletes it from filesystem.
         */
        ~UnixSocket() override;

        // Delete copy constructor and assignment operator
        UnixSocket(const UnixSocket&) = delete;
        UnixSocket& operator=(const UnixSocket) = delete;

        /**
         * @brief Accept a new incoming connection on the socket
         * @return File descriptor of the accepted connection. 0 if no new connection was accepted.
         */
        uint16_t read(Packet*, unsigned) override;

        void free_packets(unsigned) override {}

        /**
         * @brief Return file descriptor of the AF_UNIX socket
         */
        std::vector<int> fds() override { return std::vector<int>{m_fd}; }

    private:
        std::string m_socket_path;
        int m_fd;
    };
}
