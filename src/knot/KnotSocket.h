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
#include <array>
#include <string>
#include <sys/un.h>
extern "C" {
    #include <libknot/libknot.h>
}
#include "core/Port.h"

namespace DDP {
    /**
     * @brief Class for reading Knot interface datagrams from unix socket
     */
    class KnotSocket : public Port {
    public:
        /**
         * @brief Constructor. Creates Knot interface socket in location given by "sock_path"
         * parameter and starts listening on it.
         * @param sock_path Directory where to create Knot socket
         * @param idx Id of the Knot socket
         */
        explicit KnotSocket(std::string& sock_path, uint32_t idx);

        /**
         * @brief Destructor. Closes the Knot interface socket.
         */
        ~KnotSocket() override;

        // Delete copy constructor and assignment operator
        KnotSocket(const KnotSocket&) = delete;
        KnotSocket& operator=(const KnotSocket) = delete;

        /**
         * @brief Read a frame stream containing one dnstap message
         * @param pkt Packet to store read dnstap message in wire format
         * @return 1 if a dnstap message was successfully read, 0 otherwise
         * @throw PortEOF when client ends the connection
         */
        uint16_t read(Packet* pkt, unsigned) override;

        void free_packets(unsigned) override {}

        /**
         * @brief Return file descriptor of the Knot interface socket
         */
        std::vector<int> fds() override { return std::vector<int>{m_fd}; }

    private:
        std::string m_socket_path; //!< Directory where unix socket is created
        uint32_t m_idx; //!< ID of given socket (starts from 1)
        int m_fd; //!< File descriptor to unix socket associated with Knot interface
        knot_probe_t* m_knot_ctx; //!< Knot interface context
        std::array<knot_probe_data_t, BATCH_SIZE> m_data; //!< Array to store datagrams read from unix socket
    };
}
