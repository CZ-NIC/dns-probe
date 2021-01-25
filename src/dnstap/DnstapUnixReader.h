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
#include <sys/un.h>
#include <fstrm.h>
#include "platform/Packet.h"

namespace DDP {
    /**
     * @brief Class for reading fstrm frames containing dnstap messages from unix socket
     */
    class DnstapUnixReader {
    public:
        /**
         * @brief Structure holding inner state of fstrm reader
         */
        struct fstrm__unix_reader {
            fstrm__unix_reader() : connected(false), fd(-1) {}

            bool connected;
            int fd;
        };

        /**
         * @brief Initialize fstrm reader and prepare to read fstrm frames from the socket
         * @param fd Unix socket to read data from
         */
        DnstapUnixReader(int fd);

        /**
         * @brief Destroy fstrm reader and close the unix socket
         */
        ~DnstapUnixReader();

        /**
         * @brief Read a frame stream containing one dnstap message
         * @param pkt Packet to store read dnstap message in wire format
         * @return 1 if a dnstap message was successfully read, 0 otherwise
         * @throw PortEOF when client ends the connection
         */
        uint16_t read(Packet* pkt);

    private:
        int m_fd;
        fstrm__unix_reader m_opts;
        fstrm_reader* m_reader;
    };
}
