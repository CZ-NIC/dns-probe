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

#include <stdexcept>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
extern "C" {
    #include <libknot/libknot.h>
}

#include "KnotSocket.h"
#include "core/Port.h"
#include "platform/Packet.h"
#include "utils/Logger.h"

DDP::KnotSocket::KnotSocket(std::string& sock_path, uint32_t idx)
    : Port(1), m_socket_path(sock_path), m_idx(idx), m_fd(-1), m_knot_ctx(nullptr), m_data()
{
    m_knot_ctx = knot_probe_alloc();
    if (!m_knot_ctx)
        throw std::runtime_error("Couldn't allocate Knot interface context!");

    auto ret = knot_probe_set_consumer(m_knot_ctx, sock_path.c_str(), idx);
    if (ret != KNOT_EOK)
        throw std::runtime_error("Couldn't initialize Knot interface socket! Error: " + ret);

    m_fd = knot_probe_fd(m_knot_ctx);
}

DDP::KnotSocket::~KnotSocket()
{
    if (m_knot_ctx) {
        knot_probe_free(m_knot_ctx);
        m_knot_ctx = nullptr;
        m_fd = -1;
    }
}

uint16_t DDP::KnotSocket::read(Packet* pkt, unsigned)
{
    uint16_t rx_count = 0;
    auto ret = knot_probe_consume(m_knot_ctx, m_data.data(), BATCH_SIZE, 0);

    for (int i = 0; i < ret; i++) {
        try {
            pkt[rx_count] = Packet(reinterpret_cast<uint8_t*>(&m_data[i]), sizeof(knot_probe_data_t), false, PacketType::KNOT);
            rx_count++;
        }
        catch (std::exception& e) {
            Logger("Knot").warning() << "Unable to read Knot interface datagram.";
        }
    }

    return rx_count;
}
