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

#include <cstdint>
#include <array>

#include <unistd.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <sys/mman.h>
#include "core/Port.h"

namespace DDP {
    static constexpr unsigned BLOCK_SIZE = 65536;
    static constexpr unsigned FRAME_SIZE = 2048;
    static constexpr unsigned NUM_BLOCKS = 1024;
    static constexpr unsigned NUM_FRAMES = (BLOCK_SIZE * NUM_BLOCKS) / FRAME_SIZE;

    /**
     * @brief Class representing network port capture handled by AF_PACKET raw socket
     * Multithread safe. This is accomplished by using PACKET_FANOUT and PACKET_FANOUT_HASH
     * socket options that handle distribution of flows to worker cores.
     */
    class AFPacketPort : public Port {
    private:
        /**
         * @brief Structure holding information about one RX queue of network interface
         */
        struct alignas(64) QueueInfo {
            QueueInfo() : buffer(nullptr), next_packet(nullptr), socket(0), curr_block(0),
                          start_block(0), pkts_read(0) {}

            uint8_t* buffer;
            tpacket3_hdr* next_packet;
            int socket; // 1 socket for each worker core all connected to this network port
            unsigned curr_block;
            unsigned start_block;
            unsigned pkts_read;
        };

    public:
        /**
         * @brief Constructor. Initializes given network port. Creates AF_PACKET raw socket for each
         * queue.
         * @param port Interface name e.g. eth0 or PCI "domain:bus:slot.func"
         * @param num_queues Number of port's RX/TX queues (1 socket for each)
         * @param port_ID Interface's number ID (MUST be unique for each initialized port or
         * FANOUT groups will collide)
         * @throw std::runtime_error
         */
        explicit AFPacketPort(const char* port, uint16_t num_queues, uint16_t port_ID);

        /**
         * @brief Destructor. Closes all open sockets (queues).
         */
        ~AFPacketPort() override {
            int i = 0;
            for (auto info : m_info) {
                close(info.socket);
                if (info.buffer)
                    munmap(info.buffer, BLOCK_SIZE * NUM_BLOCKS);
                i++;
            }
        }

        // Delete copy constructor and assignment operator
        AFPacketPort(const AFPacketPort&) = delete;
        AFPacketPort& operator=(const AFPacketPort) = delete;

        /**
         * @brief Read up to m_batch_size packets from network port's RX queue (socket) and
         * store them in given array
         * @param batch Array of Packets where read packets are stored
         * @param queue Which RX queue (socket) to read from
         * @return Number of packets actually read from RX queue (socket)
         */
        uint16_t read(Packet* batch, unsigned queue) override;

        /**
         * @brief Free packets from the current batch (Returns current block
         * from ring buffer back to kernel)
         * @param queue RX queue from which the packets originate
         */
        void free_packets(unsigned queue) override;

        std::vector<int> fds() override;

    private:
        std::vector<QueueInfo> m_info;
    };
}