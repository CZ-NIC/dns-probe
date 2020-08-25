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

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <rte_mempool.h>

#include "core/Port.h"
#include "utils/FileDescriptor.h"

namespace DDP {
    using rte_mempool_t = std::unique_ptr<rte_mempool, std::function<void(rte_mempool*)>>;

    /**
     * @brief Class representing DPDK network port
     */
    class DPDKPort : public Port {
    public:
        constexpr static int RX_RING_SIZE = 1024; //!< Ring size for sending packets.
        constexpr static int MBUF_CACHE_SIZE = 256; //!< Cache size per core for mbufs.

        /**
         * @brief Constructor. Initializes given DPDK port
         * @param port DPDK port identifier
         * @param num_queues Number of RX/TX queues to allocate on port
         * @param mbuf_mempool DPDK memory pool for storage of rte_mbuf structures containing packets
         * @throw std::runtime_error
         */
        explicit DPDKPort(uint16_t port, uint16_t num_queues, rte_mempool_t& mbuf_mempool);

        /**
         * @brief Read up to m_batch_size packets from DPDK port's RX queue and store them in given array
         * @param batch Array of Packets where read packets are stored
         * @param queue Which RX queue to read from
         * @return Number of packets actually read from RX queue
         */
        uint16_t read(Packet* batch, unsigned queue) override;

        std::vector<int> fds() override;

        /**
         * @brief Free packets from the current batch (Does nothing)
         * @param queue RX queue from which the packets originate
         */
        void free_packets(unsigned) override {}

    private:
        uint16_t m_port; //!< Associated physical port.
        rte_mempool_t& m_mempool; //!< Associated mempool for receiving packets.
        std::vector<FileDescriptor> m_fds;

        /**
         * @brief Check if DPDK port was successfuly initialized and is up
         * @return Message with port status
         */
        std::string selected_link_status();
    };
}