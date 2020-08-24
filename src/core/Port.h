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

#include <cstdint>
#include <vector>

#include "platform/Packet.h"
#include "utils/Logger.h"

namespace DDP {
    class PortEOF : public std::runtime_error
    {
    public:
        PortEOF() : runtime_error("EOF") {}
    };

    /**
     * @brief Abstract class representing one network port
     * Represents universal interface for read, write methods
     * Derived classes must specify its own port identifier and other port parameters
     */
    class Port {
    
    public:
        constexpr static unsigned BATCH_SIZE = 32; //!< DON'T CHANGE (Calibrated for AF_PACKET ring buffer)
        
        /**
         * @brief Constructor, derived class must specify its own port identifier
         * @param num_queues Number of port's RX/TX queues
         * @param batch_size Maximum number of packets to read from port at once
         */
        explicit Port(uint16_t num_queues) : m_num_queues(num_queues) {}

        virtual ~Port() = default;;

        /**
         * @brief Read up to m_batch_size packets from network port's RX queue and store them in given array
         * @param batch Array of Packets where read packets are stored
         * @param queue Which RX queue to read from
         * @return Number of packets actually read from RX queue
         * @throw PortEOF The PortEOF is raised when the port won't produce any more packets
         */
        virtual uint16_t read(Packet* batch, unsigned queue) = 0;

        /**
         * @brief Free packets from the current batch (needed for AF_PACKET sockets with ring buffers)
         * @param queue RX queue from which the packets originate
         */
        virtual void free_packets(unsigned queue) = 0;

        virtual std::vector<int> fds() {return {};}

    protected:
        uint16_t m_num_queues;
    };
}