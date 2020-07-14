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
#include <pcap.h>
#include <utils/FileDescriptor.h>
#include "core/Port.h"

namespace DDP {

    /**
     * @brief Class representing PCAP capture handled by libpcap
     * Singlethread only. PCAP file is read through only 1 RX queue 
     */
    class PCAPPort : public Port {
    public:
        /**
         * @brief Constructor. Initializes given PCAP file for reading.
         * @param port PCAP file name
         * @param batch_size Maximum number of packets to read from PCAP at once
         * @throw std::runtime_error
         */
        explicit PCAPPort(const char* port, uint16_t num_queues);

        /**
         * @brief Destructor. Closes PCAP file.
         */
        ~PCAPPort() override { if (m_handle) pcap_close(m_handle); }

        // Delete copy constructor and assignment operator
        PCAPPort(const PCAPPort&) = delete;
        PCAPPort& operator=(const PCAPPort) = delete;

        /**
         * @brief Read up to m_batch_size packets from PCAP and store them in given array
         * @param batch Array of Packets where read packets are stored
         * @param queue Which RX queue to read from. Unnecesarry as PCAP has only 1 RX queue.
         * @return Number of packets actually read from PCAP file
         */
        uint16_t read(Packet* batch, unsigned queue) override;

        /**
         * @brief Free packets from the current batch (Does nothing)
         * @param queue RX queue from which the packets originate
         */
        void free_packets(unsigned) override {}

        std::vector<int> fds() override;

    private:
        pcap_t* m_handle; //!< Handle used for libpcap calls.
        std::vector<FileDescriptor> m_eventfds;
    };
}