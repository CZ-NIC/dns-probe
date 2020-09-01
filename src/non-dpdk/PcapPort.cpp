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

#include <iostream>
#include <sys/eventfd.h>
#include "PcapPort.h"

DDP::PCAPPort::PCAPPort(const char* port, uint16_t num_queues) : Port(1), m_handle(nullptr)
{
    char err_buff[PCAP_ERRBUF_SIZE];
    m_handle = pcap_open_offline(port, err_buff);
    if (m_handle == nullptr)
        throw std::runtime_error(std::string("Cannot open PCAP file: ") + std::string(err_buff));

    for(unsigned i = 0; i < num_queues; i++) {
        m_eventfds.emplace_back(::eventfd(1, 0));
    }
}

uint16_t DDP::PCAPPort::read(Packet* batch, unsigned queue)
{
    if(queue != 0)
        throw PortEOF();

    uint16_t rx_count = 0;
    struct pcap_pkthdr* pkthdr;
    const u_char* pkt_data;

    for (auto i = 0u; i < Port::BATCH_SIZE; i++) {
        int code = pcap_next_ex(m_handle, &pkthdr, &pkt_data);
        if (code != 1)
            break;

        try {
            batch[i] = Packet(pkt_data, pkthdr->caplen);
            rx_count++;
        }
        catch (std::exception& e) {
            Logger("Packet").warning() << "Unable to read packet data.";
        }
    }

//    if(!rx_count)
//        throw PortEOF();
    return rx_count;
}

std::vector<int> DDP::PCAPPort::fds()
{
    std::vector<int> fds;
    for(auto&& fd: m_eventfds) {
        fds.push_back(fd);
    }
    return fds;
}
