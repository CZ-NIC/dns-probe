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

#include <iostream>
#include "PcapPort.h"

DDP::PCAPPort::PCAPPort(const char* port) : Port(1), m_handle(nullptr)
{
    m_handle = pcap_open_offline(port, nullptr);
    if (m_handle == nullptr)
        throw std::runtime_error("Cannot open PCAP file!");
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
            std::cerr << "[WARNING] Packet: Unable to read packet data." << std::endl;
        }
    }

    if(!rx_count)
        throw PortEOF();
    return rx_count;
}
