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

#include <pcap.h>
#include <sys/stat.h>
#include <net/ethernet.h>
#include "PcapWriter.h"

void DDP::PcapWriter::create_file()
{
    m_filename = filename("pcap", m_invalid);

    pcap_t* handle = pcap_open_dead(DLT_RAW, 65535);
    if (!handle)
        throw std::exception();

    m_out = pcap_dump_open(handle, m_filename.c_str());
    if (!m_out)
        throw std::exception();

    chmod(m_filename.c_str(), 0666);
    m_exported_bytes = PCAP_PACKET_HEADER_LENGTH;
}

void DDP::PcapWriter::close_file()
{
    if (m_out) {
        int size;
        fseeko((FILE*)m_out, 0L, SEEK_END);
        size = ftello((FILE*)m_out);
        pcap_dump_close(m_out);

        if (size == PCAP_PACKET_HEADER_LENGTH)
            remove(m_filename.c_str());

        m_out = nullptr;
    }
}

int64_t DDP::PcapWriter::write(const Packet* pkt)
{
    if (!pkt)
        return 0;

    if (!m_out)
        create_file();

    if ((m_cfg.file_rot_size.value() > 0) && (m_cfg.file_rot_size.value() <=
         ((m_exported_bytes + pkt->size() + PCAP_PACKET_HEADER_LENGTH) / 1000000))) {
        rotate_output();
    }

    pcap_pkthdr packet_header;
    timeval ts;
    timespec timestamp;
    clock_gettime(CLOCK_REALTIME, &timestamp);
    TIMESPEC_TO_TIMEVAL(&ts, &timestamp);

    packet_header.ts = ts;

    if (m_raw_pcap) {
        if (!pkt->size())
            return 0;
        packet_header.caplen = pkt->size();
        packet_header.len = pkt->size();
        pcap_dump((u_char *) m_out, &packet_header, pkt->payload().ptr());
        m_exported_bytes += pkt->size() + PCAP_PACKET_HEADER_LENGTH;
    }
    else {
        if (pkt->size() <= sizeof(ether_header))
            return 0;
        packet_header.caplen = pkt->size() - sizeof(ether_header);
        packet_header.len = pkt->size() - sizeof(ether_header);
        pcap_dump((u_char *) m_out, &packet_header, pkt->payload().offset(sizeof(ether_header)).ptr());
        m_exported_bytes += (pkt->size() - sizeof(ether_header)) + PCAP_PACKET_HEADER_LENGTH;
    }

    return 1;
}
