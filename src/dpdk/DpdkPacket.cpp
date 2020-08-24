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
#include <algorithm>

#include <rte_mbuf.h>
#include "DpdkPacket.h"
#include "platform/Allocator.h"

DDP::DPDKPacket::DPDKPacket(rte_mbuf* mbuf) : m_payload(), m_used_mbuf(true), m_mbuf(mbuf)
{
    if (mbuf->nb_segs > 1) {
        auto buffer = reinterpret_cast<uint8_t*>(Alloc::malloc(mbuf->pkt_len));
        if (!buffer)
            throw std::bad_alloc();
        std::size_t seg_offset = 0;
        rte_mbuf* temp = mbuf;

        for (int i = 0; i < mbuf->nb_segs; i++) {
            std::memcpy(buffer + seg_offset, rte_pktmbuf_mtod(temp, uint8_t*), temp->data_len);
            seg_offset += temp->data_len;
            temp = temp->next;
        }

        m_buffer = buffer;
        m_used_mbuf = false;
        m_payload = MemView<uint8_t>(m_buffer, seg_offset);
    }
    else {
        m_payload = MemView<uint8_t>(rte_pktmbuf_mtod(m_mbuf, uint8_t*), rte_pktmbuf_data_len(m_mbuf));
        rte_pktmbuf_refcnt_update(mbuf, 1);
    }
}

DDP::DPDKPacket::DPDKPacket(const DDP::DPDKPacket& packet) : m_payload(),
                                                             m_used_mbuf(false),
                                                             m_buffer(nullptr)
{
    if (packet.used_mbuf()) {
        m_used_mbuf = true;
        m_mbuf = packet.mbuf();
        m_payload = MemView<uint8_t>(rte_pktmbuf_mtod(m_mbuf, uint8_t*), rte_pktmbuf_data_len(m_mbuf));
        rte_pktmbuf_refcnt_update(m_mbuf, 1);
    }
    else {
        m_buffer = reinterpret_cast<uint8_t*>(Alloc::malloc(packet.m_payload.count()));
        if(!m_buffer)
            throw std::bad_alloc();

        std::copy(packet.m_payload.ptr(), packet.m_payload.ptr() + packet.m_payload.count(), m_buffer);

        m_payload = MemView<uint8_t>(m_buffer, packet.m_payload.count());
    }
}

DDP::DPDKPacket::DPDKPacket(const MemView<uint8_t>& data) : m_payload(),
                                                            m_used_mbuf(false),
                                                            m_buffer(nullptr)
{
    m_buffer = reinterpret_cast<uint8_t*>(Alloc::malloc(data.count()));
    if (!m_buffer)
        throw std::bad_alloc();
    
    std::copy(data.ptr(), data.ptr() + data.count(), m_buffer);

    m_payload = MemView<uint8_t>(m_buffer, data.count());
}

void DDP::DPDKPacket::free()
{
    if (!m_used_mbuf)
        Alloc::free(m_buffer);
    else
        rte_pktmbuf_free(m_mbuf);
}
