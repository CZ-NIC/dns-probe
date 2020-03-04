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

#include <exception>
#include <algorithm>
#include <cstring>
#include "AfPacket.h"
#include "platform/Allocator.h"

DDP::AFPacket::AFPacket(const uint8_t* packet, std::size_t size)
{
    auto buffer = reinterpret_cast<uint8_t*>(Alloc::malloc(size));
    if (!buffer)
        throw std::bad_alloc();

    std::memcpy(buffer, packet, size);
    m_buffer = buffer;
    m_payload = MemView<uint8_t>(m_buffer, size);
    m_owner = true;
}

DDP::AFPacket::AFPacket(const uint8_t* packet, std::size_t size, bool owner)
{
    if (owner) {
        auto buffer = reinterpret_cast<uint8_t*>(Alloc::malloc(size));
        if (!buffer)
            throw std::bad_alloc();

        std::memcpy(buffer, packet, size);
        m_buffer = buffer;
        m_payload = MemView<uint8_t>(m_buffer, size);
        m_owner = true;
    }
    else {
        m_buffer = const_cast<uint8_t*>(packet);
        m_payload = MemView<uint8_t>(m_buffer, size);
        m_owner = false;
    }
}

DDP::AFPacket::AFPacket(const DDP::AFPacket& packet) : m_payload(), m_buffer(nullptr), m_owner(false)
{
    if (packet.m_buffer) {
        m_buffer = reinterpret_cast<uint8_t*>(Alloc::malloc(packet.size()));
        if (!m_buffer)
            throw std::bad_alloc();
        
        std::copy(packet.m_payload.ptr(), packet.m_payload.ptr() + packet.m_payload.count(), m_buffer);
        m_payload = MemView<uint8_t>(m_buffer, packet.m_payload.count());
        m_owner = true;
    }
}

void DDP::AFPacket::free()
{
    if (m_buffer && m_owner) {
        Alloc::free(m_buffer);
        m_buffer = nullptr;
    }
}