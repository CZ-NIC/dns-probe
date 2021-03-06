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
#include <pcap.h>
#include "utils/MemView.h"
#include "core/BasePacket.h"

namespace DDP {
    /**
     * @brief Class representing network packet read from socket or PCAP file
     */
    class AFPacket {
    public:
        /**
         * @brief Default constructor needed for initializing vectors etc.
         */
        explicit AFPacket() : m_payload(), m_buffer(nullptr), m_owner(false), m_type(PacketType::NONE) {}

        /**
         * @brief Constructor for packet stored in buffer
         * @param packet Pointer to start of packet data
         * @param size Packet size
         * @param type Format of packet stored in buffer
         * @throw std::bad_alloc
         */
        explicit AFPacket(const uint8_t* packet, std::size_t size, PacketType type = PacketType::WIRE);

        /**
         * @brief Constructor for packet stored in buffer
         * @param packet Pointer to start of packet data
         * @param size Packet size
         * @param owner Indicates if object should take ownership of the given packet buffer
         * or create its own copy of the packet data
         * @param type Format of packet stored in buffer
         * @throw std::bad_alloc
         */
        explicit AFPacket(const uint8_t* packet, std::size_t size, bool owner, PacketType type = PacketType::WIRE);

        /**
         * @throw std::bad_alloc
         */
        AFPacket(const AFPacket& packet);
        AFPacket(AFPacket&& packet) noexcept : m_payload(packet.m_payload),
                                               m_buffer(packet.m_buffer),
                                               m_owner(packet.m_owner),
                                               m_type(packet.m_type) { packet.m_buffer = nullptr; }

        friend void swap(AFPacket& packet1, AFPacket& packet2) noexcept {
            using std::swap;

            swap(packet1.m_buffer, packet2.m_buffer);
            swap(packet1.m_payload, packet2.m_payload);
            swap(packet1.m_owner, packet2.m_owner);
            swap(packet1.m_type, packet2.m_type);
        }

        /**
         * @brief Overload assignment operator by using swap idiom
         */
        AFPacket& operator=(AFPacket other) {
            swap(*this, other);
            return *this;
        }

        /**
         * @brief Get packet data
         */
        const MemView<uint8_t>& payload() const { return m_payload; }

        /**
         * @brief Get packet size
         */
        uint64_t size() const { return m_payload.count(); }

        /**
         * @brief Get type of packet
         */
        PacketType type() const { return m_type; }

        /**
         * @brief Destructor. Frees the packet data buffer
         */
        virtual ~AFPacket() { free(); }

    protected:
        MemView<uint8_t> m_payload;

    private:
        /**
         * @brief Free the packet data buffer
         */
        void free();

        uint8_t* m_buffer;
        bool m_owner;
        PacketType m_type;
    };
}
