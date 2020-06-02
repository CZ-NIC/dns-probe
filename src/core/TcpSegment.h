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

#include <memory>
#include "platform/Packet.h"
#include "platform/Allocator.h"

namespace DDP {
    class TcpSegment;

    /**
     * @brief Linked list with TCP segments
     */
    struct TcpSegmentInfo
    {
        uint32_t seq_number;
        uint32_t segment_size;
        uint32_t offset;
        TcpSegment* next;
        TcpSegment* prev;
    };

    /**
     * @brief Class holding TCP segment data and information about its position in linked list
     */
    class TcpSegment {
        public:
        TcpSegment(TcpSegmentInfo& info, const Packet& packet, const MemView<uint8_t>& segment)
            : m_info(info), m_packet(packet), m_seg_offset(segment.ptr() - packet.payload().ptr()) {}

        /**
         * @throw std::bad_alloc()
         */
        void* operator new(size_t size) {
            void* p = Alloc::malloc(size);
            if (p == nullptr)
                throw std::bad_alloc();

            return p;
        }

        void operator delete(void* p) noexcept {
            Alloc::free(p);
        }

        /**
         * @brief Get TCP segment information
         */
        TcpSegmentInfo& info() { return m_info; }

        /**
         * @brief Get Packet
         */
        const Packet& packet() const { return m_packet; }

        /**
         * @brief Get packet size
         * @return Size of the whole packet
         */
        uint64_t size() const { return m_packet.size(); }

        /**
         * @brief Get TCP segment data
         */
        const MemView<uint8_t> data() const {
            return MemView<uint8_t>(m_packet.payload().ptr() + m_seg_offset, m_info.segment_size);
        }

        private:
        TcpSegmentInfo m_info;
        Packet m_packet;
        uint32_t m_seg_offset;
    };
}