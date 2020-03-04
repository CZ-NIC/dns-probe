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

#include <exception>
#include <cstring>

#include "utils/MemView.h"

#include <rte_mbuf.h>
#include <rte_malloc.h>

namespace DDP {
    /**
     * Class representing network packet read from DPDK interface.
     */
    class DPDKPacket
    {
    public:
        /**
         * Constructor.
         */
        explicit DPDKPacket() : m_payload(),
                                m_used_mbuf(false),
                                m_mbuf(nullptr) {}

        /**
         * Creates DDP::DPDKPacket from DPDK mbuf.
         * @param mbuf Mbuf used for initialisation od DDP::DPDKPacket.
         */
        explicit DPDKPacket(rte_mbuf* mbuf);

        /**
         * Copy constructor.
         * @param packet Copied object.
         */
        DPDKPacket(const DPDKPacket& packet);

        /**
         * Move constructor.
         * @param packet Moved object.
         */
        DPDKPacket(DPDKPacket&& packet) noexcept : m_payload(packet.m_payload),
                                                   m_used_mbuf(packet.m_used_mbuf),
                                                   m_mbuf(packet.m_mbuf) { packet.m_buffer = nullptr; }

        /**
         * Creates DDP::DPDKPacket from DDP::MemView.
         * @param data Memview used for initialisation od the DDP:DDPKPacket.
         */
        DPDKPacket(const MemView<uint8_t>& data);

        /**
         * Swap contents of two DDP:DPDKPackets.
         * @param packet1 First swapped packet.
         * @param packet2 Second swapped packet.
         */
        friend void swap(DPDKPacket& packet1, DPDKPacket& packet2) noexcept
        {
            using std::swap;

            swap(packet1.m_used_mbuf, packet2.m_used_mbuf);
            swap(packet1.m_buffer, packet2.m_buffer);
            swap(packet1.m_payload, packet2.m_payload);
        }

        /**
         * Assign other packet into current memory space. Effectively creates copy od provided packet.
         * @param other Assigned packet.
         * @return Reference to copied packet.
         */
        DPDKPacket& operator=(DPDKPacket other)
        {
            swap(*this, other);
            return *this;
        }

        /**
         * Access underlying mbuf.
         * @return Pointer to underlying mbuf.
         */
        rte_mbuf* mbuf() const { return m_mbuf; }

        /**
         * Identify if underlying space for packet is covered by mbuf or not.
         * @return True if instance of DDP::DPDKPacket using mbuf otherwise false.
         */
        bool used_mbuf() const { return m_used_mbuf; }

        /**
         * Allows access payload of given packet.
         * @return Reference to DDP::MemView containing data of holding packet.
         */
        const MemView<uint8_t>& payload() const { return m_payload; }

        /**
         * Size of saved packet in bytes.
         * @return Size of saved packet in bytes.
         */
        uint64_t size() const { return m_payload.count(); }

        /**
         * Destructor.
         */
        virtual ~DPDKPacket() { free(); }

    protected:
        MemView<uint8_t> m_payload; //!< Unified view on saved packet.

    private:
        /**
         * Deallocate space used by saved packet.
         */
        void free();

        bool m_used_mbuf; //!< True if instance of DDP::DPDKPacket using mbuf otherwise false.
        union
        {
            rte_mbuf* m_mbuf; //!< Pointer to associated mbuf.
            uint8_t* m_buffer; //!< Pointer to allocated space for packet.
        };
    };
}