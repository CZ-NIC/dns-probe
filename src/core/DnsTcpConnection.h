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
#include <limits>
#include <string>
#include <vector>
#include <iostream>
#include <memory>

#include <cstdint>
#include <cstring>
#include <arpa/inet.h> // in6_addr
#include <sys/socket.h> // AF_INET and AF_INET6
#include <netinet/tcp.h>

#include "utils/Time.h"
#include "TcpSegment.h"
#include "DnsRecord.h"

namespace DDP {

    /**
     * @brief TCP connection states
     */
    enum class TcpConnectionState : uint8_t
    {
        LISTEN,
        SYN,
        SYN_ACK,
        ESTABLISHED,
        FIN1,
        FIN2,
        FIN1_ACK,
        FIN1_FIN2,
        CLOSED
    };

    /**
     * @brief TCP connection side
     */
    enum TcpConnectionSide : uint8_t
    {
        CLIENT = 0,
        SERVER = 1
    };

    class DnsParser;

    /**
     * @brief This class handles given TCP connection
     */
    class DnsTcpConnection
    {
    public:
        static constexpr uint8_t BUFFER_LIMIT = 100;

        DnsTcpConnection() : m_hash(0),
                            m_isn(),
                            m_next_seq(),
                            m_fin(),
                            m_state(TcpConnectionState::LISTEN),
                            m_unparsed_msg(),
                            m_buffer_size(),
                            m_buffer_head(),
                            m_buffer_tail()
        {
            m_buffer_size[CLIENT] = 0;
            m_buffer_size[SERVER] = 0;
            m_buffer_head[CLIENT] = nullptr;
            m_buffer_head[SERVER] = nullptr;
            m_buffer_tail[CLIENT] = nullptr;
            m_buffer_tail[SERVER] = nullptr;
        }

        ~DnsTcpConnection(){}

        /**
         * Modified TCP finite state machine from RFC 793 page 23. State actions based on RFC 793
         * chapter 3.9 Event processing but slightly changed to fit modified state machine.
         * @brief Update TCP connection state based on new TCP segment in packet and export DNS messages if possible
         * @param record DNS record structure to fill
         * @param packet Object with packet data
         * @param header Pointer to start of TCP header
         * @param data Pointer to start of TCP segment data
         * @param parser DNS parser object for processing new DNS messages for export
         * @param records Pointer to vector of DNS records to export
         * @return TRUE if packet contains exactly 1 DNS message for immediate export, FALSE otherwise
         */
        bool update_connection(DnsRecord& record, const Packet& packet, const tcphdr* header,
                const MemView<uint8_t>& data, DnsParser& parser, std::vector<DnsRecord*>& records);

        /**
         * @brief Handle given TCP segment (export DNS messages and insert into reorder buffer if necesarry)
         * @param packet Object with packet data
         * @param data Pointer to start of TCP segment data
         * @param parser parser object for DNS message parsing
         * @param conn_side Side of TCP connection
         * @param record DNS record for current TCP segment
         * @param header Pointer to start of TCP header in given packet
         * @param records Pointer to vector of DNS records to export
         * @return TRUE if there are DNS messages for export, FALSE otherwise
         */
        bool process_segment(const Packet& packet, const MemView<uint8_t>& data, DnsParser* parser, 
                uint8_t conn_side, DnsRecord& record, const tcphdr* header, std::vector<DnsRecord*>* records);

        /**
         * @brief Clear reorder buffer for both sides of the connection
         */
        void clear_buffers();

        /**
         * @brief Check if either side of connection reached the limit of buffered packets
         * @return TRUE if either buffer reached the limit, FALSE otherwise
         */
        bool buffers_full() {
            return m_buffer_size[CLIENT] > BUFFER_LIMIT || m_buffer_size[SERVER] > BUFFER_LIMIT;
        }

        /**
         * @brief Fill DNS record with TCP connection's L3-4 parameters
         * @param dst Destination DNS record
         * @param src Source DNS record
         */
        void fill_record_L3_L4(DnsRecord& dst, DnsRecord& src) {
            dst.m_addr[CLIENT] = src.m_addr[CLIENT];
            dst.m_addr[SERVER] = src.m_addr[SERVER];
            dst.m_port[CLIENT] = src.m_port[CLIENT];
            dst.m_port[SERVER] = src.m_port[SERVER];
            dst.m_proto = src.m_proto;
            dst.m_addr_family = src.m_addr_family;
            dst.m_client_index = src.m_client_index;
            dst.m_ttl = src.m_ttl;
        }

        /**
         * @brief Set TCP connection hash
         * @param hash Hash for this TCP connection
         */
        void set_hash(uint32_t hash) {
            m_hash = hash;
        }

        /**
         * @return Returns TCP connection's hash
         */
        uint32_t hash() const
        {
            return m_hash;
        }

        /**
         * @brief Match packet to this TCP connection
         * @param m TCP hash of given packet
         * @param match_qname unused parameter, MUST be here because of TransactionTable interface
         * @return TRUE if packet belongs to this TCP connection, FALSE otherwise
         */
        bool match(DnsTcpConnection& m, bool match_qname [[maybe_unused]]) const
        {
            return m_hash == m.m_hash;
        }

        TcpConnectionState get_state()
        {
            return m_state;
        }

    private:
        uint32_t m_hash;
        uint32_t m_isn[2];
        uint32_t m_next_seq[2];
        bool m_fin[2];
        TcpConnectionState m_state;
        uint16_t m_unparsed_msg[2]; // bytes missing from last msg before first hole in buffer
        uint8_t m_buffer_size[2];
        TcpSegment* m_buffer_head[2];
        TcpSegment* m_buffer_tail[2];

        /**
         * @brief Insert TCP segment given in packet into given connection side's reorder buffer
         * @param packet Packet containing TCP segment for insertion to reorder buffer
         * @param segment View of TCP segment in the packet
         * @param conn_side Connection side
         * @param seq Sequence number of TCP segment
         * @param offset Offset to start of unparsed data in TCP segment
         * @throw std::bad_alloc From calling new TcpSegment
         * @return TRUE if first hole in reorder buffer was filled and buffer should be parsed,
         * FALSE otherwise
         */
        bool insert_segment(const Packet& packet, const MemView<uint8_t>& segment, uint8_t conn_side,
                            uint32_t seq, uint32_t offset);

        /**
         * @brief Remove first segment in reorder buffer of given TCP connection's side
         * @param conn_side Which side's buffer to remove from
         */
        void remove_head(uint8_t conn_side);
    };

}
