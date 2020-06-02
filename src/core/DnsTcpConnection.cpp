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

#include "DnsTcpConnection.h"
#include "DnsParser.h"

bool DDP::DnsTcpConnection::update_connection(DnsRecord& record, const Packet& packet, const tcphdr* header, const MemView<uint8_t>& data,
                                              DnsParser& parser, std::vector<DnsRecord*>& records)
{
    uint8_t conn_side = (record.m_port[static_cast<uint8_t >(record.m_client_index)] == DnsParser::DNS_PORT) ? SERVER : CLIENT;
    uint32_t pkt_seq = ntohl(header->seq);
    uint32_t seg_len = data.count();
    bool ret = false;

    if (m_state == TcpConnectionState::LISTEN) {
        // to SYN
        // to CLOSED

        // RESET or ACK flags shouldn't happen at this stage
        if (header->rst || header->ack) {
            m_state = TcpConnectionState::CLOSED;
            return false;
        }

        // handle SYN packet
        if (header->syn){
            m_isn[conn_side] = pkt_seq;

            if (seg_len > 0) {
                ret = process_segment(packet, data, &parser, conn_side, record, header, &records);
                m_next_seq[conn_side] += 1;
            }
            else {
                m_next_seq[conn_side] = pkt_seq + 1;
            }

            m_state = TcpConnectionState::SYN;
        }
        else {
            // TODO TRY TO ESTABLISH IN THE MIDDLE OF CONNECTION???
            m_state = TcpConnectionState::CLOSED;
        }
        return false;
    }
    else if (m_state == TcpConnectionState::SYN) {
        // to SYN/ACK
        // to self
        // to CLOSED

        // Check correct ACK number
        if (header->ack) {
            if (ntohl(header->ack_seq) <= m_isn[conn_side ^ 1] ||
                ntohl(header->ack_seq) > m_next_seq[conn_side ^ 1]) {
                return false;
            }

            if (header->rst) {
                clear_buffers();
                m_state = TcpConnectionState::CLOSED;
                return false;
            }
        }

        // Handle RST flag
        if (header->rst) {
            return false;
        }

        // Handle segment data
        if (header->syn) {
            m_isn[conn_side] = pkt_seq;

            if (seg_len > 0) {
                ret = process_segment(packet, data, &parser, conn_side, record, header, &records);
                m_next_seq[conn_side] += 1;
            }
            else {
                m_next_seq[conn_side] = pkt_seq + 1;
            }

            if (header->ack) {
                m_state = TcpConnectionState::SYN_ACK;
            }
        }
        return ret;
    }
    // RFC 793 page 69 + sequence number overflow handling
    else if (((m_next_seq[conn_side] <= pkt_seq) ||
                    ((m_next_seq[conn_side] > pkt_seq) && (m_isn[conn_side] > pkt_seq))) ||
            ((seg_len > 0) && ((m_next_seq[conn_side] <= (pkt_seq + seg_len - 1)) ||
                    ((m_next_seq[conn_side] > (pkt_seq + seg_len)) && (m_isn[conn_side] > (pkt_seq + seg_len - 1)))))) {

        if (header->rst) {
            clear_buffers();
            m_state = TcpConnectionState::CLOSED;
            return false;
        }

        // Sequence number of this packet doesn't match next expected sequence number
        if (m_next_seq[conn_side] != pkt_seq) {
            // Don't queue empty ACKs into reorder buffer, it would see next data segment with the same
            // sequence number as previous empty ACK as duplicate segment
            if (seg_len == 0) {
                return false;
            }

            ret = process_segment(packet, data, &parser, conn_side, record, header, &records);
            return ret;
        }

        // SYN packets shouldn't happen at this stage
        if (header->syn && (m_state != TcpConnectionState::SYN_ACK)) {
            clear_buffers();
            m_state = TcpConnectionState::CLOSED;
            return false;
        }

        // All packets at this stage should have ACK flag set
        if (!header->ack) {
            return false;
        }

        // Handle specific connection states
        if (m_state == TcpConnectionState::SYN_ACK) {
            // to ESTABLISHED
            // to self
            // to CLOSED

            // simultaneous connection open
            if (header->syn && header->ack) {
                if (seg_len > 0) {
                    ret = process_segment(packet, data, &parser, conn_side, record, header, &records);
                    m_next_seq[conn_side] += 1;
                }
                else {
                    m_next_seq[conn_side] = pkt_seq + 1;
                }
                return ret;
            }

            // Received ACK to complete 3-way handshake
            if (ntohl(header->ack_seq) == m_next_seq[conn_side ^ 1]) {
                m_state = TcpConnectionState::ESTABLISHED;
            }

            // Received FIN to close connection
            if (header->fin) {
                m_state = TcpConnectionState::FIN1;
                m_fin[conn_side] = true;
            }

            // Handle segment data
            if (seg_len > 0) {
                ret = process_segment(packet, data, &parser, conn_side, record, header, &records);;
            }
            else if (header->fin) {
                m_next_seq[conn_side] = pkt_seq + 1;
            }

            return ret;
        } else if (m_state == TcpConnectionState::ESTABLISHED) {
            // to self
            // to FIN1
            // to CLOSED

            // Handle segment data
            if (seg_len > 0) {
                ret = process_segment(packet, data, &parser, conn_side, record, header, &records);;
            }

            // Check for FIN flag
            if (header->fin) {
                m_state = TcpConnectionState::FIN1;
                m_fin[conn_side] = true; // FIN flag received for this side of connection
                if (seg_len == 0) {
                    m_next_seq[conn_side] = pkt_seq + 1;
                }
            }

            if (seg_len == 0) { // Empty ACK packet
                return false;
            }
            return ret;
        } else if (m_state == TcpConnectionState::FIN1) {
            // to self
            // to FIN1_ACK
            // to FIN2
            // to FIN1_FIN2
            // to CLOSED

            // Only 1 side of connection can send data at this point
            if (m_fin[conn_side ^ 1]) {
                // Check for FIN flag
                if (header->fin) {
                    if (ntohl(header->ack_seq) == m_next_seq[conn_side ^ 1]) {
                        m_state = TcpConnectionState::FIN2;
                        m_fin[conn_side ^ 1] = false;
                    }
                    else {
                        m_state = TcpConnectionState::FIN1_FIN2;
                    }
                    m_fin[conn_side] = true;
                    if (seg_len == 0) {
                        m_next_seq[conn_side] = pkt_seq + 1;
                    }
                }
                else {
                    if (ntohl(header->ack_seq) == m_next_seq[conn_side ^ 1]) {
                        m_state = TcpConnectionState::FIN1_ACK;
                    }
                }

                // Handle segment data
                if (seg_len > 0) {
                    ret = process_segment(packet, data, &parser, conn_side, record, header, &records);
                }
            }

            return ret;
        } else if (m_state == TcpConnectionState::FIN1_ACK) {
            // to self
            // to FIN2
            // to CLOSED

            // Only 1 side of connection can send data at this point
            if (m_fin[conn_side ^ 1]) {
                // Check for FIN flag
                if (header->fin) {
                    m_state = TcpConnectionState::FIN2;
                    m_fin[conn_side] = true;
                    m_fin[conn_side ^ 1] = false;
                    if (seg_len == 0) {
                        m_next_seq[conn_side] = pkt_seq + 1;
                    }
                }

                // Handle segment data
                if (seg_len > 0) {
                    ret = process_segment(packet, data, &parser, conn_side, record, header, &records);;
                }
            }

            return ret;
        } else if (m_state == TcpConnectionState::FIN1_FIN2) {
            // to self
            // to FIN2
            // to CLOSED

            // Check for ACK of FIN
            if (ntohl(header->ack_seq) == m_next_seq[conn_side ^ 1]) {
                m_state = TcpConnectionState::FIN2;
                m_fin[conn_side ^ 1] = false;
            }

            return false;
        } else if (m_state == TcpConnectionState::FIN2) {
            // to self
            // to CLOSED

            // Check for ACK of FIN of other side of connection
            if (m_fin[conn_side ^ 1]) {
                if (ntohl(header->ack_seq) == m_next_seq[conn_side ^ 1]) {
                    m_fin[conn_side ^ 1] = false;
                    clear_buffers();
                    m_state = TcpConnectionState::CLOSED;
                }
            }

            return false;
        }
    }
    return false;
}

bool DDP::DnsTcpConnection::process_segment(const Packet& packet, const MemView<uint8_t>& segment, 
        DnsParser* parser, uint8_t conn_side, DnsRecord& record, const tcphdr* header, 
        std::vector<DnsRecord*>* records)
{
    uint32_t pkt_seq = ntohl(header->seq);
    uint32_t seg_len = segment.count();
    
    // seq == next_seq --> 
                            // export (1-x whole DNS msgs) OR 
                            // insert in reorder buffer (part of DNS msg) OR 
                            // both (1-x whole DNS msgs and one part of DNS msg)

    // seq > next_seq --> insert in reorder buffer
                            
    if (pkt_seq == m_next_seq[conn_side]) {
        // 1) buffer empty -> try to export, if unsuccessful then insert in reorder buffer
                            // a) 1 full DNS msg -> export normally, don't insert in reorder buffer

                            // b) part of 1 DNS msg -> insert in reorder buffer

                            // c) x full DNS msg -> export here, don't insert in reorder buffer
                            // d) x full DNS msg, part of 1 DNS msg -> export x here, insert in reorder buffer

        // 2) buffer not-empty -> insert in reorder buffer,
                                // a) first hole in reorder buffer filled, try to export
                                // b) another hole in reorder buffer filled, don't try to export

        // 1)
        if (m_buffer_head[conn_side] == nullptr) {
            if (seg_len < 2) {
                try {
                    insert_segment(packet, segment, conn_side, pkt_seq, 0);
                    m_unparsed_msg[conn_side] = 0;
                    m_next_seq[conn_side] = pkt_seq + seg_len;
                }
                catch (std::exception& e) {
                    Logger("DNSoverTCP").warning() << "Couldn't insert packet into reorder buffer";
                }
                return false;
            }
            uint16_t len = ntohs(*(reinterpret_cast<const uint16_t*>(header) + (header->doff * 2)));

            // 1a)
            if ((uint32_t)(len + 2) == seg_len) {
                record.m_dns_len = seg_len - 2;
                record.m_len = packet.size();
                try {
                    parser->parse_dns(segment.offset(2), record);
                }
                catch (NonDnsException& e) {}
                catch (std::exception& e) {
                    Logger("Parse error").debug() << e.what();
                    parser->export_invalid(packet);
                }
                m_next_seq[conn_side] = pkt_seq + seg_len;
                return true;
            }
            // 1b)
            else if ((uint32_t)(len + 2) > seg_len) {
                try {
                    insert_segment(packet, segment, conn_side, pkt_seq, 0);
                    m_unparsed_msg[conn_side] = (len + 2) - seg_len;
                    m_next_seq[conn_side] = pkt_seq + seg_len;
                }
                catch(std::exception& e) {
                    Logger("DNSoverTCP").warning() << "Couldn't insert packet into reorder buffer";
                }
                return false;
            }
            // 1c), 1d)
            else if ((uint32_t)(len + 2) < seg_len) {
                uint32_t seg_len_left = seg_len - 2;
                const uint8_t* data = segment.ptr();
                bool split = false;

                while (len <= seg_len_left) {
                    DnsRecord& msg = parser->get_empty();
                    records->push_back(&msg);
                    fill_record_L3_L4(msg, record);

                    try {
                        uint8_t* msg_buffer = parser->copy_to_buffer(data + 2, len, 0);
                        msg.m_dns_len = len;
                        msg.m_len = packet.size();
                        parser->parse_dns({msg_buffer, len}, msg);
                    }
                    catch (NonDnsException& e) {
                        records->pop_back();
                    }
                    catch (std::exception& e) {
                        Logger("Parse error").debug() << e.what();
                        records->pop_back();
                        parser->export_invalid(packet);
                    }

                    if (len == seg_len_left) {
                        break;
                    }
                    // 2-byte DNS msg length field split between 2 packets
                    else if (seg_len_left - len == 1) {
                        seg_len_left -= len;
                        data += len;
                        len = seg_len_left + 1;
                        split = true;
                        break;
                    }

                    seg_len_left = seg_len_left - len;
                    data += (len + 2);
                    len = ntohs(*(reinterpret_cast<const uint16_t*>(data)));
                    seg_len_left -= 2;
                }

                // 1d)
                if (len > seg_len_left) {
                    try {
                        // 2-byte DNS msg length field split between 2 packets
                        if (split) {
                            insert_segment(packet, segment, conn_side, pkt_seq, seg_len - seg_len_left);
                            m_unparsed_msg[conn_side] = 0;
                        }
                        else {
                            insert_segment(packet, segment, conn_side, pkt_seq, seg_len - (seg_len_left + 2));
                            m_unparsed_msg[conn_side] = len - seg_len_left;
                        }
                    }
                    catch (std::exception& e) {
                        Logger("DNSoverTCP").warning() << "Couldn't insert packet into reorder buffer";
                        return true;
                    }
                }

                m_next_seq[conn_side] = pkt_seq + seg_len;
                return true;
            }
        }
        // 2)
        else {
            bool filled_first;
            try {
                filled_first = insert_segment(packet, segment, conn_side, pkt_seq, 0);
            }
            catch (std::exception& e) {
                Logger("DNSoverTCP").warning() << "Couldn't insert packet into reorder buffer";
                return false;
            }

            // 2a)
            if (filled_first) {
                bool ret = true;
                bool split = false;
                std::size_t offset = 0;
                TcpSegment* next = m_buffer_head[conn_side];
                TcpSegment* msg_start = next;
                TcpSegmentInfo* next_seg = &next->info();
                const uint8_t* data = next->data().offset(next_seg->offset).ptr();
                uint32_t seg_len_left = next_seg->segment_size - next_seg->offset;
                uint16_t len, total_len, split_len = 0;
                if (seg_len_left == 1) { //2-byte DNS msg length field split between 2 packets
                    split_len = *data << 8;
                    total_len = len = seg_len_left + 1;
                    split = true;
                }
                else {
                    len = ntohs(*(reinterpret_cast<const uint16_t*>(data)));
                    total_len = len;
                    seg_len_left -= 2;
                    data += 2;
                }

                while (true) {
                    while (len <= seg_len_left) {
                        DnsRecord &msg = parser->get_empty();
                        records->push_back(&msg);
                        fill_record_L3_L4(msg, record);

                        const uint8_t *msg_buffer;
                        try {
                            if (msg_start != next) {
                                TcpSegment* tmp = msg_start;

                                while (tmp != next) {
                                    const uint8_t* tmp_data = tmp->data().offset(tmp->info().offset).ptr();
                                    TcpSegmentInfo* tmp_seg = &tmp->info();
                                    if (tmp == msg_start) {
                                        if (tmp_seg->segment_size - tmp_seg->offset > 1) {
                                            msg_buffer = parser->copy_to_buffer(tmp_data + 2,
                                                                                tmp_seg->segment_size - tmp_seg->offset - 2,
                                                                                offset);
                                            offset += ((tmp_seg->segment_size - tmp_seg->offset) - 2);
                                        }
                                    }
                                    // 2-byte DNS msg length field split between 2 packets
                                    else if ((tmp == msg_start->info().next) &&
                                            (msg_start->info().segment_size - msg_start->info().offset == 1)) {
                                        msg_buffer = parser->copy_to_buffer(tmp_data + 1,
                                                                            tmp_seg->segment_size - tmp_seg->offset - 1,
                                                                            offset);
                                        offset += ((tmp_seg->segment_size - tmp_seg->offset) - 1);
                                    }
                                    else {
                                        msg_buffer = parser->copy_to_buffer(tmp_data,
                                                                            tmp_seg->segment_size - tmp_seg->offset,
                                                                            offset);
                                        offset += tmp_seg->segment_size - tmp_seg->offset;
                                    }
                                    msg.m_len += tmp->size();
                                    tmp = tmp_seg->next;
                                }

                                data = tmp->data().offset(tmp->info().offset).ptr();
                                msg_buffer = parser->copy_to_buffer(data, len, offset);
                                msg.m_len += tmp->size();
                            }
                            else {
                                msg_buffer = data;
                                msg.m_len = next->size();
                            }

                            msg.m_dns_len = total_len;
                            parser->parse_dns({msg_buffer, total_len}, msg);
                        }
                        catch (NonDnsException& e) {
                            records->pop_back();
                        }
                        catch (std::exception& e) {
                            Logger("Parse error").debug() << e.what();
                            records->pop_back();
                            if (parser->is_export_invalid()) {
                                TcpSegment* tmp = msg_start;
                                while (tmp != next) {
                                    parser->export_invalid(tmp->packet());
                                    tmp = tmp->info().next;
                                }
                                parser->export_invalid(tmp->packet());
                            }
                        }

                        if (len == seg_len_left) {
                            break;
                        }
                        // 2-byte DNS msg length field split between 2 packets
                        else if (seg_len_left - len == 1) {
                            seg_len_left -= len;
                            data += len;
                            total_len = len = seg_len_left + 1;
                            split_len = *data << 8;
                            msg_start = next;
                            offset = 0;
                            split = true;
                            break;
                        }

                        seg_len_left = seg_len_left - len;
                        data += len;
                        total_len = len = ntohs(*(reinterpret_cast<const uint16_t*>(data)));
                        msg_start = next;
                        seg_len_left -= 2;
                        data += 2;
                        offset = 0;
                    }

                    // 1) seg_len_left == len  -> clear head,
                                                // a) if next != nullptr ->
                                                    // x) seq == next_seq -> parse, continue

                                                    // y) seq != next_seq -> set ret, break
                                                // b) else -> set ret, break

                    // 2) seg_len_left == 1 (2-byte DNS msg length split between 2 packets) ->
                                                // a) if next != nullptr ->
                                                    // x) seq == next_seq -> read DNS msg length, parse, continue

                                                    // y) seq != next_seq -> set offset, set unparsed, set ret, break
                                                // b) else -> set offset, set unparsed, set ret, break

                    // 3) len > seg_len_left ->
                                                // a) if next != nullptr ->
                                                    // x) seq == next_seq -> parse, continue

                                                    // y) seq != next_seq -> set offset, set unparsed, set ret, break
                                                // b) else -> set offset, set unparsed, set ret, break

                    // 1)
                    if (len == seg_len_left) {
                        // 1ax)
                        if ((next_seg->next != nullptr) &&
                            ((next_seg->seq_number + next_seg->segment_size) == next_seg->next->info().seq_number)) {
                            next = msg_start = next_seg->next;
                            next_seg = &next->info();
                            data = next->data().offset(next_seg->offset).ptr();
                            seg_len_left = next_seg->segment_size - next_seg->offset;
                            total_len = len = ntohs(*(reinterpret_cast<const uint16_t*>(data)));
                            seg_len_left -= 2;
                            data += 2;
                            offset = 0;
                            continue;
                        }

                        // 1ay, 1b)
                        m_next_seq[conn_side] = next_seg->seq_number + next_seg->segment_size;
                        while(next != m_buffer_head[conn_side]) {
                            remove_head(conn_side);
                        }
                        remove_head(conn_side); // remove next itself from head of buffer
                        if (records->empty())
                            ret = false;

                        break;
                    }
                    // 2)
                    else if (split) {
                        next_seg->offset = next_seg->segment_size - seg_len_left;
                        // 2ax)
                        if ((next_seg->next != nullptr) &&
                            ((next_seg->seq_number + next_seg->segment_size) == next_seg->next->info().seq_number)) {
                            next = next_seg->next;
                            next_seg = &next->info();
                            data = next->data().offset(next_seg->offset).ptr();
                            split_len = split_len | *static_cast<const uint8_t*>(data);
                            total_len = len = split_len;
                            seg_len_left = next_seg->segment_size - next_seg->offset - 1;
                            data += 1;
                            split = false;
                            continue;
                        }

                        // 2ay), 2b)
                        m_unparsed_msg[conn_side] = 0;
                        m_next_seq[conn_side] = next_seg->seq_number + next_seg->segment_size;
                        split = false;
                        while(msg_start != m_buffer_head[conn_side]) {
                            remove_head(conn_side);
                        }
                        if (records->empty())
                            ret = false;

                        break;
                    }
                    // 3)
                    else {
                        // 3ax)
                        if (next_seg->segment_size == seg_len_left || next_seg->segment_size == seg_len_left + 1) {
                            next_seg->offset = 0;
                        }
                        else {
                            next_seg->offset = next_seg->segment_size - (seg_len_left + 2);
                        }

                        if ((next_seg->next != nullptr) &&
                            ((next_seg->seq_number + next_seg->segment_size) == next_seg->next->info().seq_number)) {
                            next = next_seg->next;
                            next_seg = &next->info();
                            data = next->data().offset(next_seg->offset).ptr();
                            len = len - seg_len_left;
                            seg_len_left = next_seg->segment_size - next_seg->offset;
                            continue;
                        }

                        // 3ay, 3b)
                        m_unparsed_msg[conn_side] = len - seg_len_left;
                        m_next_seq[conn_side] = next_seg->seq_number + next_seg->segment_size;
                        while (msg_start != m_buffer_head[conn_side]) {
                            remove_head(conn_side);
                        }
                        if (records->empty())
                            ret = false;

                        break;
                    }
                }

                return ret;
            }

            // 2b)
            m_next_seq[conn_side] = pkt_seq + seg_len;
        }
    }
    else {
        try {
            insert_segment(packet, segment, conn_side, pkt_seq, 0);
        }
        catch (std::exception& e) {
            Logger("DNSoverTCP").warning() << "Couldn't insert packet into reorder buffer";
        }
        return false;
    }

    return false;
}

void DDP::DnsTcpConnection::clear_buffers()
{
    TcpSegment *head, *tmp;

    for (int i = 0; i < 2; i++) {
        head = m_buffer_head[i];

        while (head != nullptr) {
            tmp = head;
            head = head->info().next;
            delete tmp;
        }
    }

    m_buffer_size[CLIENT] = 0;
    m_buffer_size[SERVER] = 0;
    m_buffer_head[CLIENT] = nullptr;
    m_buffer_head[SERVER] = nullptr;
    m_buffer_tail[CLIENT] = nullptr;
    m_buffer_tail[SERVER] = nullptr;
}

bool DDP::DnsTcpConnection::insert_segment(const Packet& packet, const MemView<uint8_t>& segment, uint8_t conn_side,
                                           uint32_t seq, uint32_t offset)
{
    bool ret = false;
    TcpSegmentInfo seg_info;
    seg_info.seq_number = seq;
    seg_info.segment_size = segment.count();
    seg_info.offset = offset;
    TcpSegmentInfo tail;
    if (m_buffer_tail[conn_side] != nullptr) {
        tail = m_buffer_tail[conn_side]->info();
    }

    // Empty buffer, just insert segment
    if (m_buffer_tail[conn_side] == nullptr) {
        seg_info.next = nullptr;
        seg_info.prev = nullptr;
        m_buffer_head[conn_side] = m_buffer_tail[conn_side] = new TcpSegment(seg_info, packet, segment);
    }
    // Same sequence number as tail segment, drop packet
    else if (tail.seq_number == seq) {
        return ret;
    }
    // Segment is the new tail
    else if ((tail.seq_number < seq) || ((tail.seq_number > m_isn[conn_side]) && (seq < m_isn[conn_side]))) {
        seg_info.next = nullptr;
        seg_info.prev = m_buffer_tail[conn_side];
        m_buffer_tail[conn_side]->info().next = new TcpSegment(seg_info, packet, segment);
        m_buffer_tail[conn_side] = m_buffer_tail[conn_side]->info().next;
        if ((seq == m_next_seq[conn_side]) && (seg_info.segment_size >= m_unparsed_msg[conn_side])) {
            ret = true;
        }
        else if (seq == m_next_seq[conn_side]) {
            m_unparsed_msg[conn_side] = m_unparsed_msg[conn_side] - seg_info.segment_size;
        }
    }
    // Segment belongs somewhere inside the buffer before the tail
    else {
        TcpSegment* tmp = m_buffer_head[conn_side];
        TcpSegmentInfo* tmp_info = &tmp->info();

        while ((tmp_info->seq_number <= seq) || ((tmp_info->seq_number > m_isn[conn_side]) && (seq < m_isn[conn_side]))) {
            // Segment with this sequence number already in buffer, drop packet
            if (tmp_info->seq_number == seq)
                return ret;
            
            tmp = tmp_info->next;
            tmp_info = &tmp->info();
        }

        seg_info.prev = tmp_info->prev;
        seg_info.next = tmp;
        tmp_info->prev = new TcpSegment(seg_info, packet, segment);

        if (seg_info.prev == nullptr) {
            m_buffer_head[conn_side] = tmp_info->prev;
        }
        else {
            seg_info.prev->info().next = tmp_info->prev;
        }

        if (seq == m_next_seq[conn_side]) {
            ret = true;
        }
    }

    m_buffer_size[conn_side]++;
    return ret;
}

void DDP::DnsTcpConnection::remove_head(uint8_t conn_side)
{
    // Check if buffer is empty
    if (m_buffer_head[conn_side] == nullptr)
        return;

    TcpSegment* temp = m_buffer_head[conn_side];
    if (m_buffer_head[conn_side]->info().next == nullptr) {
        // Buffer is now empty after head is removed
        m_buffer_head[conn_side] = nullptr;
        m_buffer_tail[conn_side] = nullptr;
    }
    else {
        // Buffer isn't empty after head is removed
        m_buffer_head[conn_side] = m_buffer_head[conn_side]->info().next;
        m_buffer_head[conn_side]->info().prev = nullptr;
    }
    m_buffer_size[conn_side]--;
    delete temp;
}
