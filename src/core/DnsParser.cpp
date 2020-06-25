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
#include <cstring>

#include <cstdint>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "utils/Logger.h"
#include "DnsParser.h"

DDP::DnsParser::DnsParser(Config& cfg, unsigned process_id, DDP::Mempool<DDP::DnsRecord> &record_mempool,
                          DDP::Mempool<DDP::DnsTcpConnection> &tcp_mempool, Statistics& stats) :
        m_record_mempool(record_mempool),
        m_tcp_mempool(tcp_mempool),
        m_edns_mempool(EDNS_MEMPOOL_ITEM_SIZE, cfg.tt_size.value() / 10),
        m_tcp_table(cfg.tcp_ct_size, cfg.tcp_ct_timeout, false),
        m_msg_buffer(reinterpret_cast<uint8_t*>(Alloc::malloc(DNS_MSG_BUFFER_SIZE)), Alloc::free),
        m_raw_pcap(cfg.raw_pcap),
        m_export_invalid(cfg.pcap_export.value() == PcapExportCfg::INVALID),
        m_pcap_inv(cfg, cfg.pcap_export.value() == PcapExportCfg::INVALID, process_id),
        m_processed_packet{nullptr},
        m_dns_ports(cfg.dns_ports),
        m_stats(stats)
{
    if (!m_msg_buffer)
        throw DnsParserConstuctor("Message buffer allocation failed");
}

void DDP::DnsParser::parse_dns_header(const DDP::MemView<uint8_t>& pkt, DDP::DnsRecord& record)
{
    if (pkt.count() < DNS_HEADER_SIZE) {
        put_back_record(record);
        throw DnsParseException("Packet is too short. Probably missing part of DNS header.");
    }

    // Get DNS ID
    record.m_id = ntohs(*reinterpret_cast<const uint16_t*>(pkt.ptr()));

    // Parse two flag bytes
    auto flags = pkt.ptr() + 2;
    auto qr = static_cast<uint8_t>(*flags & DNS_HEADER_QR);

    if (!qr) {
        record.m_request = true;
    }
    else {
        record.m_response = true;
    }

    record.m_opcode = (*flags & DNS_HEADER_OPCODE) >> DNS_HEADER_OPCODE_SHIFT;
    record.m_aa = *flags & DNS_HEADER_AA;
    record.m_tc = *flags & DNS_HEADER_TC;
    record.m_rd = *flags & DNS_HEADER_RD;

    flags += 1;
    record.m_ra = *flags & DNS_HEADER_RA;
    record.m_z = *flags & DNS_HEADER_Z;
    record.m_ad = *flags & DNS_HEADER_AD;
    record.m_cd = *flags & DNS_HEADER_CD;
    record.m_rcode = *flags & DNS_HEADER_RCODE;

    // Get section's RR counters
    record.m_qdcount = ntohs(*(reinterpret_cast<const uint16_t*>(pkt.ptr()) + 2));
    record.m_ancount = ntohs(*(reinterpret_cast<const uint16_t*>(pkt.ptr()) + 3));
    record.m_nscount = ntohs(*(reinterpret_cast<const uint16_t*>(pkt.ptr()) + 4));
    record.m_arcount = ntohs(*(reinterpret_cast<const uint16_t*>(pkt.ptr()) + 5));
}

DDP::MemView<uint8_t> DDP::DnsParser::parse_dns_question(const DDP::MemView<uint8_t>& question, DDP::DnsRecord& record)
{
    if (question.count() < DNS_MIN_QUESTION_SIZE) {
        put_back_record(record);
        throw DnsParseException("Packet is too short. Probably missing part of DNS question.");
    }

    auto qname = reinterpret_cast<const char*>(question.ptr());
    auto qname_len = strnlen(qname, question.count());
    if(qname_len == question.count() || qname_len > DNS_MAX_QNAME_SIZE) {
        put_back_record(record);
        throw DnsParseException("Invalid DNS question.");
    }

    if(qname_len) {
        std::memcpy(record.m_qname, qname, qname_len);

        auto label_len = static_cast<uint8_t>(*qname);
        auto pos = static_cast<uint64_t>(label_len + 1);
        while(label_len != 0) {
            if (label_len > DNS_MAX_LABEL_SIZE || pos > qname_len) {
                put_back_record(record);
                throw DnsParseException("Invalid DNS question.");
            }

            label_len = record.m_qname[pos];
            pos += label_len + 1;
        }

        qname += qname_len + 1;
    }
    else {
        qname++;
    }

    // Get QTYPE and QCLASS fields
    record.m_qtype = ntohs(*reinterpret_cast<const uint16_t*>(qname));
    record.m_qclass = ntohs(*reinterpret_cast<const uint16_t*>(qname + 2));

    return question.offset(qname_len + 1 + DNS_QTYPE_QCLASS_SIZE);
}

void DDP::DnsParser::parse_edns(const DDP::MemView<uint8_t>& pkt, DDP::DnsRecord& record)
{
    if (!pkt.count()) {
        return;
    }

    std::size_t min_size = DNS_MIN_QUESTION_SIZE * (record.m_qdcount - 1) + DNS_MIN_RR_SIZE * \
            (record.m_ancount + record.m_nscount + record.m_arcount);

    if (pkt.count() < min_size) {
        put_back_record(record);
        throw DnsParseException("Packet is too short. Probably missing part of DNS message.");
    }

    auto ptr = pkt.ptr();
    auto pkt_end = pkt.ptr() + pkt.count();

    // Parse Question section
    if (record.m_qdcount > 1) {
        for (int i = 0; i < (record.m_qdcount - 1); i++) {
            if (pkt_end - ptr < DNS_MIN_QUESTION_SIZE) {
                put_back_record(record);
                throw DnsParseException("Invalid RR record");
            }

            ptr = parse_rr(ptr, pkt_end, record, DNSSectionType::QUESTION);

            if (ptr == nullptr) {
                put_back_record(record);
                throw DnsParseException("Invalid RR record");
            }
        }
    }

    // Parse Answer section
    for (unsigned j = 0; j < record.m_ancount; j++) {
        if (pkt_end - ptr < DNS_MIN_RR_SIZE) {
            put_back_record(record);
            throw DnsParseException("Invalid RR record");
        }

        if (record.m_response && j + 1 == record.m_ancount) {
            ptr = parse_rr(ptr, pkt_end, record, DNSSectionType::ANSWER);
        }
        else {
            ptr = parse_rr(ptr, pkt_end, record, DNSSectionType::OTHER);
        }

        if (ptr == nullptr) {
            put_back_record(record);
            throw DnsParseException("Invalid RR record");
        }
    }

    // Parse Authority records section
    for (int k = 0; k < record.m_nscount; k++) {
        if (pkt_end - ptr < DNS_MIN_RR_SIZE) {
            put_back_record(record);
            throw DnsParseException("Invalid RR record");
        }

        ptr = parse_rr(ptr, pkt_end, record, DNSSectionType::OTHER);

        if (ptr == nullptr) {
            put_back_record(record);
            throw DnsParseException("Invalid RR record");
        }
    }

    // Parse Additional records section and try to find and parse OPT RR with EDNS information
    for (int l = 0; l < record.m_arcount; l++) {
        if (pkt_end - ptr < DNS_MIN_RR_SIZE) {
            put_back_record(record);
            throw DnsParseException("Invalid RR record");
        }

        ptr = parse_rr(ptr, pkt_end, record, DNSSectionType::AR);

        if (ptr == nullptr) {
            put_back_record(record);
            throw DnsParseException("Invalid RR record");
        }
    }
}

const uint8_t* DDP::DnsParser::parse_rr(const uint8_t* ptr, const uint8_t* pkt_end, DDP::DnsRecord& record, DNSSectionType section)
{
    // Found OPT RR with EDNS information
    if (section == DNSSectionType::AR && *ptr == '\0') {
        ptr += 1;
        uint16_t rr_type = ntohs(*reinterpret_cast<const uint16_t*>(ptr));
        if (rr_type != DNS_EDNS_RR_TYPE) {
            ptr += 8;
            uint16_t rdata_len = ntohs(*reinterpret_cast<const uint16_t*>(ptr));
            if (rdata_len > pkt_end - ptr - 2)
                return nullptr;

            ptr += (2 + rdata_len);
            return ptr;
        }

        ptr += 2;
        record.m_ednsUDP = ntohs(*reinterpret_cast<const uint16_t*>(ptr));
        ptr += 3;
        record.m_ednsVersion = *ptr;
        ptr += 1;
        record.m_ednsDO = *ptr & DNS_EDNS_DO;

        ptr += 2;
        uint16_t rdata_len = ntohs(*reinterpret_cast<const uint16_t*>(ptr));
        ptr += 2;
        if (rdata_len > pkt_end - ptr)
            return nullptr;

        if (rdata_len != 0) {
            try {
                if (record.m_request) {
                    record.m_req_ednsRdata = static_cast<uint8_t*>(m_edns_mempool.get(rdata_len));
                    std::memcpy(record.m_req_ednsRdata, ptr, rdata_len);
                    record.m_req_ednsRdata_size = rdata_len;
                }
                else {
                    record.m_resp_ednsRdata = static_cast<uint8_t*>(m_edns_mempool.get(rdata_len));
                    std::memcpy(record.m_resp_ednsRdata, ptr, rdata_len);
                    record.m_resp_ednsRdata_size = rdata_len;
                }
            }
            catch (std::exception& e) {
                Logger("EDNS").warning() << "Couldn't allocate memory for EDNS record";
                return nullptr;
            }
        }
        ptr += rdata_len;
        return ptr;
    }

    // Parse non-OPT Resource Record
    uint16_t dname_size = 0;
    while (*ptr != '\0') {
        uint8_t label_len = *ptr;
        dname_size += label_len + 1;
        if ((label_len & DNS_LABEL_PTR) == DNS_LABEL_PTR) {
            ptr += 1;
            break;
        }
        else if (label_len > DNS_MAX_LABEL_SIZE || dname_size > DNS_MAX_QNAME_SIZE || label_len >= pkt_end - ptr - 1) {
            return nullptr;
        }
        else {
            ptr += (label_len + 1);
        }
    }

    if (section == DNSSectionType::QUESTION) {
        ptr += (1 + DNS_QTYPE_QCLASS_SIZE);
    }
    else {
        if (section == DNSSectionType::ANSWER) {
            ptr +=1;
            uint16_t type = ntohs(*reinterpret_cast<const uint16_t*>(ptr));
            if (type == DNS_TYPE_SOA) {
                record.m_last_soa = true;
            }
            ptr += DNS_RR_FIELDS_SKIP;
        }
        else {
            ptr += (1 + DNS_RR_FIELDS_SKIP);
        }
        uint16_t rdata_len = ntohs(*reinterpret_cast<const uint16_t*>(ptr));
        if (rdata_len > pkt_end - ptr - 2)
            return nullptr;
        ptr += (2 + rdata_len);
    }

    return ptr;
}

DDP::MemView<uint8_t> DDP::DnsParser::parse_l2(const DDP::MemView<uint8_t>& pkt, DDP::DnsRecord& record)
{
    // Check if packet is long enough to contain valid ethernet header
    if(pkt.count() < sizeof(ether_header)) {
        put_back_record(record);
        throw DnsParseException("Cannot skip ethernet header packet is too short.");
    }

    auto eth_header = reinterpret_cast<const ether_header*>(pkt.ptr());
    if (!(eth_header->ether_type & ETHER_TYPE_IPV4 || eth_header->ether_type & ETHER_TYPE_IPV6)) {
        put_back_record(record);
        throw NonDnsException("L3 layer doesn't contain IPv4/IPv6 header.");
    }

    return pkt.offset(sizeof(ether_header));
}

DDP::MemView<uint8_t> DDP::DnsParser::parse_l3(const DDP::MemView<uint8_t>& pkt, DDP::DnsRecord& record)
{
    // Check if first byte of L3 header exists
    if(!pkt.count()) {
        put_back_record(record);
        throw DnsParseException("Packet is too short (missing IP header)");
    }
    // Attempt to determine IP version
    // First nibble in IP header contains version
    auto ip_bits = *pkt.ptr() >> 4;

    if(ip_bits == IP_VERSION_4) {
        return parse_ipv4(pkt, record);
    }
    else if(ip_bits == IP_VERSION_6) {
        return parse_ipv6(pkt, record);
    }
    else {
        put_back_record(record);
        throw NonDnsException("L3 layer doesn't contain IPv4/IPv6 header.");
    }
}

DDP::MemView<uint8_t> DDP::DnsParser::parse_ipv4(const DDP::MemView<uint8_t>& pkt, DDP::DnsRecord& record)
{
    auto end = sizeof(iphdr);
    if(end > pkt.count()) {
        put_back_record(record);
        throw DnsParseException("Packet is too short. Probably missing part of IPv4 header.");
    }

    auto ipv4_header = reinterpret_cast<const iphdr*>(pkt.ptr());

    if(std::memcmp(&(ipv4_header->saddr), &(ipv4_header->daddr), IPV4_ADDRLEN) > 0) {
        std::memcpy(&(record.m_addr[0]), &(ipv4_header->daddr), IPV4_ADDRLEN);
        std::memcpy(&(record.m_addr[1]), &(ipv4_header->saddr), IPV4_ADDRLEN);
        // Indicate location of src addr
        record.m_client_index = DnsRecord::ClientIndex::CLIENT_HIGH;
    }
    else {
        std::memcpy(&(record.m_addr[0]), &(ipv4_header->saddr), IPV4_ADDRLEN);
        std::memcpy(&(record.m_addr[1]), &(ipv4_header->daddr), IPV4_ADDRLEN);
        record.m_client_index = DnsRecord::ClientIndex::CLIENT_LOW;
    }

    record.m_addr_family = DnsRecord::AddrFamily::IP4;
    record.m_ttl = ipv4_header->ttl;
    switch (ipv4_header->protocol) {
        case static_cast<uint8_t>(DDP::DnsRecord::Proto::TCP):
            record.m_proto = DDP::DnsRecord::Proto::TCP;
            break;
        case static_cast<uint8_t>(DDP::DnsRecord::Proto::UDP):
            record.m_proto = DDP::DnsRecord::Proto::UDP;
            break;
        default:
            put_back_record(record);
            throw NonDnsException("Unsupported L4 layer.");
    }

    if (ntohs(ipv4_header->tot_len) > pkt.count()) {
        put_back_record(record);
        throw DnsParseException("Packet is shorter than IPv4 header claims.");
    }

    return MemView<uint8_t>(pkt.offset(end).ptr(), ntohs(ipv4_header->tot_len) - end);
}

DDP::MemView<uint8_t> DDP::DnsParser::parse_ipv6(const DDP::MemView<uint8_t>& pkt, DDP::DnsRecord& record)
{
    auto end = sizeof(ip6_hdr);
    if(end > pkt.count()) {
        put_back_record(record);
        throw DnsParseException("Packet is too short. Probably missing part of IPv6 header.");
    }

    auto ipv6_header = reinterpret_cast<const ip6_hdr*>(pkt.ptr());

    if(std::memcmp(&ipv6_header->ip6_src, &ipv6_header->ip6_dst, IPV6_ADDRLEN) > 0) {
        std::memcpy(&(record.m_addr[0]), &ipv6_header->ip6_dst, IPV6_ADDRLEN);
        std::memcpy(&(record.m_addr[1]), &ipv6_header->ip6_src, IPV6_ADDRLEN);
        record.m_client_index = DnsRecord::ClientIndex::CLIENT_HIGH;
    }
    else {
        std::memcpy(&(record.m_addr[0]), &ipv6_header->ip6_src, IPV6_ADDRLEN);
        std::memcpy(&(record.m_addr[1]), &ipv6_header->ip6_dst, IPV6_ADDRLEN);
        record.m_client_index = DnsRecord::ClientIndex::CLIENT_LOW;
    }

    record.m_addr_family = DnsRecord::AddrFamily::IP6;
    record.m_ttl = ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim;
    // TODO: Add support for IPv6 next header
    switch (ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
        case static_cast<uint8_t>(DDP::DnsRecord::Proto::TCP):
            record.m_proto = DDP::DnsRecord::Proto::TCP;
            break;
        case static_cast<uint8_t>(DDP::DnsRecord::Proto::UDP):
            record.m_proto = DDP::DnsRecord::Proto::UDP;
            break;
        default:
            put_back_record(record);
            throw NonDnsException("Unsupported L4 layer.");
    }

    if ((ntohs(ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_plen) + end) > pkt.count()) {
        put_back_record(record);
        throw DnsParseException("Packet is shorter than IPv6 header claims");
    }

    return MemView<uint8_t>(pkt.offset(end).ptr(), ntohs(ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_plen));
}

DDP::MemView<uint8_t> DDP::DnsParser::parse_l4_udp(const DDP::MemView<uint8_t>& pkt, DDP::DnsRecord& record)
{
    auto end = sizeof(udphdr);
    if(end > pkt.count()) {
        put_back_record(record);
        throw DnsParseException("Packet is too short. Probably missing part of UDP header.");
    }

    auto udp_header = reinterpret_cast<const udphdr*>(pkt.ptr());

    auto src_port = ntohs(udp_header->source);
    auto dst_port = ntohs(udp_header->dest);

    bool is_dns = false;
    for (auto& dns_port : m_dns_ports) {
        if (src_port == dns_port || dst_port == dns_port) {
            is_dns = true;
            break;
        }
    }

    if (!is_dns) {
        put_back_record(record);
        throw NonDnsException("Packet doesn't contain DNS UDP port.");
    }

    record.m_port[static_cast<int>(record.m_client_index)] = src_port;
    record.m_port[!static_cast<int>(record.m_client_index)] = dst_port;

    record.m_udp_sum = ntohs(udp_header->check);
    record.m_dns_len = pkt.count() - end;

    return pkt.offset(end);
}

bool DDP::DnsParser::parse_l4_tcp(const DDP::MemView<uint8_t>& pkt, DDP::DnsRecord& record, std::vector<DnsRecord*>& records)
{
    auto end = sizeof(tcphdr);
    if(end > pkt.count()) {
        put_back_record(record);
        throw DnsParseException("Packet is too short. Probably missing part of TCP header.");
    }

    auto tcp_header = reinterpret_cast<const tcphdr*>(pkt.ptr());

    end = (tcp_header->doff * 4);
    if (end > pkt.count()) {
        put_back_record(record);
        throw DnsParseException("Packet is too short. Probably missing part of TCP header.");
    }

    auto src_port = ntohs(tcp_header->source);
    auto dst_port = ntohs(tcp_header->dest);

    bool is_dns = false;
    for (auto& dns_port : m_dns_ports) {
        if (src_port == dns_port || dst_port == dns_port) {
            is_dns = true;
            break;
        }
    }

    if (!is_dns) {
        put_back_record(record);
        throw NonDnsException("Packet doesn't contain DNS TCP port.");
    }

    record.m_port[static_cast<int>(record.m_client_index)] = src_port;
    record.m_port[!static_cast<int>(record.m_client_index)] = dst_port;

    DnsTcpConnection* connection = nullptr;
    try {
        connection = &m_tcp_mempool.get();
    }
    catch(std::bad_alloc &e) {
        put_back_record(record);
        throw DnsParseException("Couldn't allocate new item in TCP connection table.");
    }
    connection->set_hash(record.do_tcp_hash());

    // TODO Handle exception thrown from bad tcp table allocation
    bool export_record;
    try {
        auto gate = m_tcp_table[*connection];

        if (gate.empty()) {
            // initialize new TCP connection
            export_record = connection->update_connection(record, *m_processed_packet, tcp_header, pkt.offset(end), *this, records);

            // create new TCP connection
            if (connection->get_state() != DDP::TcpConnectionState::CLOSED) {
                m_tcp_table.insert_hint(gate, *connection);
            }
            else {
                connection->clear_buffers();
                m_tcp_mempool.free(connection);
            }
        }
        else {
            // update DnsTcpConnection values
            export_record = gate->update_connection(record, *m_processed_packet, tcp_header, pkt.offset(end), *this, records);

            // if TCP connection is closed, erase from TCP connection table
            if (gate->get_state() == DDP::TcpConnectionState::CLOSED || gate->buffers_full()) {
                DnsTcpConnection* tmp = gate.operator->();
                m_tcp_table.erase(gate);
                tmp->clear_buffers();
                m_tcp_mempool.free(*tmp);
            }
            else {
                m_tcp_table.update_item(gate);
            }

            // release temporary TCP connection
            connection->clear_buffers();
            m_tcp_mempool.free(connection);
        }
    }
    catch (std::exception& e) {
        put_back_record(record);
        throw DnsParseException(e.what());
    }

    return export_record;
}

void DDP::DnsParser::parse_dns(DDP::MemView<uint8_t> pkt, DDP::DnsRecord& record)
{
    if (!pkt.count()) {
        put_back_record(record);
        throw DnsParseException("Invalid packet. No DNS header and data.");
    }

    // Extract DNS header information
    parse_dns_header(pkt, record);

    if (record.m_response) {
        record.m_res_len = record.m_len;
        record.m_len = 0;
        record.m_res_dns_len = record.m_dns_len;
        record.m_dns_len = 0;
    }

    pkt = pkt.offset(DNS_HEADER_SIZE);

    // Extract QUESTION section data
    if (record.m_qdcount != 0) {
        pkt = parse_dns_question(pkt, record);
    }

    // Check indexing of addresses and ports
    // Interpretation of src <-> dst ports and addresses for responses is inverse to queries
    if(record.m_response) {
        record.m_client_index = (record.m_client_index == DnsRecord::ClientIndex::CLIENT_LOW) ?
                DnsRecord::ClientIndex::CLIENT_HIGH : DnsRecord::ClientIndex::CLIENT_LOW;
    }

    // Extract EDNS if enabled
    parse_edns(pkt, record);
}

DDP::DnsRecord& DDP::DnsParser::get_empty()
{
    return m_record_mempool.get();
}

std::vector<DDP::DnsRecord*> DDP::DnsParser::parse_packet(const Packet& packet)
{
    std::vector<DnsRecord*> records;

    DnsRecord& record = get_empty();
    record.m_len = packet.size();

    auto pkt = packet.payload();
    m_processed_packet = &packet;

    if (!m_raw_pcap) {
        pkt = parse_l2(pkt, record);
    }

    pkt = parse_l3(pkt, record);

    if (record.m_proto == DDP::DnsRecord::Proto::UDP) {
        pkt = parse_l4_udp(pkt, record);

        parse_dns(pkt, record);
        record.do_hash();
        record.m_timestamp = Time(DDP::Time::Clock::REALTIME);
        records.push_back(&record);
    }
    else {
        bool export_record = parse_l4_tcp(pkt, record, records);
        if (!export_record) {
            put_back_record(record);
        }
        else {
            Time timestamp = Time(DDP::Time::Clock::REALTIME);
            if (!records.empty()) {
                for (auto& rec : records) {
                    rec->do_hash();
                    rec->m_timestamp = timestamp;
                }
                put_back_record(record);
            }
            else {
                record.do_hash();
                record.m_timestamp = timestamp;
                records.push_back(&record);
            }
        }
    }

    return records;
}

void DDP::DnsParser::put_back_record(DDP::DnsRecord& record)
{
    if (record.m_req_ednsRdata != nullptr) {
        m_edns_mempool.free(record.m_req_ednsRdata);
        record.m_req_ednsRdata = nullptr;
    }

    if (record.m_resp_ednsRdata != nullptr) {
        m_edns_mempool.free(record.m_resp_ednsRdata);
        record.m_resp_ednsRdata = nullptr;
    }

    m_record_mempool.free(record);
}

void DDP::DnsParser::put_back_records(std::vector<DDP::DnsRecord*>& records)
{
    for (auto& record : records) {
        put_back_record(*record);
    }
}

DDP::DnsRecord& DDP::DnsParser::merge_records(DDP::DnsRecord& request, DDP::DnsRecord& response)
{
    request.m_response = true;
    request.m_res_len = response.m_res_len;
    request.m_res_dns_len = response.m_res_dns_len;
    request.m_aa = response.m_aa;
    request.m_tc = response.m_tc;
    request.m_rcode = response.m_rcode;
    request.m_ancount = response.m_ancount;
    request.m_nscount = response.m_nscount;
    request.m_arcount = response.m_arcount;

    request.m_resp_ednsRdata = response.m_resp_ednsRdata;
    response.m_resp_ednsRdata = nullptr;
    request.m_resp_ednsRdata_size = response.m_resp_ednsRdata_size;

    return request;
}

void DDP::DnsParser::merge_AXFR_record(DDP::DnsRecord& request, DDP::DnsRecord& response)
{
    request.m_response = true;
    request.m_last_soa = response.m_last_soa;
    request.m_res_len += response.m_res_len;
    request.m_res_dns_len += response.m_res_dns_len;
    request.m_ancount += response.m_ancount;
}

uint8_t* DDP::DnsParser::copy_to_buffer(const uint8_t* msg, uint16_t size, std::size_t offset)
{
    if (offset + size > DNS_MSG_BUFFER_SIZE) {
        throw DnsParseException("Buffer is too small");
    }
    std::memcpy(m_msg_buffer.get() + offset, msg, size);
    return m_msg_buffer.get();
}
