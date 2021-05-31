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

#include <exception>
#include <cstring>

#include <cstdint>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#ifdef PROBE_DNSTAP
#include "dnstap.pb.h"
#endif

#ifdef PROBE_KNOT
extern "C" {
    #include <libknot/libknot.h>
}
#endif

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
        m_pcap_inv(cfg, true, process_id),
        m_processed_packet{nullptr},
        m_dns_ports(cfg.dns_ports),
        m_ipv4_allowlist(cfg.ipv4_allowlist),
        m_ipv4_denylist(cfg.ipv4_denylist),
        m_ipv6_allowlist(cfg.ipv6_allowlist),
        m_ipv6_denylist(cfg.ipv6_denylist),
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

#ifdef PROBE_DNSTAP
DDP::MemView<uint8_t> DDP::DnsParser::parse_dnstap_header(const dnstap::Dnstap& msg, DnsRecord& record, bool& drop)
{
    MemView<uint8_t> dns = MemView<uint8_t>();

    // Check for RTT estimate in "extra" byte field as exported by Knot Resolver
    if (msg.has_extra() && msg.extra().size() > 4 && msg.extra().compare(0,4, "rtt=") == 0) {
        try {
            record.m_tcp_rtt = static_cast<int64_t>(std::stoul(msg.extra().substr(4, msg.extra().size())));
        }
        catch (std::exception& e) {
            Logger("DNSTAP").debug() << "Couldn't parse RTT from extra field";
        }
    }

    // Check if message contains everything necessary
    if (!msg.has_message())
        throw DnsParseException("Dnstap missing message content");
    auto& hdr = msg.message();

    if (!hdr.has_type())
        throw DnsParseException("Missing type of dnstap message");

    if (!hdr.has_socket_family() || !hdr.has_query_address() || !hdr.has_response_address())
        throw DnsParseException("IP version or address missing in dnstap message");

    if (!hdr.has_socket_protocol() || !hdr.has_query_port() || !hdr.has_response_port())
        throw DnsParseException("Transport protocol or port missing in dnstap message");

    // Parse L3 information
    if (hdr.socket_family() == dnstap::SocketFamily::INET) {
        record.m_addr_family = DnsRecord::AddrFamily::IP4;
        drop = block_ipv4s(reinterpret_cast<const uint8_t*>(hdr.query_address().c_str()),
                            reinterpret_cast<const uint8_t*>(hdr.response_address().c_str()));
        if (drop) {
            put_back_record(record);
            return MemView<uint8_t>();
        }
        set_ips(record, reinterpret_cast<const uint8_t*>(hdr.query_address().c_str()),
            reinterpret_cast<const uint8_t*>(hdr.response_address().c_str()), IPV4_ADDRLEN);
    }
    else if (hdr.socket_family() == dnstap::SocketFamily::INET6) {
        record.m_addr_family = DnsRecord::AddrFamily::IP6;
        drop = block_ipv6s(reinterpret_cast<const uint8_t*>(hdr.query_address().c_str()),
                            reinterpret_cast<const uint8_t*>(hdr.response_address().c_str()));
        if (drop) {
            put_back_record(record);
            return MemView<uint8_t>();
        }
        set_ips(record, reinterpret_cast<const uint8_t*>(hdr.query_address().c_str()),
            reinterpret_cast<const uint8_t*>(hdr.response_address().c_str()), IPV6_ADDRLEN);
    }
    else {
        put_back_record(record);
        drop = true;
        return MemView<uint8_t>();
    }

    // Parse L4 information
    switch (hdr.socket_protocol()) {
        case dnstap::SocketProtocol::UDP:
            record.m_proto = DnsRecord::Proto::UDP;
            break;
        case dnstap::SocketProtocol::TCP:
        case dnstap::SocketProtocol::DOT:
        case dnstap::SocketProtocol::DOH:
            record.m_proto = DnsRecord::Proto::TCP;
            break;
        default:
            put_back_record(record);
            drop = true;
            return MemView<uint8_t>();
            break;
    }

    if (!is_dns_ports(hdr.query_port(), hdr.response_port())) {
        put_back_record(record);
        drop = true;
        return MemView<uint8_t>();
    }

    record.m_port[static_cast<int>(record.m_client_index)] = hdr.query_port();
    record.m_port[!static_cast<int>(record.m_client_index)] = hdr.response_port();

    // Parse additional information (DNS wire length, timestamps)
    switch (hdr.type()) {
        case dnstap::Message_Type::Message_Type_CLIENT_QUERY:
        case dnstap::Message_Type::Message_Type_RESOLVER_QUERY:
        case dnstap::Message_Type::Message_Type_AUTH_QUERY:
        case dnstap::Message_Type::Message_Type_FORWARDER_QUERY:
        case dnstap::Message_Type::Message_Type_STUB_QUERY:
        case dnstap::Message_Type::Message_Type_TOOL_QUERY:
        case dnstap::Message_Type::Message_Type_UPDATE_QUERY:
            if (!hdr.has_query_message())
                throw DnsParseException("dnstap message missing query DNS data");

            record.m_dns_len = hdr.query_message().size();
            dns = MemView<uint8_t>(reinterpret_cast<const uint8_t*>(hdr.query_message().c_str()), hdr.query_message().size());
            if (hdr.has_query_time_sec() && hdr.has_query_time_nsec()) {
                struct timespec tm;
                tm.tv_sec = hdr.query_time_sec();
                tm.tv_nsec = hdr.query_time_nsec();
                record.m_timestamp = Time(tm);
            }
            else
                record.m_timestamp = Time(Time::Clock::REALTIME);
            break;
        case dnstap::Message_Type::Message_Type_CLIENT_RESPONSE:
        case dnstap::Message_Type::Message_Type_RESOLVER_RESPONSE:
        case dnstap::Message_Type::Message_Type_AUTH_RESPONSE:
        case dnstap::Message_Type::Message_Type_FORWARDER_RESPONSE:
        case dnstap::Message_Type::Message_Type_STUB_RESPONSE:
        case dnstap::Message_Type::Message_Type_TOOL_RESPONSE:
        case dnstap::Message_Type::Message_Type_UPDATE_RESPONSE:
            if (!hdr.has_response_message())
                throw DnsParseException("dnstap message missing response DNS data");

            record.m_dns_len = hdr.response_message().size();
            dns = MemView<uint8_t>(reinterpret_cast<const uint8_t*>(hdr.response_message().c_str()), hdr.response_message().size());
            if (hdr.has_response_time_sec() && hdr.has_response_time_nsec()) {
                struct timespec tm;
                tm.tv_sec = hdr.response_time_sec();
                tm.tv_nsec = hdr.response_time_nsec();
                record.m_timestamp = Time(tm);
            }
            else
                record.m_timestamp = Time(Time::Clock::REALTIME);
            break;
        default:
            throw DnsParseException("Invalid type of dnstap message");
            break;
    }

    return dns;
}
#endif

DDP::MemView<uint8_t> DDP::DnsParser::parse_l2(const DDP::MemView<uint8_t>& pkt, DDP::DnsRecord& record, bool& drop)
{
    // Check if packet is long enough to contain valid ethernet header
    if(pkt.count() < sizeof(ether_header)) {
        put_back_record(record);
        throw DnsParseException("Cannot skip ethernet header packet is too short.");
    }

    auto eth_header = reinterpret_cast<const ether_header*>(pkt.ptr());
    if (!(eth_header->ether_type & ETHER_TYPE_IPV4 || eth_header->ether_type & ETHER_TYPE_IPV6)) {
        put_back_record(record);
        drop = true;
    }

    return pkt.offset(sizeof(ether_header));
}

DDP::MemView<uint8_t> DDP::DnsParser::parse_l3(const DDP::MemView<uint8_t>& pkt, DDP::DnsRecord& record, bool& drop)
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
        return parse_ipv4(pkt, record, drop);
    }
    else if(ip_bits == IP_VERSION_6) {
        return parse_ipv6(pkt, record, drop);
    }
    else {
        put_back_record(record);
        drop = true;
        return pkt;
    }
}

DDP::MemView<uint8_t> DDP::DnsParser::parse_ipv4(const DDP::MemView<uint8_t>& pkt, DDP::DnsRecord& record, bool& drop)
{
    auto end = sizeof(iphdr);
    if(end > pkt.count()) {
        put_back_record(record);
        throw DnsParseException("Packet is too short. Probably missing part of IPv4 header.");
    }

    auto ipv4_header = reinterpret_cast<const iphdr*>(pkt.ptr());

    end = ipv4_header->ihl * 4;
    if(end > pkt.count()) {
        put_back_record(record);
        throw DnsParseException("Packet is too short. Probably missing part of IPv4 header.");
    }

    drop = block_ipv4s(reinterpret_cast<const uint8_t*>(&(ipv4_header->saddr)),
                        reinterpret_cast<const uint8_t*>(&(ipv4_header->daddr)));
    if (drop) {
        put_back_record(record);
        return pkt;
    }

    set_ips(record, reinterpret_cast<const uint8_t*>(&ipv4_header->saddr),
        reinterpret_cast<const uint8_t*>(&ipv4_header->daddr), IPV4_ADDRLEN);

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
            drop = true;
            return pkt;
    }

    if (ntohs(ipv4_header->tot_len) > pkt.count()) {
        put_back_record(record);
        throw DnsParseException("Packet is shorter than IPv4 header claims.");
    }

    return MemView<uint8_t>(pkt.offset(end).ptr(), ntohs(ipv4_header->tot_len) - end);
}

DDP::MemView<uint8_t> DDP::DnsParser::parse_ipv6(const DDP::MemView<uint8_t>& pkt, DDP::DnsRecord& record, bool& drop)
{
    auto end = sizeof(ip6_hdr);
    if(end > pkt.count()) {
        put_back_record(record);
        throw DnsParseException("Packet is too short. Probably missing part of IPv6 header.");
    }

    auto ipv6_header = reinterpret_cast<const ip6_hdr*>(pkt.ptr());

    drop = block_ipv6s(reinterpret_cast<const uint8_t*>(&(ipv6_header->ip6_src)),
                        reinterpret_cast<const uint8_t*>(&(ipv6_header->ip6_dst)));
    if (drop) {
        put_back_record(record);
        return pkt;
    }

    set_ips(record, reinterpret_cast<const uint8_t*>(&ipv6_header->ip6_src),
        reinterpret_cast<const uint8_t*>(&ipv6_header->ip6_dst), IPV6_ADDRLEN);

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
            drop = true;
            return pkt;
    }

    if ((ntohs(ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_plen) + end) > pkt.count()) {
        put_back_record(record);
        throw DnsParseException("Packet is shorter than IPv6 header claims");
    }

    return MemView<uint8_t>(pkt.offset(end).ptr(), ntohs(ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_plen));
}

DDP::MemView<uint8_t> DDP::DnsParser::parse_l4_udp(const DDP::MemView<uint8_t>& pkt, DDP::DnsRecord& record, bool& drop)
{
    auto end = sizeof(udphdr);
    if(end > pkt.count()) {
        put_back_record(record);
        throw DnsParseException("Packet is too short. Probably missing part of UDP header.");
    }

    auto udp_header = reinterpret_cast<const udphdr*>(pkt.ptr());

    auto src_port = ntohs(udp_header->source);
    auto dst_port = ntohs(udp_header->dest);

    if (!is_dns_ports(src_port, dst_port)) {
        put_back_record(record);
        drop = true;
        return pkt;
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

    if (!is_dns_ports(src_port, dst_port))
        return false;

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

void DDP::DnsParser::parse_wire_packet(const Packet& packet, DnsRecord& record, std::vector<DnsRecord*>& records, bool& drop)
{
    auto pkt = packet.payload();
    if (!m_raw_pcap) {
        pkt = parse_l2(pkt, record, drop);
        if (drop)
            return;
    }

    pkt = parse_l3(pkt, record, drop);

    if (drop)
        return;

    if (record.m_proto == DDP::DnsRecord::Proto::UDP) {
        pkt = parse_l4_udp(pkt, record, drop);
        if (drop)
            return;

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
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
void DDP::DnsParser::parse_dnstap_packet(const Packet& packet, DnsRecord& record, std::vector<DnsRecord*>& records, bool& drop)
{
#ifdef PROBE_DNSTAP
    auto pkt = packet.payload();
    dnstap::Dnstap msg;
    if (!msg.ParseFromArray(pkt.ptr(), pkt.count())) {
        put_back_record(record);
        throw DnsParseException("Couldn't parse dnstap message.");
    }

    pkt = parse_dnstap_header(msg, record, drop);

    if (drop)
        return;

    parse_dns(pkt, record);

    record.do_hash();
    records.push_back(&record);
#else
    drop = true;
    put_back_record(record);
#endif
}
#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
void DDP::DnsParser::parse_knot_dgram(const Packet& dgram, DnsRecord& record, std::vector<DnsRecord*>& records, bool& drop)
{
#ifdef PROBE_KNOT
    const knot_probe_data_t* data = reinterpret_cast<const knot_probe_data_t*>(dgram.payload().ptr());

    if (data->reply.size == 0) {
        put_back_record(record);
        throw DnsParseException("Response missing in Knot interface datagram.");
    }

    // Parse general information
    record.m_dns_len = data->query.size;
    record.m_res_dns_len = data->reply.size;
    record.m_timestamp = Time(Time::Clock::REALTIME);
    record.m_request = data->query.size > 0 ? true : false;
    record.m_response = data->reply.size > 0 ? true : false;
    if (data->tcp_rtt > 0)
        record.m_tcp_rtt = static_cast<int64_t>(data->tcp_rtt);

    // Parse L3 information
    if (data->ip == 4) {
        record.m_addr_family = DnsRecord::AddrFamily::IP4;
        drop = block_ipv4s(data->remote.addr, data->local.addr);

        if (drop) {
            put_back_record(record);
            return;
        }
        set_ips(record, data->remote.addr, data->local.addr, IPV4_ADDRLEN);
    }
    else if (data->ip == 6) {
        record.m_addr_family = DnsRecord::AddrFamily::IP6;
        drop = block_ipv6s(data->remote.addr, data->local.addr);

        if (drop) {
            put_back_record(record);
            return;
        }
        set_ips(record, data->remote.addr, data->local.addr, IPV6_ADDRLEN);
    }
    else {
        put_back_record(record);
        drop = true;
        return;
    }

    // Parse L4 information
    switch (data->proto) {
        case KNOT_PROBE_PROTO_UDP:
            record.m_proto = DnsRecord::Proto::UDP;
            break;
        case KNOT_PROBE_PROTO_TCP:
        case KNOT_PROBE_PROTO_TLS:
        case KNOT_PROBE_PROTO_HTTPS:
            record.m_proto = DnsRecord::Proto::TCP;
            break;
        default:
            put_back_record(record);
            drop = true;
            return;
            break;
    }

    if (!is_dns_ports(data->remote.port, data->local.port)) {
        put_back_record(record);
        drop = true;
        return;
    }

    record.m_port[static_cast<int>(record.m_client_index)] = data->remote.port;
    record.m_port[!static_cast<int>(record.m_client_index)] = data->local.port;

    // Parse DNS data
    record.m_id = ntohs(data->query.hdr.id);
    record.m_opcode = (data->query.hdr.byte3 & DNS_HEADER_OPCODE) >> DNS_HEADER_OPCODE_SHIFT;
    record.m_aa = data->reply.hdr.byte3 & DNS_HEADER_AA;
    record.m_tc = data->reply.hdr.byte3 & DNS_HEADER_TC;
    record.m_rd = data->query.hdr.byte3 & DNS_HEADER_RD;
    record.m_ra = data->query.hdr.byte4 & DNS_HEADER_RA;
    record.m_ad = data->query.hdr.byte4 & DNS_HEADER_AD;
    record.m_cd = data->query.hdr.byte4 & DNS_HEADER_CD;
    record.m_z = data->query.hdr.byte4 & DNS_HEADER_Z;
    record.m_rcode = data->reply.rcode;
    record.m_qdcount = ntohs(data->query.hdr.questions);
    record.m_ancount = ntohs(data->reply.hdr.answers);
    record.m_nscount = ntohs(data->reply.hdr.authorities);
    record.m_arcount = ntohs(data->reply.hdr.additionals);
    record.m_qclass = data->query.qclass;
    record.m_qtype = data->query.qtype;
    std::memcpy(record.m_qname, data->query.qname, data->query.qname_len);

    // Parse EDNS
    if (data->query_edns.present) {
        record.m_ednsUDP = data->query_edns.payload;
        record.m_ednsVersion = data->query_edns.version;
        record.m_ednsDO = data->query_edns.flag_do;

        if (data->query_edns.options) {
            uint16_t rdata_len = 0;
            uint32_t options = data->query_edns.options;

            // Brian Kernighan's algorithm to count set bits. The number of loops is equal
            // to bits set in integer.
            while (options) {
                options &= (options - 1);
                rdata_len += DNS_MIN_OPTION_SIZE;
            }

            record.m_req_ednsRdata = static_cast<uint8_t*>(m_edns_mempool.get(rdata_len));
            record.m_req_ednsRdata_size = rdata_len;

            uint32_t count = 0;
            for (uint16_t i = 0; i < sizeof(data->query_edns.options) * 8; i++) {
                if (data->query_edns.options & (1 << i)) {
                    uint16_t* ptr = reinterpret_cast<uint16_t*>(record.m_req_ednsRdata) + (count * (DNS_MIN_OPTION_SIZE / 2));
                    *ptr = htons(i);
                    *(ptr + 1) = htons(0);
                    count++;
                }
            }
        }
    }


    record.do_hash();
    records.push_back(&record);
#else
    drop = true;
    put_back_record(record);
#endif
}
#pragma GCC diagnostic pop

std::vector<DDP::DnsRecord*> DDP::DnsParser::parse_packet(const Packet& packet)
{
    std::vector<DnsRecord*> records;

    DnsRecord& record = get_empty();
    record.m_len = packet.size();
    m_processed_packet = &packet;
    bool drop = false;

    if (packet.type() == PacketType::DNSTAP)
        parse_dnstap_packet(packet, record, records, drop);
    else if (packet.type() == PacketType::KNOT)
        parse_knot_dgram(packet, record, records, drop);
    else
        parse_wire_packet(packet, record, records, drop);

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

    if (response.m_tcp_rtt > 0)
        request.m_tcp_rtt = response.m_tcp_rtt;

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

bool DDP::DnsParser::block_ipv4s(const uint8_t* src, const uint8_t* dst)
{
    if (!m_ipv4_allowlist.empty()) {
        bool deny = true;
        for (auto& ipv4 : m_ipv4_allowlist) {
            if ((std::memcmp(src, &ipv4, IPV4_ADDRLEN) == 0) ||
                (std::memcmp(dst, &ipv4, IPV4_ADDRLEN) == 0)) {
                deny = false;
                break;
            }
        }

        if (deny)
            return true;
    }
    else if (!m_ipv4_denylist.empty() && m_ipv4_allowlist.empty()) {
        for (auto& ipv4 : m_ipv4_denylist) {
            if ((std::memcmp(src, &ipv4, IPV4_ADDRLEN) == 0) ||
                (std::memcmp(dst, &ipv4, IPV4_ADDRLEN) == 0)) {
                return true;
            }
        }
    }

    return false;
}

bool DDP::DnsParser::block_ipv6s(const uint8_t* src, const uint8_t* dst)
{
    if (!m_ipv6_allowlist.empty()) {
        bool deny = true;
        for (auto& ipv6 : m_ipv6_allowlist) {
            if ((std::memcmp(src, ipv6.data(), IPV6_ADDRLEN) == 0) ||
                (std::memcmp(dst, ipv6.data(), IPV6_ADDRLEN) == 0)) {
                deny = false;
                break;
            }
        }

        if (deny)
            return true;
    }
    else if (!m_ipv6_denylist.empty() && m_ipv6_allowlist.empty()) {
        for (auto& ipv6 : m_ipv6_denylist) {
            if ((std::memcmp(src, ipv6.data(), IPV6_ADDRLEN) == 0) ||
                (std::memcmp(dst, ipv6.data(), IPV6_ADDRLEN) == 0)) {
                return true;
            }
        }
    }

    return false;
}

bool DDP::DnsParser::is_dns_ports(const uint16_t srcp, const uint16_t dstp)
{
    for (auto& dns_port : m_dns_ports) {
        if (srcp == dns_port || dstp == dns_port)
            return true;
    }

    return false;
}

void DDP::DnsParser::set_ips(DnsRecord& record, const uint8_t* src, const uint8_t* dst, uint8_t ip_len)
{
    if(std::memcmp(src, dst, ip_len) > 0) {
        std::memcpy(&(record.m_addr[0]), dst, ip_len);
        std::memcpy(&(record.m_addr[1]), src, ip_len);
        // Indicate location of src addr
        record.m_client_index = DnsRecord::ClientIndex::CLIENT_HIGH;
    }
    else {
        std::memcpy(&(record.m_addr[0]), src, ip_len);
        std::memcpy(&(record.m_addr[1]), dst, ip_len);
        record.m_client_index = DnsRecord::ClientIndex::CLIENT_LOW;
    }
}
