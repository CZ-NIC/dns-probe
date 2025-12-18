/*
 *  Copyright (C) 2025 CZ.NIC, z. s. p. o.
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

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
extern "C" {
    #include <libknot/libknot.h>
}

#include "JsonExport.h"


/**
 * @brief Convert policy action enum to textual representation
 * @param policy_action Policy action enum
 * @return Textual representation of policy action enum
 */
static std::string get_policy_action_string(DDP::DnsRecord::PolicyAction policy_action)
{
    std::string result = "";

    switch (policy_action) {
        case DDP::DnsRecord::PolicyAction::ALLOW:
            result = "PASS";
            break;
        case DDP::DnsRecord::PolicyAction::BLOCK:
            result = "BLOCK";
            break;
        case DDP::DnsRecord::PolicyAction::AUDIT:
            result = "AUDIT";
            break;
        default:
            break;
    }

    return result;
}

/**
 * @brief Convert domain name in wire format to textual representation in place
 * @param wire_dname Domain name in wire format that will be converted to textual representation in place
 * @return Size of textual representation of domain name (if > 0 then textual domain name starts at wire_dname + 1)
 */
static std::size_t wire_dname_to_text(char* wire_dname, std::size_t max_size)
{
    unsigned size = 0;
    unsigned labels = 0;

    auto label_len = static_cast<uint8_t>(wire_dname[0]);
    auto pos = static_cast<uint64_t>(label_len + 1);

    while (label_len != 0) {
        size += label_len + 1;
        if (size > max_size)
            throw std::runtime_error("Invalid domain name!");

        labels++;
        label_len = wire_dname[pos];
        if (label_len != 0) {
            wire_dname[pos] = '.';
        }
        pos += label_len + 1;
    }

    if (labels > 0)
        size -= 1;

    return size;
}

/**
 * @brief Get textual representation of DNS resource record's RDATA
 * @param rr DNS resource record with binary RDATA to convert
 * @param buf Buffer where resulting textual representation will be stored
 * @param buf_size Size of buf. Recommended size is 65536 (maximum RR size)
 * @return Size of textual representation of RDATA in bytes, < 0 if error.
 */
static int get_text_rdata(DDP::DnsRR& rr, char* buf, std::size_t buf_size) {
    if (!rr.rdata || !buf)
        return -1;

    knot_rrset_t* rrset = knot_rrset_new(reinterpret_cast<const knot_dname_t*>(rr.dname),
        rr.type, rr.class_, rr.ttl, NULL);
    auto ret = knot_rrset_add_rdata(rrset, rr.rdata, rr.rdlength, NULL);
    if (ret != KNOT_EOK) {
        knot_rrset_free(rrset, NULL);
        return -1;
    }

    knot_dump_style_t style = KNOT_DUMP_STYLE_DEFAULT;
    knot_dump_style_t generic_style = KNOT_DUMP_STYLE_DEFAULT;
    generic_style.generic = true;
    ret = knot_rrset_txt_dump_data(rrset, 0, buf, buf_size, &style);
    if (ret < 0) {
        ret = knot_rrset_txt_dump_data(rrset, 0, buf, buf_size, &generic_style);
        if (ret < 0) {
            knot_rrset_free(rrset, NULL);
            return ret;
        }
    }

    knot_rrset_free(rrset, NULL);
    return ret;
}

DDP::JsonExport::JsonExport(Config& cfg, MMDB_s& country_db, MMDB_s& asn_db)
    : BaseExport(cfg.anonymize_ip.value(), country_db, asn_db), m_buffer(),
    m_export_resp_rr(cfg.cdns_export_resp_rr.value()),
    m_max_records(cfg.cdns_records_per_block.value())
{
    m_chunk = std::make_shared<std::vector<rapidjson::StringBuffer>>();
}

boost::any DDP::JsonExport::buffer_record(DnsRecord& record)
{
    // Parse EDNS record first to drop the DNS record if EDNS record is invalid
    std::unordered_map<uint16_t, boost::any> req_edns_map, resp_edns_map;
    if (record.m_req_ednsRdata != nullptr)
        req_edns_map = parse_edns_options(record.m_req_ednsRdata, record.m_req_ednsRdata_size);

    if (record.m_resp_ednsRdata != nullptr)
        resp_edns_map = parse_edns_options(record.m_resp_ednsRdata, record.m_resp_ednsRdata_size);

    m_buffer.Clear();
    m_writer.Reset(m_buffer);
    m_writer.StartObject();

    // DNS ID
    m_writer.Key("id");
    m_writer.Uint(record.m_id);

    // Seconds part of timestamp
    m_writer.Key("unixtime");
    m_writer.Uint64(record.m_timestamp.getSeconds());

    // Timestamp (microseconds precision)
    m_writer.Key("time");
    m_writer.Uint64(record.m_timestamp.getMicros());

    // Qname and Domain Name (part of Qname)
    m_writer.Key("qname");
    char* domain_name = nullptr;
    uint8_t labels = 0;
    int size = record.domain_name(&domain_name, &labels);
    if (labels > 0)
        m_writer.String(record.m_qname + 1, strlen(record.m_qname) - 1);
    else
        m_writer.String(record.m_qname, strlen(record.m_qname));

    for (int i = 0; i < size; i++) {
        domain_name[i] = std::tolower(static_cast<unsigned char>(domain_name[i]));
    }

    m_writer.Key("domainname");
    m_writer.String(domain_name, size);

    // Request packet length
    m_writer.Key("len");
    m_writer.Uint(record.m_len);

    // Fragmentation (Always empty)
    m_writer.Key("frag");
    m_writer.Uint(0);

    // TTL
    m_writer.Key("ttl");
    m_writer.Uint(record.m_ttl);

    // IP Version
    m_writer.Key("ipv");
    if (record.m_addr_family == DDP::DnsRecord::AddrFamily::IP4) {
        m_writer.Uint(4);
    }
    else {
        m_writer.Uint(6);
    }

    // Transport layer protocol
    m_writer.Key("prot");
    m_writer.Uint(static_cast<unsigned>(record.m_proto));

    // Source IP address
    int buf_len = record.m_addr_family == DDP::DnsRecord::AddrFamily::IP4 ? INET_ADDRSTRLEN + 4 : INET6_ADDRSTRLEN + 4;
    char addrBuf[buf_len];
    in6_addr* addr = record.client_address();
    int ipv = record.m_addr_family == DDP::DnsRecord::AddrFamily::IP4 ? AF_INET : AF_INET6;

    std::string country;
    std::string asn;
    fill_asn_country(addr, ipv, asn, country);

#ifdef PROBE_CRYPTOPANT
    if (m_anonymize_ip) {
        if (ipv == AF_INET)
            *reinterpret_cast<uint32_t*>(addr) = scramble_ip4(*reinterpret_cast<uint32_t*>(addr), 0);
        else
            scramble_ip6(addr, 0);
    }
#endif

    inet_ntop(ipv, addr, addrBuf, sizeof(addrBuf));
    m_writer.Key("src");
    m_writer.String(addrBuf, strlen(addrBuf));

    // Source port
    m_writer.Key("srcp");
    m_writer.Uint(record.client_port());

    // Destination IP address
    in6_addr* srv_addr = record.server_address();
    inet_ntop(ipv, srv_addr, addrBuf, sizeof(addrBuf));
    m_writer.Key("dst");
    m_writer.String(addrBuf, strlen(addrBuf));

    // Destination port
    m_writer.Key("dstp");
    m_writer.Uint(record.server_port());

    // UDP checksum
    m_writer.Key("udp_sum");
    m_writer.Uint(record.m_udp_sum);

    // Request DNS payload length
    m_writer.Key("dns_len");
    m_writer.Uint(record.m_dns_len);

    // DNS header AA bit
    m_writer.Key("aa");
    m_writer.Bool(record.m_aa);

    // DNS header TC bit
    m_writer.Key("tc");
    m_writer.Bool(record.m_tc);

    // DNS header RD bit
    m_writer.Key("rd");
    m_writer.Bool(record.m_rd);

    // DNS header RA bit
    m_writer.Key("ra");
    m_writer.Bool(record.m_ra);

    // DNS header Z bit
    m_writer.Key("z");
    m_writer.Bool(record.m_z);

    // EDNS AD bit
    m_writer.Key("ad");
    m_writer.Bool(record.m_ad);

    // EDNS CD bit
    m_writer.Key("cd");
    m_writer.Bool(record.m_cd);

    // DNS header AnCount
    m_writer.Key("ancount");
    m_writer.Uint(record.m_ancount);

    // DNS header ArCount
    m_writer.Key("arcount");
    m_writer.Uint(record.m_arcount);

    // DNS header NsCount
    m_writer.Key("nscount");
    m_writer.Uint(record.m_nscount);

    // DNS header QdCount
    m_writer.Key("qdcount");
    m_writer.Uint(record.m_qdcount);

    // DNS header OpCode
    m_writer.Key("opcode");
    m_writer.Uint(record.m_opcode);

    // DNS header RCode
    m_writer.Key("rcode");
    m_writer.Uint(record.m_rcode);

    // DNS QType
    m_writer.Key("qtype");
    m_writer.Uint(record.m_qtype);

    // DNS QClass
    m_writer.Key("qclass");
    m_writer.Uint(record.m_qclass);

    // Country
    m_writer.Key("country");
    m_writer.String(country.c_str());

    // ASN
    m_writer.Key("asn");
    m_writer.String(asn.c_str());

    // EDNS UDP payload
    m_writer.Key("edns_udp");
    m_writer.Uint(record.m_ednsUDP);

    // EDNS Version
    m_writer.Key("edns_version");
    m_writer.Uint(record.m_ednsVersion);

    // EDNS DO bit
    m_writer.Key("edns_do");
    m_writer.Bool(record.m_ednsDO);

    // EDNS Ping bit
    m_writer.Key("edns_ping");
    m_writer.Bool(false);

    // EDNS options
    if (record.m_resp_ednsRdata != nullptr) {
        // EDNS NSID
        auto find = resp_edns_map.find(static_cast<uint16_t>(EDNSOptions::NSID));
        m_writer.Key("edns_nsid");
        if (find != resp_edns_map.end()) {
            m_writer.String(boost::any_cast<std::string>(resp_edns_map[static_cast<uint16_t>(EDNSOptions::NSID)]).c_str());
        }
        else {
            m_writer.String("");
        }
    }
    else {
        // EDNS NSID
        m_writer.Key("edns_nsid");
        m_writer.String("");
    }

    if (record.m_req_ednsRdata != nullptr) {
        // EDNS DNSSEC DAU
        m_writer.Key("edns_dnssec_dau");
        auto find_dau = req_edns_map.find(static_cast<uint16_t>(EDNSOptions::DNSSEC_DAU));
        if (find_dau != req_edns_map.end()) {
            m_writer.String(boost::any_cast<std::string>(req_edns_map[static_cast<uint16_t>(EDNSOptions::DNSSEC_DAU)]).c_str());
        }
        else {
            m_writer.String("");
        }

        // EDNS DNSSEC DHU
        m_writer.Key("edns_dnssec_dhu");
        auto find_dhu = req_edns_map.find(static_cast<uint16_t>(EDNSOptions::DNSSEC_DHU));
        if (find_dhu != req_edns_map.end()) {
            m_writer.String(boost::any_cast<std::string>(req_edns_map[static_cast<uint16_t>(EDNSOptions::DNSSEC_DHU)]).c_str());
        }
        else {
            m_writer.String("");
        }

        // EDNS DNSSEC N3U
        m_writer.Key("edns_dnssec_n3u");
        auto find_n3u = req_edns_map.find(static_cast<uint16_t>(EDNSOptions::DNSSEC_N3U));
        if (find_n3u != req_edns_map.end()) {
            m_writer.String(boost::any_cast<std::string>(req_edns_map[static_cast<uint16_t>(EDNSOptions::DNSSEC_N3U)]).c_str());
        }
        else {
            m_writer.String("");
        }

        // EDNS client subnet
        m_writer.Key("edns_client_subnet");
        m_writer.String("");

        // EDNS other
        m_writer.Key("edns_other");
        auto find_other = req_edns_map.find(static_cast<uint16_t>(EDNSOptions::Other));
        if (find_other != req_edns_map.end()) {
            m_writer.String(boost::any_cast<std::string>(req_edns_map[static_cast<uint16_t>(EDNSOptions::Other)]).c_str());
        }
        else {
            m_writer.String("");
        }
    }
    else {
        // EDNS DNSSEC DAU
        m_writer.Key("edns_dnssec_dau");
        m_writer.String("");

        // EDNS DNSSEC DHU
        m_writer.Key("edns_dnssec_dhu");
        m_writer.String("");

        // EDNS DNSSEC N3U
        m_writer.Key("edns_dnssec_n3u");
        m_writer.String("");

        // EDNS client subnet
        m_writer.Key("edns_client_subnet");
        m_writer.String("");

        // EDNS other
        m_writer.Key("edns_other");
        m_writer.String("");
    }

    // EDNS client subnet ASN
    m_writer.Key("edns_client_subnet_asn");
    m_writer.String("");

    // EDNS client subnet country
    m_writer.Key("edns_client_subnet_country");
    m_writer.String("");

    // Labels
    m_writer.Key("labels");
    m_writer.Uint(labels);

    // Response packet length
    m_writer.Key("res_len");
    m_writer.Uint64(record.m_res_len);

    // Microseconds part of timestamp
    m_writer.Key("time_micro");
    m_writer.Uint64(record.m_timestamp.getMicroseconds());

    // Response fragmentation (always empty)
    m_writer.Key("resp_frag");
    m_writer.Uint(0);

    // Processor time spent to process this DNS record?
    m_writer.Key("proc_time");
    m_writer.Uint(0);

    // Is query to Google DNS servers
    m_writer.Key("is_google");
    m_writer.Bool(false);

    // Is query to OpenDNS servers
    m_writer.Key("is_opendns");
    m_writer.Bool(false);

    // Response DNS payload length
    m_writer.Key("dns_res_len");
    m_writer.Uint64(record.m_res_dns_len);

    // Server location
    m_writer.Key("server_location");
    m_writer.String("");

    // TCP RTT (microseconds precision)
    m_writer.Key("tcp_hs_rtt");
    if (record.m_tcp_rtt >= 0)
        m_writer.Double(static_cast<double>(record.m_tcp_rtt / 1000.0));
    else
        m_writer.Null();

    // answer_rrs
    m_writer.Key("answer_rrs");
    if (m_export_resp_rr && record.m_resp_answer_rrs.size() > 0)
        write_rr_array(record.m_resp_answer_rrs);
    else
        m_writer.Null();


    // authority_rrs
    m_writer.Key("authority_rrs");
    if (m_export_resp_rr && record.m_resp_authority_rrs.size() > 0)
        write_rr_array(record.m_resp_authority_rrs);
    else
        m_writer.Null();

    // additional_rrs
    m_writer.Key("additional_rrs");
    if (m_export_resp_rr && (record.m_resp_additional_rrs.size() > 0 || record.m_resp_ednsRdata))
        write_rr_array(record.m_resp_additional_rrs, &record);
    else
        m_writer.Null();

    // UUID
    m_writer.Key("user_id");
    m_writer.String(record.m_uid, strnlen(record.m_uid, UUID_SIZE));

    // Policy action
    m_writer.Key("policy_action");
    if (record.m_policy_action != DnsRecord::PolicyAction::NO_ACTION) {
        auto action = get_policy_action_string(record.m_policy_action);
        if (!action.empty())
            m_writer.String(action.c_str());
        else
            m_writer.Null();
    }
    else
        m_writer.Null();

    // Policy rule
    m_writer.Key("policy_rule");
    if (record.m_policy_rule) {
        if (record.m_policy_rule[0] == '\0')
            m_writer.String("");
        else
            m_writer.String(reinterpret_cast<char*>(record.m_policy_rule), record.m_policy_rule_size);
    }
    else
        m_writer.Null();

    m_writer.EndObject();

    if (!m_writer.IsComplete())
        throw DnsExportException("JSON object isn't complete");

    m_chunk->emplace_back(std::move(m_buffer));
    m_buffer = rapidjson::StringBuffer();
    m_writer.Reset(m_buffer);

    if (m_chunk->size() >= m_max_records) {
        return rotate_export();
    }

    return nullptr;
}

void DDP::JsonExport::write_leftovers(JsonWriter& writer, Statistics& stats)
{
    if (m_chunk->size() == 0)
        return;

    writer.write(m_chunk);
    stats.exported_records += m_chunk->size();
    m_chunk = std::make_shared<std::vector<rapidjson::StringBuffer>>();
}

void DDP::JsonExport::write_rr_array(std::vector<DnsRR*>& rrs, DnsRecord* record)
{
    if (rrs.size() == 0 && record == nullptr)
        return;

    m_writer.StartArray();
    if (record && record->m_resp_ednsRdata) {
        m_writer.StartObject();

        m_writer.Key("name");
        m_writer.String("");

        m_writer.Key("type");
        m_writer.Uint(41);

        m_writer.Key("class");
        m_writer.Uint(record->m_ednsUDP);

        m_writer.Key("ttl");
        m_writer.Null();

        m_writer.Key("rdata");
        DnsRR edns;
        edns.dname[0] = '\0';
        edns.type = 41;
        edns.class_ = record->m_ednsUDP;
        edns.ttl = 0;
        edns.rdlength = record->m_resp_ednsRdata_size;
        edns.rdata = record->m_resp_ednsRdata;
        int ret = get_text_rdata(edns, m_rdata_buffer, UINT16_MAX);
        if (ret < 0)
            m_writer.Null();
        else
            m_writer.String(m_rdata_buffer, ret);

        m_writer.EndObject();
    }

    for (DnsRR* rr : rrs) {
        m_writer.StartObject();

        m_writer.Key("name");
        auto size = wire_dname_to_text(rr->dname, QNAME_BUFFER_SIZE);
        if (size > 0)
            m_writer.String(rr->dname + 1, size);
        else
            m_writer.String("");

        m_writer.Key("type");
        m_writer.Uint(rr->type);

        m_writer.Key("class");
        m_writer.Uint(rr->class_);

        m_writer.Key("ttl");
        m_writer.Uint64(rr->ttl);

        m_writer.Key("rdata");
        int ret = get_text_rdata(*rr, m_rdata_buffer, UINT16_MAX);
        if (ret < 0)
            m_writer.Null();
        else
            m_writer.String(m_rdata_buffer, ret);

        m_writer.EndObject();
    }
    m_writer.EndArray();
}
