/*
 *  Copyright (C) 2020 Brno University of Technology
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

#include "CdnsExport.h"

DDP::CdnsExport::CdnsExport(Config& cfg)
    : DnsExport(cfg), m_fields(cfg.cdns_fields.value()), m_parameters()
{
    m_parameters.storage_parameters.max_block_items = cfg.cdns_records_per_block.value();
    set_cdns_hints(m_parameters.storage_parameters.storage_hints.query_response_hints,
                   m_parameters.storage_parameters.storage_hints.query_response_signature_hints,
                   m_fields);

    m_block = std::make_shared<CDNS::CdnsBlock>(CDNS::CdnsBlock(m_parameters, 0));

    if (m_anonymize_ip) {
        if (scramble_init_from_file(m_ip_enc_key.c_str(), static_cast<scramble_crypt_t>(m_ip_encryption),
            static_cast<scramble_crypt_t>(m_ip_encryption), nullptr) != 0)
            throw std::runtime_error("Couldn't initialize source IP anonymization!");
    }
}

boost::any DDP::CdnsExport::buffer_record(DnsRecord& record)
{
    CDNS::QueryResponse qr;
    CDNS::QueryResponseSignature qrs;
    bool qrs_filled = false;

    // Fill QueryResponse and QueryResponseSignature
    if (m_fields[static_cast<uint32_t>(CDNSField::TRANSACTION_ID)])
        qr.transaction_id = record.m_id;

    if (m_fields[static_cast<uint32_t>(CDNSField::TIME_OFFSET)])
        qr.time_offset = CDNS::Timestamp(record.m_timestamp.getSeconds(), record.m_timestamp.getMicroseconds());

    if (m_fields[static_cast<uint32_t>(CDNSField::QUERY_NAME)])
        qr.query_name_index = m_block->add_name_rdata(std::string(record.m_qname, strlen(record.m_qname) + 1));

    if (m_fields[static_cast<uint32_t>(CDNSField::CLIENT_HOPLIMIT)])
        qr.client_hoplimit = record.m_ttl;

    if (m_fields[static_cast<uint32_t>(CDNSField::QR_TRANSPORT_FLAGS)]) {
        uint8_t flags = 0;
        if (record.m_addr_family == DnsRecord::AddrFamily::IP6)
            flags |= CDNS::QueryResponseTransportFlagsMask::ip_address;

        switch(record.m_proto) {
            case(DnsRecord::Proto::UDP):
                flags |= CDNS::QueryResponseTransportFlagsMask::udp;
                break;
            case(DnsRecord::Proto::TCP):
                flags |= CDNS::QueryResponseTransportFlagsMask::tcp;
                break;
            default:
                break;
        }

        qrs.qr_transport_flags = static_cast<CDNS::QueryResponseTransportFlagsMask>(flags);
        qrs_filled = true;
    }

    if (m_fields[static_cast<uint32_t>(CDNSField::CLIENT_ADDRESS)]) {
        in6_addr* addr = record.client_address();
        if (record.m_addr_family == DnsRecord::AddrFamily::IP4) {
            *reinterpret_cast<uint32_t*>(addr) = scramble_ip4(*reinterpret_cast<uint32_t*>(addr), 0);
            qr.client_address_index = m_block->add_ip_address(std::string(reinterpret_cast<const char*>(addr), 4));
        }
        else if (record.m_addr_family == DnsRecord::AddrFamily::IP6) {
            scramble_ip6(addr, 0);
            qr.client_address_index = m_block->add_ip_address(std::string(reinterpret_cast<const char*>(addr), 16));
        }
    }

    if (m_fields[static_cast<uint32_t>(CDNSField::CLIENT_PORT)])
        qr.client_port = record.client_port();

    if (m_fields[static_cast<uint32_t>(CDNSField::SERVER_ADDRESS)]) {
        in6_addr* addr = record.server_address();
        if (record.m_addr_family == DnsRecord::AddrFamily::IP4)
            qrs.server_address_index = m_block->add_ip_address(std::string(reinterpret_cast<const char*>(addr), 4));
        else if (record.m_addr_family == DnsRecord::AddrFamily::IP6)
            qrs.server_address_index = m_block->add_ip_address(std::string(reinterpret_cast<const char*>(addr), 16));

        qrs_filled = true;
    }

    if (m_fields[static_cast<uint32_t>(CDNSField::SERVER_PORT)]) {
        qrs.server_port = record.server_port();
        qrs_filled = true;
    }

    if (m_fields[static_cast<uint32_t>(CDNSField::QUERY_SIZE)])
        qr.query_size = record.m_dns_len;

    if (m_fields[static_cast<uint32_t>(CDNSField::QR_DNS_FLAGS)]) {
        uint16_t flags = 0;

        if (record.m_aa)
            flags |= CDNS::DNSFlagsMask::response_aa;

        if (record.m_tc)
            flags |= CDNS::DNSFlagsMask::response_tc;

        if (record.m_rd)
            flags |= CDNS::DNSFlagsMask::query_rd;

        if (record.m_ra)
            flags |= CDNS::DNSFlagsMask::query_ra;

        if (record.m_ad)
            flags |= CDNS::DNSFlagsMask::query_ad;

        if (record.m_cd)
            flags |= CDNS::DNSFlagsMask::query_cd;

        if (record.m_z)
            flags |= CDNS::DNSFlagsMask::query_z;

        if (record.m_ednsDO)
            flags |= CDNS::DNSFlagsMask::query_do;

        qrs.qr_dns_flags = static_cast<CDNS::DNSFlagsMask>(flags);
        qrs_filled = true;
    }

    if (m_fields[static_cast<uint32_t>(CDNSField::QUERY_ANCOUNT)]) {
        qrs.query_ancount = record.m_ancount;
        qrs_filled = true;
    }

    if (m_fields[static_cast<uint32_t>(CDNSField::QUERY_ARCOUNT)]) {
        qrs.query_arcount = record.m_arcount;
        qrs_filled = true;
    }

    if (m_fields[static_cast<uint32_t>(CDNSField::QUERY_NSCOUNT)]) {
        qrs.query_nscount = record.m_nscount;
        qrs_filled = true;
    }

    if (m_fields[static_cast<uint32_t>(CDNSField::QUERY_QDCOUNT)]) {
        qrs.query_qdcount = record.m_qdcount;
        qrs_filled = true;
    }

    if (m_fields[static_cast<uint32_t>(CDNSField::QUERY_OPCODE)]) {
        qrs.query_opcode = record.m_opcode;
        qrs_filled = true;
    }

    if (m_fields[static_cast<uint32_t>(CDNSField::RESPONSE_RCODE)]) {
        qrs.response_rcode = record.m_rcode;
        qrs_filled = true;
    }

    if (m_fields[static_cast<uint32_t>(CDNSField::QUERY_CLASSTYPE)]) {
        CDNS::ClassType cltype;
        cltype.type = record.m_qtype;
        cltype.class_ = record.m_qclass;
        qrs.query_classtype_index = m_block->add_classtype(cltype);
        qrs_filled = true;
    }

    if (m_fields[static_cast<uint32_t>(CDNSField::QUERY_EDNS_VERSION)]) {
        qrs.query_edns_version = record.m_ednsVersion;
        qrs_filled = true;
    }

    if (m_fields[static_cast<uint32_t>(CDNSField::QUERY_EDNS_UDP_SIZE)]) {
        qrs.query_udp_size = record.m_ednsUDP;
        qrs_filled = true;
    }

    if (m_fields[static_cast<uint32_t>(CDNSField::QUERY_OPT_RDATA)] && record.m_req_ednsRdata) {
        qrs.query_opt_rdata_index = m_block->add_name_rdata(std::string(reinterpret_cast<char*>(record.m_req_ednsRdata), record.m_req_ednsRdata_size));
        qrs_filled = true;
    }

    if (m_fields[static_cast<uint32_t>(CDNSField::RESPONSE_ADDITIONAL_SECTIONS)] && record.m_resp_ednsRdata) {
        CDNS::QueryResponseExtended qre;
        std::vector<CDNS::index_t> list;
        CDNS::RR edns;
        CDNS::ClassType cltype;
        cltype.type = 41;
        cltype.class_ = record.m_ednsUDP;
        edns.name_index = m_block->add_name_rdata(std::string("\0", 1));
        edns.classtype_index = m_block->add_classtype(cltype);
        edns.rdata_index = m_block->add_name_rdata(std::string(reinterpret_cast<char*>(record.m_resp_ednsRdata), record.m_resp_ednsRdata_size));
        list.push_back(m_block->add_rr(edns));
        qre.additional_index = m_block->add_rr_list(list);
        qr.response_extended = qre;
    }

    if (m_fields[static_cast<uint32_t>(CDNSField::RESPONSE_SIZE)])
        qr.response_size = record.m_res_dns_len;

    // Add QueryResponseSignature to the QueryResponse
    if (qrs_filled)
        qr.qr_signature_index = m_block->add_qr_signature(qrs);

    // Add QueryResponse to Block and export Block if it's full
    if (m_block->add_question_response_record(qr)) {
        return rotate_export();
    }

    return nullptr;
}

void DDP::CdnsExport::write_leftovers(CdnsWriter& writer, Statistics& stats)
{
    if (m_block->get_item_count() == 0)
        return;

    writer.write(m_block);
    stats.exported_records += m_block->get_qr_count();
    m_block = std::make_shared<CDNS::CdnsBlock>(CDNS::CdnsBlock(m_parameters, 0));
}