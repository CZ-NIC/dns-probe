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

#include <exception>
#include <limits>
#include <string>
#include <vector>
#include <iostream>

#include <cstdint>
#include <cstring>
#include <arpa/inet.h> // in6_addr
#include <sys/socket.h> // AF_INET and AF_INET6

#include "utils/Time.h"
#include "utils/CRC32.h"

namespace DDP {
    /**
    * @brief Maximum parseable length of QNAME
    */
    static constexpr uint16_t QNAME_BUFFER_SIZE = 256;

    /**
     * @brief QTYPE code for zone transfer
     */
    static constexpr uint8_t DNS_QTYPE_AXFR = 252;

    /**
     * @brief Size of standard UUID's textual representation
     */
    static constexpr uint8_t UUID_SIZE = 36;

    /**
     * @brief Stores data of one DNS Resource Record
     */
    struct DnsRR
    {
        char dname[QNAME_BUFFER_SIZE]; // wire format
        uint16_t type;
        uint16_t class_;
        uint32_t ttl;
        uint16_t rdlength;
        uint8_t* rdata;
    };

    static constexpr uint32_t DNS_RR_STRUCT_SIZE = sizeof(DnsRR);

    /**
     * @brief Stores parsed data of a DNS packet
     * (request or response)
     */
    struct DnsRecord
    {
        /**
         * @brief IPv4 or IPv6 address families
         */
        enum class AddrFamily : uint8_t
        {
            IP4 = AF_INET,
            IP6 = AF_INET6,
            INVALID = 0,
        };

        /**
         * @brief Protocol numbers of supported protocols
         * (see https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
         */
        enum class Proto : uint8_t
        {
            UDP = 17,
            TCP = 6,
            INVALID = 0,
        };

        /**
         * @brief Specify index of client addr and port in array
         */
        enum class ClientIndex : uint8_t
        {
            CLIENT_LOW,
            CLIENT_HIGH,
        };

        DnsRecord() : m_hash(0),
                      m_request(false),
                      m_response(false),
                      m_last_soa(false),
                      m_addr(),
                      m_port(),
                      m_id(0),
                      m_proto(Proto::INVALID),
                      m_addr_family(AddrFamily::INVALID),
                      m_timestamp(),
                      m_tcp_rtt(-1),
                      m_client_index_ip(ClientIndex::CLIENT_LOW),
                      m_client_index_port(ClientIndex::CLIENT_LOW),
                      m_len(0),
                      m_dns_len(0),
                      m_res_len(0),
                      m_res_dns_len(0),
                      m_ttl(0),
                      m_udp_sum(0),
                      m_opcode(0),
                      m_aa(0),
                      m_tc(0),
                      m_rd(0),
                      m_ra(0),
                      m_ad(0),
                      m_cd(0),
                      m_z(0),
                      m_rcode(0),
                      m_qdcount(0),
                      m_ancount(0),
                      m_nscount(0),
                      m_arcount(0),
                      m_qname(),
                      m_qtype(0),
                      m_qclass(0),
                      m_uid(),
                      m_ednsUDP(0),
                      m_ednsVersion(0),
                      m_ednsDO(0),
                      m_req_ednsRdata(nullptr),
                      m_req_ednsRdata_size(0),
                      m_resp_ednsRdata(nullptr),
                      m_resp_ednsRdata_size(0),
                      m_resp_answer_rrs(),
                      m_resp_authority_rrs(),
                      m_resp_additional_rrs()
        {
        }

        /**
         * @return Returns record's hash
         */
        uint32_t hash() const
        {
            return m_hash;
        }

        void do_hash()
        {
            m_hash = CRC32::hash(reinterpret_cast<const char*>(m_addr), reinterpret_cast<const char*>(m_addr) +
            (sizeof(m_addr) + sizeof(m_port) + sizeof(m_id) + sizeof(m_proto) + sizeof(m_addr_family)));
        }

        uint32_t do_tcp_hash()
        {
            return CRC32::hash(reinterpret_cast<const char*>(m_addr),
                reinterpret_cast<const char*>(m_addr) + (sizeof(m_addr) + sizeof(m_port)));
        }

        bool match(DnsRecord& m, bool match_qname) const
        {
            if (match_qname) {
                return m_hash == m.m_hash && !strcmp(m_qname, m.m_qname);
            }
            else {
                return m_hash == m.m_hash;
            }
        }

        in6_addr* client_address()
        {
            return &m_addr[static_cast<int>(m_client_index_ip)];
        }

        in6_addr* server_address()
        {
            return &m_addr[!static_cast<int>(m_client_index_ip)];
        }

        uint16_t client_port()
        {
            return m_port[static_cast<int>(m_client_index_port)];
        }

        uint16_t server_port()
        {
            return m_port[!static_cast<int>(m_client_index_port)];
        }

        /**
         * @brief Parse domainname field (last two domains) from qname and write dots instead of
         * label length bytes in the whole qname
         * @param result Pointer to pointer where start of domainname in qname will be stored after return
         * @param labels Is filled with the number of labels in qname
         * @return Size of domainname
         */
        int domain_name(char** result, uint8_t* labels)
        {
            char* second = nullptr;
            int size = 0;
            *labels = 0;
            auto label_len = static_cast<uint8_t>(m_qname[0]);
            auto pos = static_cast<uint64_t>(label_len + 1);

            while (label_len != 0) {
                size += label_len;
                (*labels)++;
                label_len = m_qname[pos];
                if (label_len != 0) {
                    m_qname[pos] = '.';
                    *result = second;
                    second = (m_qname + pos);
                    size++;
                }
                pos += label_len + 1;
            }

            if (*result != nullptr) {
                *result += 1;
                return (size - (*result - m_qname) + 1);
            }
            else {
                *result = m_qname + 1;
                return size;
            }
        }

        // Hash
        uint32_t m_hash;

        // DNS record type
        bool m_request;
        bool m_response;
        bool m_last_soa;

        //Netflow data
        struct {
            in6_addr m_addr[2];
            uint16_t m_port[2];
            uint16_t m_id;
            Proto m_proto;
            AddrFamily m_addr_family;
        };

        // Timestamp extracted from mbuf
        Time m_timestamp;
        int64_t m_tcp_rtt; // microsecond precision, less than 0 means no rtt

        ClientIndex m_client_index_ip;
        ClientIndex m_client_index_port;

        // Sizes
        size_t m_len;
        size_t m_dns_len;
        size_t m_res_len;
        size_t m_res_dns_len;


        uint8_t m_ttl;
        uint16_t m_udp_sum;

        // DNS header
        uint8_t m_opcode;
        uint8_t m_aa;
        uint8_t m_tc;
        uint8_t m_rd;
        uint8_t m_ra;
        uint8_t m_ad;
        uint8_t m_cd;
        uint8_t m_z;
        uint16_t m_rcode;
        uint16_t m_qdcount;
        uint32_t m_ancount;
        uint16_t m_nscount;
        uint16_t m_arcount;

        // DNS question section
        char m_qname[QNAME_BUFFER_SIZE]; // wire format
        uint16_t m_qtype;
        uint16_t m_qclass;

        // User ID (only from dnstap, UUID)
        char m_uid[UUID_SIZE];

        // EDNS properties
        uint16_t m_ednsUDP; // EDNS header
        uint8_t m_ednsVersion; // EDNS header
        uint8_t m_ednsDO; // EDNS header

        uint8_t* m_req_ednsRdata;
        uint64_t m_req_ednsRdata_size;
        uint8_t* m_resp_ednsRdata;
        uint64_t m_resp_ednsRdata_size;

        // Optional list of response RRs from Answer and Additional sections
        std::vector<DnsRR*> m_resp_answer_rrs;
        std::vector<DnsRR*> m_resp_authority_rrs;
        std::vector<DnsRR*> m_resp_additional_rrs;
    };

}
