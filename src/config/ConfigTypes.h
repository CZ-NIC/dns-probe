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

#include <sys/socket.h>
#include <string>
#include <array>
#include <unordered_set>
#include <unordered_map>

namespace DDP {
    template <typename T>
    using CList = std::unordered_set<T>;

    using Port_t = uint16_t;
    using IPv4_t = uint32_t;
    using IPv6_t = std::array<uint32_t, 4>;

    static constexpr uint8_t CdnsBits = 26; //!< Number of C-DNS fields options
    static constexpr uint64_t get_cdns_bitmask() {
        uint64_t bitmask = 0;
        for (unsigned i = 0; i < CdnsBits; i++) {
            bitmask |= 1 << i;
        }
        return bitmask;
    }

    /**
     * Available values for PCAP export config.
     */
    enum class PcapExportCfg : uint8_t {
        DISABLED = 0, //!< PCAP will not be generated.
        INVALID = 1, //!< PCAP will contain only non DNS packets.
        ALL = 2 //!< Full mirroring of traffic.
    };

    /**
     * Available export record formats
     */
    enum class ExportFormat : uint8_t {
        PARQUET, //!< Parquet export format.
        CDNS //!< CDMS export format.
    };

    /**
     * Available locations for exported DNS records
     */
    enum class ExportLocation : uint8_t {
        LOCAL, //!< Store exported data to local files
        REMOTE //!< Send exported data directly to remote location
    };

    /**
     * Specify bits positions in bit set for CDNS fields.
     */
    enum class CDNSField : uint32_t {
        TRANSACTION_ID = 0,
        TIME_OFFSET,
        QUERY_NAME,
        CLIENT_HOPLIMIT,
        QR_TRANSPORT_FLAGS,
        CLIENT_ADDRESS,
        CLIENT_PORT,
        SERVER_ADDRESS,
        SERVER_PORT,
        QUERY_SIZE,
        QR_DNS_FLAGS,
        QUERY_ANCOUNT,
        QUERY_ARCOUNT,
        QUERY_NSCOUNT,
        QUERY_QDCOUNT,
        QUERY_OPCODE,
        RESPONSE_RCODE,
        QUERY_CLASSTYPE,
        QUERY_EDNS_VERSION,
        QUERY_EDNS_UDP_SIZE,
        QUERY_OPT_RDATA,
        RESPONSE_ADDITIONAL_SECTIONS,
        RESPONSE_SIZE,
        ASN,
        COUNTRY_CODE,
        ROUND_TRIP_TIME
    };

    static const std::unordered_map<std::string, uint32_t> CdnsFieldsMap = {
        {"transaction_id",                  static_cast<uint32_t>(CDNSField::TRANSACTION_ID)},
        {"time_offset",                     static_cast<uint32_t>(CDNSField::TIME_OFFSET)},
        {"query_name",                      static_cast<uint32_t>(CDNSField::QUERY_NAME)},
        {"client_hoplimit",                 static_cast<uint32_t>(CDNSField::CLIENT_HOPLIMIT)},
        {"qr_transport_flags",              static_cast<uint32_t>(CDNSField::QR_TRANSPORT_FLAGS)},
        {"client_address",                  static_cast<uint32_t>(CDNSField::CLIENT_ADDRESS)},
        {"client_port",                     static_cast<uint32_t>(CDNSField::CLIENT_PORT)},
        {"server_address",                  static_cast<uint32_t>(CDNSField::SERVER_ADDRESS)},
        {"server_port",                     static_cast<uint32_t>(CDNSField::SERVER_PORT)},
        {"query_size",                      static_cast<uint32_t>(CDNSField::QUERY_SIZE)},
        {"qr_dns_flags",                    static_cast<uint32_t>(CDNSField::QR_DNS_FLAGS)},
        {"query_ancount",                   static_cast<uint32_t>(CDNSField::QUERY_ANCOUNT)},
        {"query_arcount",                   static_cast<uint32_t>(CDNSField::QUERY_ARCOUNT)},
        {"query_nscount",                   static_cast<uint32_t>(CDNSField::QUERY_NSCOUNT)},
        {"query_qdcount",                   static_cast<uint32_t>(CDNSField::QUERY_QDCOUNT)},
        {"response_rcode",                  static_cast<uint32_t>(CDNSField::RESPONSE_RCODE)},
        {"query_classtype",                 static_cast<uint32_t>(CDNSField::QUERY_CLASSTYPE)},
        {"query_edns_version",              static_cast<uint32_t>(CDNSField::QUERY_EDNS_VERSION)},
        {"query_edns_udp_size",             static_cast<uint32_t>(CDNSField::QUERY_EDNS_UDP_SIZE)},
        {"query_opt_data",                  static_cast<uint32_t>(CDNSField::QUERY_OPT_RDATA)},
        {"response_additional_sections",    static_cast<uint32_t>(CDNSField::RESPONSE_ADDITIONAL_SECTIONS)},
        {"response_size",                   static_cast<uint32_t>(CDNSField::RESPONSE_SIZE)},
        {"asn",                             static_cast<uint32_t>(CDNSField::ASN)},
        {"country_code",                    static_cast<uint32_t>(CDNSField::COUNTRY_CODE)},
        {"round_trip_time",                 static_cast<uint32_t>(CDNSField::ROUND_TRIP_TIME)},
    };

    /**
     * Encryption algorithm used for optional client IP anonymization
     */
    enum class IpEncryption : uint8_t {
        NONE = 0x00,
        MD5 = 0x01,
        BLOWFISH = 0x02,
        AES = 0x03,
        SHA1 = 0x04
    };
}