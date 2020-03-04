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

#include <string>

namespace DDP {
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
        RESPONSE_SIZE
    };
}