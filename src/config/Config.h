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


#include <string>
#include <forward_list>
#include <functional>

#include "ConfigTypes.h"
#include "ConfigItem.h"

namespace DDP {
    /**
     * Structure containing configuration of the application
     */
    struct Config
    {
        Config() : interface_list(),
                   pcap_list(),
                   raw_pcap(false),
                   dnstap_socket_list(),
                   log_file(),
                   coremask(0x7),
                   dns_ports({53}),
                   ipv4_allowlist(),
                   ipv4_denylist(),
                   ipv6_allowlist(),
                   ipv6_denylist(),
                   tt_size(1048576),
                   tt_timeout(1000),
                   match_qname(false),
                   tcp_ct_size(131072),
                   tcp_ct_timeout(60000),
                   target_directory("."),
                   file_prefix("dns_"),
                   file_rot_timeout(0),
                   file_rot_size(0),
                   file_compression(true),
                   pcap_export(PcapExportCfg::DISABLED),
                   country_db(),
                   asn_db(),
                   export_format(ExportFormat::PARQUET),
                   parquet_records(5000000),
                   cdns_fields(get_cdns_bitmask()),
                   cdns_records_per_block(10000),
                   cdns_blocks_per_file(0),
                   export_location(ExportLocation::LOCAL),
                   export_ip("127.0.0.1"),
                   export_port(6378),
                   export_ca_cert(),
                   anonymize_ip(false),
                   ip_encryption(IpEncryption::AES),
                   ip_enc_key("key.cryptopant") {}

        ConfigItem<CList<std::string>> interface_list; //!< List of network interfaces to process traffic from
        ConfigItem<CList<std::string>> pcap_list; //!< List of PCAP files to process
        ConfigItem<bool> raw_pcap; //!< Defines if input PCAP files are without ethernet headers
        ConfigItem<CList<std::string>> dnstap_socket_list; //!< List of unix sockets to process dnstap data from
        ConfigItem<std::string> log_file; //!< Log file for storing probe's logs
        ConfigItem<ThreadManager::MaskType> coremask; //!< Coremask used fo selecting cores where application will be running.
        ConfigItem<CList<Port_t>> dns_ports; //!< TCP/UDP port list used for identifying DNS traffic
        ConfigItem<CList<IPv4_t>> ipv4_allowlist; //!< List of allowed IPv4 addresses to process traffic from
        ConfigItem<CList<IPv4_t>> ipv4_denylist; //!< List of IPv4 addresses from which to NOT process traffic
        ConfigItem<CList<IPv6_t>> ipv6_allowlist; //!< List of allowed IPv6 addresses to process traffic from
        ConfigItem<CList<IPv6_t>> ipv6_denylist; //!< List of IPv6 addresses from which to NOT process traffic

        ConfigItem<uint32_t> tt_size; //!< Number of items in the transaction table
        ConfigItem<uint64_t> tt_timeout; //!< Timeout for orphaned items transaction table in milliseconds
        ConfigItem<bool> match_qname; //!< Enable matching qnames in transaction table

        ConfigItem<uint32_t> tcp_ct_size; //!< Maximal concurrent tracking TCP connections
        ConfigItem<uint64_t> tcp_ct_timeout; //!< Timeout of TCP connection

        ConfigItem<std::string> target_directory; //!< Directory for exported data
        ConfigItem<std::string> file_prefix; //!< Exported file prefix name
        ConfigItem<uint32_t> file_rot_timeout; //!< Exported file rotation timeout in seconds
        ConfigItem<uint64_t> file_rot_size; //!< Exported file size limit in MB
        ConfigItem<bool> file_compression; //!< Enable GZIP compression for exported files
        ConfigItem<PcapExportCfg> pcap_export; //!< Define what will be in exported PCAPs
        ConfigItem<std::string> country_db; //!< Path to Maxmind Country database
        ConfigItem<std::string> asn_db; //!< Path to Maxmind ASN database

        ConfigItem<ExportFormat> export_format; //!< Specify export format
        ConfigItem<uint64_t> parquet_records; //!< Number of records in parquet file
        ConfigBitfield<CdnsBits> cdns_fields; //!< Fields which will be part of CDNS file
        ConfigItem<uint64_t> cdns_records_per_block; //!< Number of records in one block in CDNS file
        ConfigItem<uint64_t> cdns_blocks_per_file; //!< Number of blocks in CDNS file

        ConfigItem<ExportLocation> export_location; //!< Location for the exported DNS records
        ConfigItem<std::string> export_ip; //!< IP address for remote export of DNS records
        ConfigItem<uint16_t> export_port; //!< Transport protocol port for remote export of DNS records
        ConfigItem<std::string> export_ca_cert; //!< CA certificate for authentication of remote server's certificate

        ConfigItem<bool> anonymize_ip; //!< Enable client IP anonymization in exported data
        ConfigItem<IpEncryption> ip_encryption; //!< Encryption algorithm for IP anonymization
        ConfigItem<std::string> ip_enc_key; //!< File with encryption key for IP anonymization
    };
}
