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
     * Structure containing configuration for connecting to Kafka cluster
     */
    struct KafkaConfig
    {
        KafkaConfig() : brokers("127.0.0.1"),
                        topic("dns-probe"),
                        partition(""),
                        ca_location(""),
                        sec_protocol(KafkaSecurityProtocol::PLAINTEXT),
                        cert_location(""),
                        key_location(""),
                        key_passwd(""),
                        sasl_mechanism(KafkaSaslMechanism::PLAIN),
                        sasl_username(""),
                        sasl_password("") {}

        ConfigItem<std::string> brokers; //!< Comma separated list of Kafka brokers (host or host:port)
        ConfigItem<std::string> topic; //!< Kafka topic
        ConfigItem<std::string> partition; //!< Kafka message key to assign messages to specific partition

        ConfigItem<std::string> ca_location; //!< CA certificate for authentication of Kafka brokers's certificate
        ConfigItem<KafkaSecurityProtocol> sec_protocol; //!< Protocol used to communicate with Kafka brokesrs
        ConfigItem<std::string> cert_location; //!< Public key for authentication to Kafka cluster
        ConfigItem<std::string> key_location; //!< Private key for authentication to Kafka cluster
        ConfigItem<std::string> key_passwd; //!< Private key passphrase
        ConfigItem<KafkaSaslMechanism> sasl_mechanism; //!< SASL mechanism to use for authentication to Kafka brokers
        ConfigItem<std::string> sasl_username; //!< SASL username
        ConfigItem<std::string> sasl_password; //!< SASL password
    };

    /**
     * Structure containing configuration of the application
     */
    struct Config
    {
        Config() : interface_list(),
                   pcap_list(),
                   raw_pcap(false),
                   dnstap_socket_list(),
                   dnstap_socket_group(),
                   knot_socket_path("/tmp"),
                   knot_socket_count(0),
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
                   cdns_export_resp_rr(false),
                   export_location(ExportLocation::LOCAL),
                   export_ip("127.0.0.1"),
                   export_port(6378),
                   export_ca_cert(),
                   backup_export_ip(""),
                   backup_export_port(6378),
                   kafka_export(),
                   anonymize_ip(false),
                   ip_encryption(IpEncryption::AES),
                   ip_enc_key("key.cryptopant"),
                   export_stats(false),
                   stats_per_ip(false),
                   stats_timeout(300),
                   stats_location(ExportLocation::LOCAL),
                   stats_directory("."),
                   stats_ip("127.0.0.1"),
                   stats_port(6379),
                   stats_ca_cert(),
                   backup_stats_ip(""),
                   backup_stats_port(6379),
                   stats_kafka_export(),
                   moving_avg_window(300),
                   stats_fields(get_stats_bitmask()),
                   instance("default") { stats_kafka_export.topic = ConfigItem<std::string>("dns-probe-stats"); }

        ConfigItem<CList<std::string>> interface_list; //!< List of network interfaces to process traffic from
        ConfigItem<CList<std::string>> pcap_list; //!< List of PCAP files to process
        ConfigItem<bool> raw_pcap; //!< Defines if input PCAP files are without ethernet headers
        ConfigItem<CList<std::string>> dnstap_socket_list; //!< List of unix sockets to process dnstap data from
        ConfigItem<std::string> dnstap_socket_group; //!< User group under which to create dnstap sockets
        ConfigItem<std::string> knot_socket_path; //!< Path to directory in which to create Knot interface sockets
        ConfigItem<uint32_t> knot_socket_count; //!< Number of Knot interface sockets to create
        ConfigItem<std::string> log_file; //!< Log file for storing probe's logs
        ConfigItem<ThreadManager::MaskType> coremask; //!< Coremask used fo selecting cores where application will be running.
        ConfigItem<CList<Port_t>> dns_ports; //!< TCP/UDP port list used for identifying DNS traffic
        ConfigItem<CList<IPv4_prefix_t>> ipv4_allowlist; //!< List of allowed IPv4 addresses to process traffic from
        ConfigItem<CList<IPv4_prefix_t>> ipv4_denylist; //!< List of IPv4 addresses from which to NOT process traffic
        ConfigItem<CList<IPv6_prefix_t>> ipv6_allowlist; //!< List of allowed IPv6 addresses to process traffic from
        ConfigItem<CList<IPv6_prefix_t>> ipv6_denylist; //!< List of IPv6 addresses from which to NOT process traffic

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
        ConfigItem<bool> cdns_export_resp_rr; //!< Export full answer and additional RRs of response

        ConfigItem<ExportLocation> export_location; //!< Location for the exported DNS records
        ConfigItem<std::string> export_ip; //!< IP address for remote export of DNS records
        ConfigItem<uint16_t> export_port; //!< Transport protocol port for remote export of DNS records
        ConfigItem<std::string> export_ca_cert; //!< CA certificate for authentication of remote server's certificate
        ConfigItem<std::string> backup_export_ip; //!< Backup IP address for remote export of DNS records
        ConfigItem<uint16_t> backup_export_port; //!< Backup transport protocol port for remote export of DNS records
        KafkaConfig kafka_export; //!< Kafka configuration for export of DNS records

        ConfigItem<bool> anonymize_ip; //!< Enable client IP anonymization in exported data
        ConfigItem<IpEncryption> ip_encryption; //!< Encryption algorithm for IP anonymization
        ConfigItem<std::string> ip_enc_key; //!< File with encryption key for IP anonymization

        ConfigItem<bool> export_stats; //!< Enable export of run-time statistics
        ConfigItem<bool> stats_per_ip; //!< Enable export of 'queries*' run-time statistics per IP address
        ConfigItem<uint32_t> stats_timeout; //!< Export run-time statistics every 'stats_timeout' seconds
        ConfigItem<ExportLocation> stats_location; //!< Location for exported run-time statistics
        ConfigItem<std::string> stats_directory; //!< Directory for exported run-time statistics
        ConfigItem<std::string> stats_ip; //!< IP address for remote export of run-time statistics
        ConfigItem<uint16_t> stats_port; //!< Transport protocol port for remote export of run-time statistics
        ConfigItem<std::string> stats_ca_cert; //!< CA certificate for authentication of remote server's certificate
        ConfigItem<std::string> backup_stats_ip; //!< Backup IP address for remote export of run-time statistics
        ConfigItem<uint16_t> backup_stats_port; //!< Backup transport protocol port for remote export of run-time statistics
        KafkaConfig stats_kafka_export; //!< Kafka configuration for export of run-time statistics
        ConfigItem<uint16_t> moving_avg_window; //!< Time window for computing queries-per-second* statistics
        ConfigBitfield<StatsBits> stats_fields; //!< Indicates which statistics should be exported

        ConfigItem<std::string> instance; //!< Name of running dns-probe instance. "Default" by default.
    };
}
