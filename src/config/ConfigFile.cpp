/*
 *  Copyright (C) 2020 CZ.NIC, z.s.p.o.
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

#include <stdexcept>
#include <utility>
#include <algorithm>
#include <bitset>
#include <yaml-cpp/yaml.h>

#include "ConfigItem.h"
#include "ConfigFile.h"
#include "utils/Logger.h"

void DDP::ConfigFile::load_configuration(Config& cfg, std::string conf_file, std::string instance)
{
    Config loaded_cfg;

    try {
        YAML::Node config = YAML::LoadFile(conf_file);

        // Always load default configuration first and then load changes for given instance if present
        if (config["default"])
            load_instance(loaded_cfg, config["default"]);

        if (instance != "default" && config[instance])
            load_instance(loaded_cfg, config[instance]);

        cfg = loaded_cfg;
    }
    catch (std::exception& e) {
        Logger("YAML").warning() << "Couldn't load configuration file " << conf_file
                           << " - " << e.what() << ". Using default configuration.";
    }
}

void DDP::ConfigFile::load_instance(Config& cfg, YAML::Node node)
{
    if (node["interface-list"] && node["interface-list"].IsSequence()) {
        for (auto item : node["interface-list"]) {
            cfg.interface_list.add_value(item.as<std::string>());
        }
    }

    if (node["pcap-list"] && node["pcap-list"].IsSequence()) {
        for (auto item : node["pcap-list"]) {
            cfg.pcap_list.add_value(item.as<std::string>());
        }
    }

    if (node["raw-pcap"] && node["raw-pcap"].IsScalar())
        cfg.raw_pcap.add_value(node["raw-pcap"].as<bool>());

    if (node["dnstap-socket-list"] && node["dnstap-socket-list"].IsSequence()) {
        for (auto item : node["dnstap-socket-list"]) {
            cfg.dnstap_socket_list.add_value(item.as<std::string>());
        }
    }

    if (node["dnstap-socket-group"] && node["dnstap-socket-group"].IsScalar())
        cfg.dnstap_socket_group.add_value(node["dnstap-socket-group"].as<std::string>());

    if (node["knot-socket-path"] && node["knot-socket-path"].IsScalar())
        cfg.knot_socket_path.add_value(node["knot-socket-path"].as<std::string>());

    if (node["knot-socket-count"] && node["knot-socket-count"].IsScalar())
        cfg.knot_socket_count.add_value(node["knot-socket-count"].as<uint32_t>());

    if (node["log-file"] && node["log-file"].IsScalar())
        cfg.log_file.add_value(node["log-file"].as<std::string>());

    if (node["coremask"] && node["coremask"].IsScalar())
        cfg.coremask.add_value(node["coremask"].as<uint64_t>());

    if (node["dns-ports"] && node["dns-ports"].IsSequence()) {
        for (auto item : node["dns-ports"]) {
            cfg.dns_ports.add_value(item.as<Port_t>());
        }
    }

    if (node["ipv4-allowlist"] && node["ipv4-allowlist"].IsSequence()) {
        for (auto item : node["ipv4-allowlist"]) {
            cfg.ipv4_allowlist.add_value(item.as<std::string>());
        }
    }

    if (node["ipv4-denylist"] && node["ipv4-denylist"].IsSequence()) {
        for (auto item : node["ipv4-denylist"]) {
            cfg.ipv4_denylist.add_value(item.as<std::string>());
        }
    }

    if (node["ipv6-allowlist"] && node["ipv6-allowlist"].IsSequence()) {
        for (auto item : node["ipv6-allowlist"]) {
            cfg.ipv6_allowlist.add_value(item.as<std::string>());
        }
    }

    if (node["ipv6-denylist"] && node["ipv6-denylist"].IsSequence()) {
        for (auto item : node["ipv6-denylist"]) {
            cfg.ipv6_denylist.add_value(item.as<std::string>());
        }
    }

    // Export configuration
    if (node["export"]["location"] && node["export"]["location"].IsScalar())
        cfg.export_location.add_value(node["export"]["location"].as<std::string>());


    if (node["export"]["export-dir"] && node["export"]["export-dir"].IsScalar())
        cfg.target_directory.add_value(node["export"]["export-dir"].as<std::string>());

    if (node["export"]["remote-ip-address"] && node["export"]["remote-ip-address"].IsScalar())
        cfg.export_ip.add_value(node["export"]["remote-ip-address"].as<std::string>());

    if (node["export"]["backup-remote-ip-address"] && node["export"]["backup-remote-ip-address"].IsScalar())
        cfg.backup_export_ip.add_value(node["export"]["backup-remote-ip-address"].as<std::string>());

    if (node["export"]["remote-port"] && node["export"]["remote-port"].IsScalar())
        cfg.export_port.add_value(node["export"]["remote-port"].as<uint16_t>());

    if (node["export"]["backup-remote-port"] && node["export"]["backup-remote-port"].IsScalar())
        cfg.backup_export_port.add_value(node["export"]["backup-remote-port"].as<uint16_t>());

    if (node["export"]["remote-ca-cert"] && node["export"]["remote-ca-cert"].IsScalar())
        cfg.export_ca_cert.add_value(node["export"]["remote-ca-cert"].as<std::string>());

    if (node["export"]["kafka-brokers"] && node["export"]["kafka-brokers"].IsScalar())
        cfg.kafka_export.brokers.add_value(node["export"]["kafka-brokers"].as<std::string>());

    if (node["export"]["kafka-address-family"] && node["export"]["kafka-address-family"].IsScalar())
        cfg.kafka_export.address_family.add_value(node["export"]["kafka-address-family"].as<std::string>());

    if (node["export"]["kafka-topic"] && node["export"]["kafka-topic"].IsScalar())
        cfg.kafka_export.topic.add_value(node["export"]["kafka-topic"].as<std::string>());

    if (node["export"]["kafka-partition"] && node["export"]["kafka-partition"].IsScalar())
        cfg.kafka_export.partition.add_value(node["export"]["kafka-partition"].as<std::string>());

    if (node["export"]["kafka-ca-location"] && node["export"]["kafka-ca-location"].IsScalar())
        cfg.kafka_export.ca_location.add_value(node["export"]["kafka-ca-location"].as<std::string>());

    if (node["export"]["kafka-security-protocol"] && node["export"]["kafka-security-protocol"].IsScalar())
        cfg.kafka_export.sec_protocol.add_value(node["export"]["kafka-security-protocol"].as<std::string>());

    if (node["export"]["kafka-cert-location"] && node["export"]["kafka-cert-location"].IsScalar())
        cfg.kafka_export.cert_location.add_value(node["export"]["kafka-cert-location"].as<std::string>());

    if (node["export"]["kafka-key-location"] && node["export"]["kafka-key-location"].IsScalar())
        cfg.kafka_export.key_location.add_value(node["export"]["kafka-key-location"].as<std::string>());

    if (node["export"]["kafka-key-password"] && node["export"]["kafka-key-password"].IsScalar())
        cfg.kafka_export.key_passwd.add_value(node["export"]["kafka-key-password"].as<std::string>());

    if (node["export"]["kafka-sasl-mechanism"] && node["export"]["kafka-sasl-mechanism"].IsScalar())
        cfg.kafka_export.sasl_mechanism.add_value(node["export"]["kafka-sasl-mechanism"].as<std::string>());

    if (node["export"]["kafka-sasl-username"] && node["export"]["kafka-sasl-username"].IsScalar())
        cfg.kafka_export.sasl_username.add_value(node["export"]["kafka-sasl-username"].as<std::string>());

    if (node["export"]["kafka-sasl-password"] && node["export"]["kafka-sasl-password"].IsScalar())
        cfg.kafka_export.sasl_password.add_value(node["export"]["kafka-sasl-password"].as<std::string>());

    if (node["export"]["export-format"] && node["export"]["export-format"].IsScalar())
        cfg.export_format.add_value(node["export"]["export-format"].as<std::string>());

    if (node["export"]["cdns-fields"] && node["export"]["cdns-fields"].IsSequence()) {
        std::bitset<CdnsBits> fields;
        for (auto item : node["export"]["cdns-fields"]) {
            std::string field = item.as<std::string>();
            std::transform(field.begin(), field.end(), field.begin(), tolower);
            auto found = CdnsFieldsMap.find(field);
            if (found != CdnsFieldsMap.end())
                fields.set(found->second);
        }

        cfg.cdns_fields.add_value(fields);
    }

    if (node["export"]["cdns-records-per-block"] && node["export"]["cdns-records-per-block"].IsScalar())
        cfg.cdns_records_per_block.add_value(node["export"]["cdns-records-per-block"].as<uint64_t>());

    if (node["export"]["cdns-blocks-per-file"] && node["export"]["cdns-blocks-per-file"].IsScalar())
        cfg.cdns_blocks_per_file.add_value(node["export"]["cdns-blocks-per-file"].as<uint64_t>());

    if (node["export"]["cdns-export-response-rr"] && node["export"]["cdns-export-response-rr"].IsScalar())
        cfg.cdns_export_resp_rr.add_value(node["export"]["cdns-export-response-rr"].as<bool>());

    if (node["export"]["parquet-records-per-file"] && node["export"]["parquet-records-per-file"].IsScalar())
        cfg.parquet_records.add_value(node["export"]["parquet-records-per-file"].as<uint64_t>());

    if (node["export"]["file-name-prefix"] && node["export"]["file-name-prefix"].IsScalar())
        cfg.file_prefix.add_value(node["export"]["file-name-prefix"].as<std::string>());

    if (node["export"]["timeout"] && node["export"]["timeout"].IsScalar())
        cfg.file_rot_timeout.add_value(node["export"]["timeout"].as<uint32_t>());

    if (node["export"]["file-size-limit"] && node["export"]["file-size-limit"].IsScalar())
        cfg.file_rot_size.add_value(node["export"]["file-size-limit"].as<uint64_t>());

    if (node["export"]["file-compression"] && node["export"]["file-compression"].IsScalar())
        cfg.file_compression.add_value(node["export"]["file-compression"].as<bool>());

    if (node["export"]["pcap-export"] && node["export"]["pcap-export"].IsScalar())
        cfg.pcap_export.add_value(node["export"]["pcap-export"].as<std::string>());

    if (node["export"]["country-maxmind-db"] && node["export"]["country-maxmind-db"].IsScalar())
        cfg.country_db.add_value(node["export"]["country-maxmind-db"].as<std::string>());

    if (node["export"]["asn-maxmind-db"] && node["export"]["asn-maxmind-db"].IsScalar())
        cfg.asn_db.add_value(node["export"]["asn-maxmind-db"].as<std::string>());

    // IP anonymization configuration
    if (node["ip-anonymization"]["anonymize-ip"] && node["ip-anonymization"]["anonymize-ip"].IsScalar())
        cfg.anonymize_ip.add_value(node["ip-anonymization"]["anonymize-ip"].as<bool>());

    if (node["ip-anonymization"]["encryption"] && node["ip-anonymization"]["encryption"].IsScalar())
        cfg.ip_encryption.add_value(node["ip-anonymization"]["encryption"].as<std::string>());

    if (node["ip-anonymization"]["key-path"] && node["ip-anonymization"]["key-path"].IsScalar())
        cfg.ip_enc_key.add_value(node["ip-anonymization"]["key-path"].as<std::string>());

    // Transaction table configuration
    if (node["transaction-table"]["max-transactions"] && node["transaction-table"]["max-transactions"].IsScalar())
        cfg.tt_size.add_value(node["transaction-table"]["max-transactions"].as<uint32_t>());

    if (node["transaction-table"]["query-timeout"] && node["transaction-table"]["query-timeout"].IsScalar())
        cfg.tt_timeout.add_value(node["transaction-table"]["query-timeout"].as<uint64_t>());

    if (node["transaction-table"]["match-qname"] && node["transaction-table"]["match-qname"].IsScalar())
        cfg.match_qname.add_value(node["transaction-table"]["match-qname"].as<bool>());

    // TCP table configuration
    if (node["tcp-table"]["concurrent-connections"] && node["tcp-table"]["concurrent-connections"].IsScalar())
        cfg.tcp_ct_size.add_value(node["tcp-table"]["concurrent-connections"].as<uint32_t>());

    if (node["tcp-table"]["timeout"] && node["tcp-table"]["timeout"].IsScalar())
        cfg.tcp_ct_timeout.add_value(node["tcp-table"]["timeout"].as<uint64_t>());

    // Statistics export configuration
    if (node["statistics"]["export-stats"] && node["statistics"]["export-stats"].IsScalar())
        cfg.export_stats.add_value(node["statistics"]["export-stats"].as<bool>());

    if (node["statistics"]["stats-per-ip"] && node["statistics"]["stats-per-ip"].IsScalar())
        cfg.stats_per_ip.add_value(node["statistics"]["stats-per-ip"].as<bool>());

    if (node["statistics"]["stats-timeout"] && node["statistics"]["stats-timeout"].IsScalar())
        cfg.stats_timeout.add_value(node["statistics"]["stats-timeout"].as<uint32_t>());

    if (node["statistics"]["location"] && node["statistics"]["location"].IsScalar())
        cfg.stats_location.add_value(node["statistics"]["location"].as<std::string>());

    if (node["statistics"]["export-dir"] && node["statistics"]["export-dir"].IsScalar())
        cfg.stats_directory.add_value(node["statistics"]["export-dir"].as<std::string>());

    if (node["statistics"]["remote-ip"] && node["statistics"]["remote-ip"].IsScalar())
        cfg.stats_ip.add_value(node["statistics"]["remote-ip"].as<std::string>());

    if (node["statistics"]["backup-remote-ip"] && node["statistics"]["backup-remote-ip"].IsScalar())
        cfg.backup_stats_ip.add_value(node["statistics"]["backup-remote-ip"].as<std::string>());

    if (node["statistics"]["remote-port"] && node["statistics"]["remote-port"].IsScalar())
        cfg.stats_port.add_value(node["statistics"]["remote-port"].as<uint16_t>());

    if (node["statistics"]["backup-remote-port"] && node["statistics"]["backup-remote-port"].IsScalar())
        cfg.backup_stats_port.add_value(node["statistics"]["backup-remote-port"].as<uint16_t>());

    if (node["statistics"]["remote-ca-cert"] && node["statistics"]["remote-ca-cert"].IsScalar())
        cfg.stats_ca_cert.add_value(node["statistics"]["remote-ca-cert"].as<std::string>());

    if (node["statistics"]["kafka-brokers"] && node["statistics"]["kafka-brokers"].IsScalar())
        cfg.stats_kafka_export.brokers.add_value(node["statistics"]["kafka-brokers"].as<std::string>());

    if (node["statistics"]["kafka-topic"] && node["statistics"]["kafka-topic"].IsScalar())
        cfg.stats_kafka_export.topic.add_value(node["statistics"]["kafka-topic"].as<std::string>());

    if (node["statistics"]["kafka-address-family"] && node["statistics"]["kafka-address-family"].IsScalar())
        cfg.stats_kafka_export.address_family.add_value(node["statistics"]["kafka-address-family"].as<std::string>());

    if (node["statistics"]["kafka-partition"] && node["statistics"]["kafka-partition"].IsScalar())
        cfg.stats_kafka_export.partition.add_value(node["statistics"]["kafka-partition"].as<std::string>());

    if (node["statistics"]["kafka-ca-location"] && node["statistics"]["kafka-ca-location"].IsScalar())
        cfg.stats_kafka_export.ca_location.add_value(node["statistics"]["kafka-ca-location"].as<std::string>());

    if (node["statistics"]["kafka-security-protocol"] && node["statistics"]["kafka-security-protocol"].IsScalar())
        cfg.stats_kafka_export.sec_protocol.add_value(node["statistics"]["kafka-security-protocol"].as<std::string>());

    if (node["statistics"]["kafka-cert-location"] && node["statistics"]["kafka-cert-location"].IsScalar())
        cfg.stats_kafka_export.cert_location.add_value(node["statistics"]["kafka-cert-location"].as<std::string>());

    if (node["statistics"]["kafka-key-location"] && node["statistics"]["kafka-key-location"].IsScalar())
        cfg.stats_kafka_export.key_location.add_value(node["statistics"]["kafka-key-location"].as<std::string>());

    if (node["statistics"]["kafka-key-password"] && node["statistics"]["kafka-key-password"].IsScalar())
        cfg.stats_kafka_export.key_passwd.add_value(node["statistics"]["kafka-key-password"].as<std::string>());

    if (node["statistics"]["kafka-sasl-mechanism"] && node["statistics"]["kafka-sasl-mechanism"].IsScalar())
        cfg.stats_kafka_export.sasl_mechanism.add_value(node["statistics"]["kafka-sasl-mechanism"].as<std::string>());

    if (node["statistics"]["kafka-sasl-username"] && node["statistics"]["kafka-sasl-username"].IsScalar())
        cfg.stats_kafka_export.sasl_username.add_value(node["statistics"]["kafka-sasl-username"].as<std::string>());

    if (node["statistics"]["kafka-sasl-password"] && node["statistics"]["kafka-sasl-password"].IsScalar())
        cfg.stats_kafka_export.sasl_password.add_value(node["statistics"]["kafka-sasl-password"].as<std::string>());

    if (node["statistics"]["moving-avg-window"] && node["statistics"]["moving-avg-window"].IsScalar())
        cfg.moving_avg_window.add_value(node["statistics"]["moving-avg-window"].as<uint16_t>());

    if (node["statistics"]["stats-fields"] && node["statistics"]["stats-fields"].IsSequence()) {
        std::bitset<StatsBits> fields;
        for (auto item : node["statistics"]["stats-fields"]) {
            std::string field = item.as<std::string>();
            std::transform(field.begin(), field.end(), field.begin(), tolower);
            auto found = StatsFieldsMap.find(field);
            if (found != StatsFieldsMap.end())
                fields.set(found->second);
        }

        cfg.stats_fields.add_value(fields);
    }
}
