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
    try {
        YAML::Node config = YAML::LoadFile(conf_file);

        // Always load default configuration first and then load changes for given instance if present
        if (config["default"])
            load_instance(cfg, config["default"]);

        if (instance != "default" && config[instance])
            load_instance(cfg, config[instance]);
    }
    catch (std::exception& e) {
        Logger("YAML").warning() << "Couldn't load configuration file " << conf_file
                           << " - " << e.what() << ". Using default configuration.";
    }
}

void DDP::ConfigFile::load_instance(Config& cfg, YAML::Node node)
{
    if (node["interface-list"]) {
        for (auto item : node["interface-list"]) {
            cfg.interface_list.add_value(item.as<std::string>());
        }
    }

    if (node["pcap-list"]) {
        for (auto item : node["pcap-list"]) {
            cfg.pcap_list.add_value(item.as<std::string>());
        }
    }

    if (node["raw-pcap"])
        cfg.raw_pcap.add_value(node["raw-pcap"].as<bool>());

    if (node["log-file"])
        cfg.log_file.add_value(node["log-file"].as<std::string>());

    if (node["coremask"])
        cfg.coremask.add_value(node["coremask"].as<uint64_t>());

    if (node["dns-ports"]) {
        for (auto item : node["dns-ports"]) {
            cfg.dns_ports.add_value(item.as<Port_t>());
        }
    }

    if (node["ipv4-allowlist"]) {
        for (auto item : node["ipv4-allowlist"]) {
            cfg.ipv4_allowlist.add_value(item.as<std::string>());
        }
    }

    if (node["ipv4-denylist"]) {
        for (auto item : node["ipv4-denylist"]) {
            cfg.ipv4_denylist.add_value(item.as<std::string>());
        }
    }

    if (node["ipv6-allowlist"]) {
        for (auto item : node["ipv6-allowlist"]) {
            cfg.ipv6_allowlist.add_value(item.as<std::string>());
        }
    }

    if (node["ipv6-denylist"]) {
        for (auto item : node["ipv6-denylist"]) {
            cfg.ipv6_denylist.add_value(item.as<std::string>());
        }
    }

    if (node["export"]["location"])
        cfg.export_location.add_value(node["export"]["location"].as<std::string>());


    if (node["export"]["export-dir"])
        cfg.target_directory.add_value(node["export"]["export-dir"].as<std::string>());

    if (node["export"]["remote-ip-address"])
        cfg.export_ip.add_value(node["export"]["remote-ip-address"].as<std::string>());

    if (node["export"]["remote-port"])
        cfg.export_port.add_value(node["export"]["remote-port"].as<uint16_t>());

    if (node["export"]["remote-ca-cert"])
        cfg.export_ca_cert.add_value(node["export"]["remote-ca-cert"].as<std::string>());

    if (node["export"]["export-format"])
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

    if (node["export"]["cdns-records-per-block"])
        cfg.cdns_records_per_block.add_value(node["export"]["cdns-records-per-block"].as<uint64_t>());

    if (node["export"]["cdns-blocks-per-file"])
        cfg.cdns_blocks_per_file.add_value(node["export"]["cdns-blocks-per-file"].as<uint64_t>());

    if (node["export"]["parquet-records-per-file"])
        cfg.parquet_records.add_value(node["export"]["parquet-records-per-file"].as<uint64_t>());

    if (node["export"]["file-name-prefix"])
        cfg.file_prefix.add_value(node["export"]["file-name-prefix"].as<std::string>());

    if (node["export"]["timeout"])
        cfg.file_rot_timeout.add_value(node["export"]["timeout"].as<uint32_t>());

    if (node["export"]["file-size-limit"])
        cfg.file_rot_size.add_value(node["export"]["file-size-limit"].as<uint64_t>());

    if (node["export"]["file-compression"])
        cfg.file_compression.add_value(node["export"]["file-compression"].as<bool>());

    if (node["export"]["pcap-export"])
        cfg.pcap_export.add_value(node["export"]["pcap-export"].as<std::string>());

    if (node["ip-anonymization"]["anonymize-ip"])
        cfg.anonymize_ip.add_value(node["ip-anonymization"]["anonymize-ip"].as<bool>());

    if (node["ip-anonymization"]["encryption"])
        cfg.ip_encryption.add_value(node["ip-anonymization"]["encryption"].as<std::string>());

    if (node["ip-anonymization"]["key-path"])
        cfg.ip_enc_key.add_value(node["ip-anonymization"]["key-path"].as<std::string>());

    if (node["transaction-table"]["max-transactions"])
        cfg.tt_size.add_value(node["transaction-table"]["max-transactions"].as<uint32_t>());

    if (node["transaction-table"]["query-timeout"])
        cfg.tt_timeout.add_value(node["transaction-table"]["query-timeout"].as<uint64_t>());

    if (node["transaction-table"]["match-qname"])
        cfg.match_qname.add_value(node["transaction-table"]["match-qname"].as<bool>());

    if (node["tcp-table"]["concurrent-connections"])
        cfg.tcp_ct_size.add_value(node["tcp-table"]["concurrent-connections"].as<uint32_t>());

    if (node["tcp-table"]["timeout"])
        cfg.tcp_ct_timeout.add_value(node["tcp-table"]["timeout"].as<uint64_t>());
}
