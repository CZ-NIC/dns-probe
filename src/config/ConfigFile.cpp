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

#include <yaml-cpp/yaml.h>

#include <stdexcept>
#include <boost/any.hpp>
#include <utility>
#include <algorithm>
#include <bitset>

#include "ConfigFile.h"
#include "core/Probe.h"

void DDP::ConfigFile::load_instance(YAML::Node node)
{
    if (node["interface-list"]) {
        for (auto item : node["interface-list"]) {
            m_cfg.interface_list.add_value(item.as<std::string>());
        }
    }

    if (node["pcap-list"]) {
        for (auto item : node["pcap-list"]) {
            m_cfg.pcap_list.add_value(item.as<std::string>());
        }
    }

    if (node["raw-pcap"])
        m_cfg.raw_pcap.add_value(node["raw-pcap"].as<bool>());

    if (node["log-file"])
        m_cfg.log_file.add_value(node["log-file"].as<std::string>());

    if (node["coremask"])
        m_cfg.coremask.add_value(node["coremask"].as<uint64_t>());

    if (node["dns-ports"]) {
        for (auto item : node["dns-ports"]) {
            m_cfg.dns_ports.add_value(item.as<Port_t>());
        }
    }

    if (node["ipv4-allowlist"]) {
        for (auto item : node["ipv4-allowlist"]) {
            m_cfg.ipv4_allowlist.add_value(item.as<std::string>());
        }
    }

    if (node["ipv4-denylist"]) {
        for (auto item : node["ipv4-denylist"]) {
            m_cfg.ipv4_denylist.add_value(item.as<std::string>());
        }
    }

    if (node["ipv6-allowlist"]) {
        for (auto item : node["ipv6-allowlist"]) {
            m_cfg.ipv6_allowlist.add_value(item.as<std::string>());
        }
    }

    if (node["ipv6-denylist"]) {
        for (auto item : node["ipv6-denylist"]) {
            m_cfg.ipv6_denylist.add_value(item.as<std::string>());
        }
    }

    if (node["export"]["location"])
        m_cfg.export_location.add_value(node["export"]["location"].as<std::string>());


    if (node["export"]["export-dir"])
        m_cfg.target_directory.add_value(node["export"]["export-dir"].as<std::string>());

    if (node["export"]["remote-ip-address"])
        m_cfg.export_ip.add_value(node["export"]["remote-ip-address"].as<std::string>());

    if (node["export"]["remote-port"])
        m_cfg.export_port.add_value(node["export"]["remote-port"].as<uint16_t>());

    if (node["export"]["remote-ca-cert"])
        m_cfg.export_ca_cert.add_value(node["export"]["remote-ca-cert"].as<std::string>());

    if (node["export"]["export-format"])
        m_cfg.export_format.add_value(node["export"]["export-format"].as<std::string>());

    if (node["export"]["cdns-fields"] && node["export"]["cdns-fields"].IsSequence()) {
        std::bitset<CdnsBits> fields;
        for (auto item : node["export"]["cdns-fields"]) {
            std::string field = item.as<std::string>();
            std::transform(field.begin(), field.end(), field.begin(), tolower);
            auto found = CdnsFieldsMap.find(field);
            if (found != CdnsFieldsMap.end())
                fields.set(found->second);
        }

        m_cfg.cdns_fields.add_value(fields);
    }

    if (node["export"]["cdns-records-per-block"])
        m_cfg.cdns_records_per_block.add_value(node["export"]["cdns-records-per-block"].as<uint64_t>());

    if (node["export"]["cdns-blocks-per-file"])
        m_cfg.cdns_blocks_per_file.add_value(node["export"]["cdns-blocks-per-file"].as<uint64_t>());

    if (node["export"]["parquet-records-per-file"])
        m_cfg.parquet_records.add_value(node["export"]["parquet-records-per-file"].as<uint64_t>());

    if (node["export"]["file-name-prefix"])
        m_cfg.file_prefix.add_value(node["export"]["file-name-prefix"].as<std::string>());

    if (node["export"]["timeout"])
        m_cfg.file_rot_timeout.add_value(node["export"]["timeout"].as<uint32_t>());

    if (node["export"]["file-size-limit"])
        m_cfg.file_rot_size.add_value(node["export"]["file-size-limit"].as<uint64_t>());

    if (node["export"]["file-compression"])
        m_cfg.file_compression.add_value(node["export"]["file-compression"].as<bool>());

    if (node["export"]["pcap-export"])
        m_cfg.pcap_export.add_value(node["export"]["pcap-export"].as<std::string>());

    if (node["ip-anonymization"]["anonymize-ip"])
        m_cfg.anonymize_ip.add_value(node["ip-anonymization"]["anonymize-ip"].as<bool>());

    if (node["ip-anonymization"]["encryption"])
        m_cfg.ip_encryption.add_value(node["ip-anonymization"]["encryption"].as<std::string>());

    if (node["ip-anonymization"]["key-path"])
        m_cfg.ip_enc_key.add_value(node["ip-anonymization"]["key-path"].as<std::string>());

    if (node["transaction-table"]["max-transactions"])
        m_cfg.tt_size.add_value(node["transaction-table"]["max-transactions"].as<uint32_t>());

    if (node["transaction-table"]["query-timeout"])
        m_cfg.tt_timeout.add_value(node["transaction-table"]["query-timeout"].as<uint64_t>());

    if (node["transaction-table"]["match-qname"])
        m_cfg.match_qname.add_value(node["transaction-table"]["match-qname"].as<bool>());

    if (node["tcp-table"]["concurrent-connections"])
        m_cfg.tcp_ct_size.add_value(node["tcp-table"]["concurrent-connections"].as<uint32_t>());

    if (node["tcp-table"]["timeout"])
        m_cfg.tcp_ct_timeout.add_value(node["tcp-table"]["timeout"].as<uint64_t>());
}

DDP::ConfigFile::ConfigFile(Config& cfg, std::string conf_file, std::string instance) : PollAble(),
    m_cfg(cfg), m_logger("YAML"), m_fd()
{
    try {
        YAML::Node config = YAML::LoadFile(conf_file);

        if (config["default"])
            load_instance(config["default"]);

        if (instance != "default" && config[instance])
            load_instance(config[instance]);
    }
    catch (std::exception& e) {
        m_logger.warning() << "Couldn't load configuration file " << conf_file
                           << " - " << e.what() << ". Using default configuration.";
    }
}


void DDP::ConfigFile::ready_read()
{
}

void DDP::ConfigFile::error()
{
    throw std::runtime_error("Server management socket failed!");
}

void DDP::ConfigFile::hup()
{
    throw std::runtime_error("Server management HANG UP!");
}

