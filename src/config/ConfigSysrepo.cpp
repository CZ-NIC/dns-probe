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

#include <sysrepo.h>
#include <libyang/Libyang.hpp>

#include <stdexcept>
#include <boost/any.hpp>
#include <utility>

#include "core/Probe.h"
#include "ConfigSysrepo.h"

static boost::any conv_sysrepo_data(libyang::S_Data_Node data)
{
    libyang::Data_Node_Leaf_List leaf(std::move(data));
    auto value = leaf.value();
    switch (static_cast<LY_DATA_TYPE>(leaf.value_type())) {
        case LY_TYPE_DER:
        case LY_TYPE_EMPTY:
        case LY_TYPE_BINARY:
        case LY_TYPE_IDENT:
        case LY_TYPE_INST:
        case LY_TYPE_LEAFREF:
        case LY_TYPE_UNION:
        case LY_TYPE_UNKNOWN:
            throw std::runtime_error("Unsupported type!");
        case LY_TYPE_BITS:
            return {leaf.value()->bit()};
        case LY_TYPE_BOOL:
            return {static_cast<bool>(value->bln())};
        case LY_TYPE_DEC64:
            return {value->dec64()};
        case LY_TYPE_ENUM:
            return {std::string(value->enm()->name())};
        case LY_TYPE_STRING:
            return {std::string(value->string())};
        case LY_TYPE_INT8:
            return {value->int8()};
        case LY_TYPE_UINT8:
            return {value->uint8()};
        case LY_TYPE_INT16:
            return {value->int16()};
        case LY_TYPE_UINT16:
            return {value->uint16()};
        case LY_TYPE_INT32:
            return {value->int32()};
        case LY_TYPE_UINT32:
            return {value->uint32()};
        case LY_TYPE_INT64:
            return {value->int64()};
        case LY_TYPE_UINT64:
            return {value->uint64()};
    }

    throw std::runtime_error("Unsupported type!");
}

DDP::ConfigSysrepo::ConfigSysrepo(std::string instance, Config& cfg) :
        PollAble(),
        m_instance(std::move(instance)),
        m_root("/" +  m_module + ":dns-probe[instance='" + m_instance + "']"),
        m_cfg(cfg), m_path_map{
        {"interface-list",                     m_cfg.interface_list},
        {"pcap-list",                          m_cfg.pcap_list},
        {"dnstap-socket-list",                 m_cfg.dnstap_socket_list},
        {"dnstap-socket-group",                m_cfg.dnstap_socket_group},
        {"knot-socket-path",                   m_cfg.knot_socket_path},
        {"knot-socket-count",                  m_cfg.knot_socket_count},
        {"raw-pcap",                           m_cfg.raw_pcap},
        {"log-file",                           m_cfg.log_file},
        {"coremask",                           m_cfg.coremask},
        {"dns-ports",                          m_cfg.dns_ports},
        {"ipv4-allowlist",                     m_cfg.ipv4_allowlist},
        {"ipv4-denylist",                      m_cfg.ipv4_denylist},
        {"ipv6-allowlist",                     m_cfg.ipv6_allowlist},
        {"ipv6-denylist",                      m_cfg.ipv6_denylist},
        {"transaction-table/max-transactions", m_cfg.tt_size},
        {"transaction-table/query-timeout",    m_cfg.tt_timeout},
        {"transaction-table/match-qname",      m_cfg.match_qname},
        {"tcp-table/concurrent-connections",   m_cfg.tcp_ct_size},
        {"tcp-table/timeout",                  m_cfg.tcp_ct_timeout},
        {"export/location",                    m_cfg.export_location},
        {"export/remote-ip-address",           m_cfg.export_ip},
        {"export/remote-port",                 m_cfg.export_port},
        {"export/remote-ca-cert",              m_cfg.export_ca_cert},
        {"export/export-dir",                  m_cfg.target_directory},
        {"export/file-name-prefix",            m_cfg.file_prefix},
        {"export/timeout",                     m_cfg.file_rot_timeout},
        {"export/file-size-limit",             m_cfg.file_rot_size},
        {"export/file-compression",            m_cfg.file_compression},
        {"export/pcap-export",                 m_cfg.pcap_export},
        {"export/export-format",               m_cfg.export_format},
        {"export/parquet-records-per-file",    m_cfg.parquet_records},
        {"export/cdns-fields",                 m_cfg.cdns_fields},
        {"export/cdns-records-per-block",      m_cfg.cdns_records_per_block},
        {"export/cdns-blocks-per-file",        m_cfg.cdns_blocks_per_file},
        {"export/country-maxmind-db",          m_cfg.country_db},
        {"export/asn-maxmind-db",              m_cfg.asn_db},
        {"ip-anonymization/anonymize-ip",      m_cfg.anonymize_ip},
        {"ip-anonymization/encryption",        m_cfg.ip_encryption},
        {"ip-anonymization/key-path",          m_cfg.ip_enc_key},
}, m_sysrepo_session(), m_sysrepo_subscribe(), m_sysrepo_callback(), m_fd(), m_logger("Sysrepo")
{
    m_sysrepo_register = [this] (int fd, std::function<void()> cb) {
        m_fd = fd;
        m_sysrepo_callback = cb;
    };

    // This gets called only in ConfigSysrepo's destructor, where the whole object is destroyed anyway.
    // If this would contain manual unregistration from it's poll array, the descructor would be called twice
    // and SEGFAULT might happen.
    m_sysrepo_unregister = [] (int) {};

    try {
        m_sysrepo_session = std::make_shared<sysrepo::Session>(std::make_shared<sysrepo::Connection>());
        m_sysrepo_subscribe = std::make_shared<sysrepo::Subscribe>(m_sysrepo_session, m_sysrepo_register, m_sysrepo_unregister);
    } catch (sysrepo::sysrepo_exception& e) {
        m_logger.error() << "Couldn't load sysrepo! (" << e.what() << ")";
        throw std::runtime_error(e.what());
    }

    auto root_tree = m_sysrepo_session->get_data(m_root.c_str());

    // Check if config instance exists if not create it
    bool found_instance = false;
    if (root_tree) {
        for (auto sibling = root_tree->first_sibling(); sibling != nullptr && !found_instance; sibling = sibling->next()) {
            for (auto&& item: sibling->find_path("instance")->data())
                if (boost::any_cast<std::string>(conv_sysrepo_data(item)) == m_instance) {
                    found_instance = true;
                    break;
                }
        }
    }

    if (!found_instance) {
        m_logger.debug() << "Creating new config instance " << m_instance;
        m_sysrepo_session->set_item(m_root.c_str());
        m_sysrepo_session->apply_changes();
        root_tree = m_sysrepo_session->get_data(m_root.c_str());
    }

    auto config_subtrees = root_tree->find_path("configuration")->data();

    if (config_subtrees.empty() or config_subtrees.size() != 1) {
        m_logger.error() << "Invalid schema!";
        throw std::runtime_error("Invalid schema!");
    }

    auto tree = config_subtrees[0];

    for (auto&& item : m_path_map) {
        try {
            auto nodes = tree->find_path(item.first.c_str())->data();

            if (nodes.empty()) {
                auto show_not_found_warning = true;
                auto cfg_schemas = tree->schema()->find_path(item.first.c_str())->schema();

                // Check if value has set default. If not do not show warning.
                for (auto&& cfg_schema: cfg_schemas) {
                    if (cfg_schema->nodetype() == LYS_LEAF) {
                        auto leaf = libyang::Schema_Node_Leaf(cfg_schema);
                        if (leaf.dflt() == nullptr)
                            show_not_found_warning = false;
                    } else if (cfg_schema->nodetype() == LYS_LEAFLIST) {
                        auto leaf_list = libyang::Schema_Node_Leaflist(cfg_schema);
                        if (leaf_list.dflt().empty())
                            show_not_found_warning = false;
                    }
                }

                if (show_not_found_warning)
                    m_logger.warning() << "Config for path '" << item.first << "' not found!";
                continue;
            }

            for (auto& val : nodes) {
                m_logger.debug() << "Setting new value for " << val->path() << " (old value: " << item.second.string()
                                 << ")";
                item.second.add_value(conv_sysrepo_data(val));
                m_logger.debug() << "New value for " << item.first << " is " << item.second.string();
            }
        } catch (sysrepo::sysrepo_exception& e) {
            m_logger.warning() << "Getting config for path '" << item.first << "' failed! (" << e.what() << ")";
        }
    }

    auto module_change = [this] (sysrepo::S_Session session, const char*, const char*, sr_event_t event,
        uint32_t) {
        auto cfg_root = this->m_root + "/configuration";
        auto it = session->get_changes_iter((cfg_root + "//.").c_str());

        while (auto change = session->get_change_tree_next(it)) {
            auto node = change->node();
            auto path = node->path().erase(0, cfg_root.length() + 1);

            if (node->schema()->nodetype() == LYS_CONTAINER) {
                continue;
            } else if (node->schema()->nodetype() == LYS_LEAFLIST) {
                auto last_open_bracket = path.rfind('[');
                path.erase(last_open_bracket);
            }


            if (change->oper() == SR_OP_CREATED || change->oper() == SR_OP_MODIFIED) {
                try {
                    auto& cfg = this->m_path_map.at(path);

                    if (event == SR_EV_DONE) {
                        this->m_logger.info() << "New configuration '" << node->path()
                                            << "' with value: '" << libyang::Data_Node_Leaf_List(node).value_str()
                                            << "' modifying '"
                                            << cfg.string() << "'";

                        cfg.add_value(conv_sysrepo_data(node));
                    } else if (event == SR_EV_CHANGE) {

                    }
                } catch (std::out_of_range& e) {
                    this->m_logger.info() << "New configuration '" << path
                                        << "'. Cannot be applied because this path doesn't have associated config item.";
                }
            } else if (change->oper() == SR_OP_DELETED) {
                try {
                    auto& cfg = this->m_path_map.at(path);

                    if (event == SR_EV_DONE) {
                        // Set default value for leaves if exists
                        auto schema = node->schema();
                        if (schema->nodetype() == LYS_LEAF) {
                            auto node_info = libyang::Schema_Node_Leaf(schema);
                            if (node_info.dflt()) {
                                auto default_node = this->m_sysrepo_session->get_data(change->node()->path().c_str());
    //                            cfg.add_value(conv_sysrepo_data(default_node));
    //                            this->m_logger.info() << "Setting default configuration '" << node->path()
    //                                                  << "' to '" << cfg.string();
                                this->m_logger.info() << "Deleted configuration '" << node->path()
                                                    << "' from '" << cfg.string() << "'";
                            }
                        } else {
                            this->m_logger.info() << "Deleted configuration '" << node->path()
                                                << "' from '" << cfg.string() << "'";

                            cfg.delete_value(conv_sysrepo_data(node));
                        }

                    } else if (event == SR_EV_CHANGE) {

                    }
                }
                catch (std::out_of_range& e) {
                    this->m_logger.info() << "Deleted configuration '" << node->path()
                                        << "'. Cannot be applied because this path doesn't have associated config item.";
                }
            }
        }

        Probe::getInstance().update_config();
        return SR_ERR_OK;
    };

    auto oper_get_items = [this] (sysrepo::S_Session session, const char* module_name, const char*, const char*,
        uint32_t, libyang::S_Data_Node& parent) {
        auto stats = DDP::Probe::getInstance().statistics();

        std::unordered_map<std::string, std::string> stats_map{
                {"processed-packets",       std::to_string(stats.packets)},
                {"processed-transactions",  std::to_string(stats.transactions)},
                {"exported-records",        std::to_string(stats.exported_records)},
                {"queries-per-second-ipv4", std::to_string(stats.qps[Statistics::Q_IPV4])},
                {"queries-per-second-ipv6", std::to_string(stats.qps[Statistics::Q_IPV6])},
                {"queries-per-second-tcp",  std::to_string(stats.qps[Statistics::Q_TCP])},
                {"queries-per-second-udp",  std::to_string(stats.qps[Statistics::Q_UDP])},
                {"queries-per-second",      std::to_string(stats.qps[Statistics::Q_IPV4] + stats.qps[Statistics::Q_IPV6])},
                {"pending-transactions",    std::to_string(stats.active_tt_records)},
                {"exported-pcap-packets",   std::to_string(stats.exported_to_pcap)}
        };

        auto ctx = session->get_context();
        auto mod = ctx->get_module(module_name);

        auto instance = parent->new_path(ctx, "statistics", nullptr, LYD_ANYDATA_CONSTSTRING, 0);

        for (auto&& item : stats_map) {
            instance->new_path(ctx, item.first.c_str(), item.second.c_str(), LYD_ANYDATA_CONSTSTRING, 0);
        }

        return SR_ERR_OK;
    };

    auto rpc = [this] (sysrepo::S_Session, const char*, const sysrepo::S_Vals, sr_event_t, uint32_t,
        sysrepo::S_Vals_Holder) {
        this->m_logger.info() << "Received request to restart.";
        Probe::getInstance().stop(true);
        return SR_ERR_OK;
    };

    try {
        uint32_t prio = std::hash<std::string>{}(m_instance);
        m_sysrepo_subscribe->module_change_subscribe(m_module.c_str(), module_change, (m_root + "/configuration").c_str(), 0, SR_SUBSCR_NO_THREAD);
        m_sysrepo_session->session_switch_ds(SR_DS_OPERATIONAL);
        m_sysrepo_subscribe->oper_get_items_subscribe(m_module.c_str(), oper_get_items, (m_root + "/statistics").c_str(), SR_SUBSCR_NO_THREAD);
        m_sysrepo_subscribe->rpc_subscribe((m_root + "/restart").c_str(), rpc, prio, SR_SUBSCR_NO_THREAD);
    } catch (sysrepo::sysrepo_exception& e) {
        m_logger.warning() << "Couldn't subscribe to sysrepo changes! (" << e.what() << ")";
    }
}

void DDP::ConfigSysrepo::ready_read()
{
    m_sysrepo_callback();
}

void DDP::ConfigSysrepo::error()
{
    throw std::runtime_error("Server management socket failed!");
}

void DDP::ConfigSysrepo::hup()
{
    throw std::runtime_error("Server management HANG UP!");
}
