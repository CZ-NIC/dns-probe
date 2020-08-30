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


const char* SYSCONF_MODULE = "cznic-dns-probe";
const char* SYSCONF_CFG_ROOT = "/cznic-dns-probe:dns-probe";
const char* SYSCONF_STATS_ROOT = "/cznic-dns-probe:statistics";


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

DDP::ConfigSysrepo::ConfigSysrepo(std::string instance, Config& cfg) : PollAble(), m_instance(std::move(instance)),
                                                                       m_cfg(cfg), m_path_map{
                {"/interface-list",                     m_cfg.interface_list},
                {"/pcap-list",                          m_cfg.pcap_list},
                {"/raw-pcap",                           m_cfg.raw_pcap},
                {"/log-file",                           m_cfg.log_file},
                {"/coremask",                           m_cfg.coremask},
                {"/dns-ports",                          m_cfg.dns_ports},
                {"/ipv4-allowlist",                     m_cfg.ipv4_allowlist},
                {"/ipv4-denylist",                      m_cfg.ipv4_denylist},
                {"/ipv6-allowlist",                     m_cfg.ipv6_allowlist},
                {"/ipv6-denylist",                      m_cfg.ipv6_denylist},
                {"/transaction-table/max-transactions", m_cfg.tt_size},
                {"/transaction-table/query-timeout",    m_cfg.tt_timeout},
                {"/transaction-table/match-qname",      m_cfg.match_qname},
                {"/tcp-table/concurrent-connections",   m_cfg.tcp_ct_size},
                {"/tcp-table/timeout",                  m_cfg.tcp_ct_timeout},
                {"/export/location",                    m_cfg.export_location},
                {"/export/remote-ip-address",           m_cfg.export_ip},
                {"/export/remote-port",                 m_cfg.export_port},
                {"/export/remote-ca-cert",              m_cfg.export_ca_cert},
                {"/export/export-dir",                  m_cfg.target_directory},
                {"/export/file-name-prefix",            m_cfg.file_prefix},
                {"/export/timeout",                     m_cfg.file_rot_timeout},
                {"/export/file-size-limit",             m_cfg.file_rot_size},
                {"/export/file-compression",            m_cfg.file_compression},
                {"/export/pcap-export",                 m_cfg.pcap_export},
                {"/export/export-format",               m_cfg.export_format},
                {"/export/parquet-records-per-file",    m_cfg.parquet_records},
                {"/export/cdns-fields",                 m_cfg.cdns_fields},
                {"/export/cdns-records-per-block",      m_cfg.cdns_records_per_block},
                {"/export/cdns-blocks-per-file",        m_cfg.cdns_blocks_per_file},
                {"/ip-anonymization/anonymize-ip",      m_cfg.anonymize_ip},
                {"/ip-anonymization/encryption",        m_cfg.ip_encryption},
                {"/ip-anonymization/key-path",          m_cfg.ip_enc_key},
        }, m_sysrepo_session(), m_sysrepo_subscribe(), m_sysrepo_callback(), m_fd(), m_logger("Sysrepo")
{
    try {
        m_sysrepo_session = std::make_shared<sysrepo::Session>(std::make_shared<sysrepo::Connection>());
        m_sysrepo_subscribe = std::make_shared<sysrepo::Subscribe>(m_sysrepo_session);
        m_sysrepo_callback = std::make_shared<SysrepoCallback>(*this);
    } catch (sysrepo::sysrepo_exception& e) {
        m_logger.error() << "Couldn't load sysrepo! (" << e.what() << ")";
        throw std::runtime_error(e.what());
    }


    auto cfg_root = std::string(SYSCONF_CFG_ROOT)  + "[instance='" + m_instance + "']";
    auto tree = m_sysrepo_session->get_data(SYSCONF_CFG_ROOT);

    // Check if config instance exists if not create it
    bool found_instance = false;
    for (auto sibling = tree->first_sibling(); sibling != nullptr && !found_instance; sibling = sibling->next()) {
        for (auto&& item: sibling->find_path("instance")->data())
            if (boost::any_cast<std::string>(conv_sysrepo_data(item)) == m_instance) {
                found_instance = true;
                break;
            }
    }

    if (!found_instance) {
        m_logger.debug() << "Creating new config instance " << m_instance;
        m_sysrepo_session->set_item(cfg_root.c_str());
        m_sysrepo_session->apply_changes();
        tree = m_sysrepo_session->get_data(SYSCONF_CFG_ROOT);
    }

    auto allow_empty = std::set<std::string>{
            "/ipv4-allowlist",
            "/ipv4-denylist",
            "/ipv6-allowlist",
            "/ipv6-denylist",
            "/export/remote-ca-cert",
            "/log-file"
    };

    for (auto&& item : m_path_map) {
        try {
            auto nodes = tree->find_path((cfg_root + item.first).c_str())->data();

            if(nodes.empty() && !allow_empty.count(item.first)) {
                m_logger.warning() << "Config for path '" << item.first << "' not found!";
                continue;
            }

            for (auto& val : nodes) {
                m_logger.debug() << "Setting new value for " << item.first << " (old value: " << item.second.string()
                                 << ")";
                item.second.from_sysrepo(conv_sysrepo_data(val));
                m_logger.debug() << "New value for " << item.first << " is " << item.second.string();
            }
        } catch (sysrepo::sysrepo_exception& e) {
            m_logger.warning() << "Getting config for path '" << item.first << "' failed! (" << e.what() << ")";
        }
    }

    try {
        m_sysrepo_subscribe->module_change_subscribe(SYSCONF_MODULE, m_sysrepo_callback, nullptr, nullptr, 0,
                                                     SR_SUBSCR_NO_THREAD);
        m_sysrepo_session->session_switch_ds(SR_DS_OPERATIONAL);

        m_sysrepo_subscribe->oper_get_items_subscribe(SYSCONF_MODULE, SYSCONF_STATS_ROOT,
                                                      m_sysrepo_callback, nullptr, SR_SUBSCR_NO_THREAD);

        m_sysrepo_subscribe->rpc_subscribe((std::string("/") + SYSCONF_MODULE + ":restart").c_str(), m_sysrepo_callback, nullptr, 0,
                                           SR_SUBSCR_NO_THREAD);
    } catch (sysrepo::sysrepo_exception& e) {
        m_logger.warning() << "Couldn't subscribe to sysrepo changes! (" << e.what() << ")";
    }

    m_fd = m_sysrepo_subscribe->get_event_pipe();
}

void DDP::ConfigSysrepo::ready_read()
{
    m_sysrepo_subscribe->process_events();
}

void DDP::ConfigSysrepo::error()
{
    throw std::runtime_error("Server management socket failed!");
}

void DDP::ConfigSysrepo::hup()
{
    throw std::runtime_error("Server management HANG UP!");
}

int DDP::ConfigSysrepo::SysrepoCallback::module_change(sysrepo::S_Session session,
                                                       const char*,
                                                       const char*,
                                                       sr_event_t event,
                                                       uint32_t,
                                                       void*)
{
    auto it = session->get_changes_iter("//.");

    while (auto change = session->get_change_tree_next(it)) {
        auto node = change->node();
        auto path = node->path();
        auto pos = path.find('[');
        if (pos != std::string::npos)
            path = path.substr(0, pos);

        if (change->oper() == SR_OP_CREATED || change->oper() == SR_OP_MODIFIED) {
            try {
                auto& cfg = m_cfg.m_path_map.at(path);

                if (event == SR_EV_DONE) {
                    m_cfg.m_logger.info() << "New configuration '" << node->path()
                                          << "' with value: '" << libyang::Data_Node_Leaf_List(node).value_str()
                                          << "' modifying '"
                                          << cfg.string() << "'";

                    cfg.from_sysrepo(conv_sysrepo_data(node));
                } else if (event == SR_EV_CHANGE) {

                }
            } catch (std::out_of_range& e) {
                m_cfg.m_logger.info() << "New configuration '" << node->path()
                                      << "'. Cannot be applied because this path doesn't have associated config item.";
            }
        }
        else if (change->oper() == SR_OP_DELETED) {
            try {
                auto& cfg = m_cfg.m_path_map.at(path);

                if (event == SR_EV_DONE) {
                    m_cfg.m_logger.info() << "Deleted configuration '" << node->path()
                                        << "' from '" << cfg.string() << "'";

                    cfg.delete_value(conv_sysrepo_data(node));
                }
                else if (event == SR_EV_CHANGE) {

                }
            }
            catch (std::out_of_range& e) {
                m_cfg.m_logger.info() << "Deleted configuration '" << node->path()
                                      << "'. Cannot be applied because this path doesn't have associated config item.";
            }
        }
    }

    Probe::getInstance().update_config();
    return SR_ERR_OK;
}
#include <iostream>
int DDP::ConfigSysrepo::SysrepoCallback::oper_get_items(sysrepo::S_Session session,
                                                        const char* module_name,
                                                        const char*,
                                                        const char*,
                                                        uint32_t,
                                                        libyang::S_Data_Node& parent,
                                                        void*)
{
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

    parent.reset(new libyang::Data_Node(ctx, SYSCONF_STATS_ROOT, nullptr, LYD_ANYDATA_CONSTSTRING, 0));
    auto instance = parent->new_path(ctx, "instances", nullptr, LYD_ANYDATA_CONSTSTRING, 0);
    instance->new_path(ctx, "instance", m_cfg.m_instance.c_str(), LYD_ANYDATA_CONSTSTRING, 0);

    for (auto&& item : stats_map) {
        instance->new_path(ctx, item.first.c_str(), item.second.c_str(), LYD_ANYDATA_CONSTSTRING, 0);
    }

    return SR_ERR_OK;
}

int DDP::ConfigSysrepo::SysrepoCallback::rpc(sysrepo::S_Session,
                                         const char*,
                                         const sysrepo::S_Vals,
                                         sr_event_t,
                                         uint32_t,
                                         sysrepo::S_Vals_Holder,
                                         void*)
{
    m_cfg.m_logger.info() << "Received request to restart.";
    Probe::getInstance().stop(true);
    return SR_ERR_OK;
}
