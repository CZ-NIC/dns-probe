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

#include <sysrepo.h>
#include <libyang/Libyang.hpp>

#include <stdexcept>
#include <any>
#include <utility>

#include "core/Probe.h"
#include "ConfigSysrepo.h"

#ifndef SYSCONF_MODULE
#define SYSCONF_MODULE "cznic-dns-probe"
#endif

#ifndef SYSCONF_CFG_CONTAINER
#define SYSCONF_CFG_CONTAINER "dns-probe"
#endif

#ifndef SYSCONF_STATISTICS_CONTAINER
#define SYSCONF_STATISTICS_CONTAINER "statistics"
#endif

#define SYSCONF_CFG_ROOT "/" SYSCONF_MODULE ":" SYSCONF_CFG_CONTAINER
#define SYSCONF_STATS_ROOT "/" SYSCONF_MODULE ":" SYSCONF_STATISTICS_CONTAINER

static std::any conv_sysrepo_data(libyang::S_Data_Node data)
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

DDP::ConfigSysrepo::ConfigSysrepo(Config& cfg) : PollAble(), m_cfg(cfg), m_path_map{
        {SYSCONF_CFG_ROOT "/coremask",                           m_cfg.coremask},
        {SYSCONF_CFG_ROOT "/transaction-table/max-transactions", m_cfg.tt_size},
        {SYSCONF_CFG_ROOT "/transaction-table/query-timeout",    m_cfg.tt_timeout},
        {SYSCONF_CFG_ROOT "/transaction-table/match-qname",      m_cfg.match_qname},
        {SYSCONF_CFG_ROOT "/tcp-table/concurrent-connections",   m_cfg.tcp_ct_size},
        {SYSCONF_CFG_ROOT "/tcp-table/timeout",                  m_cfg.tcp_ct_timeout},
        {SYSCONF_CFG_ROOT "/export/export-dir",                  m_cfg.target_directory},
        {SYSCONF_CFG_ROOT "/export/file-name-prefix",            m_cfg.file_prefix},
        {SYSCONF_CFG_ROOT "/export/timeout",                     m_cfg.file_rot_timeout},
        {SYSCONF_CFG_ROOT "/export/file-size-limit",             m_cfg.file_rot_size},
        {SYSCONF_CFG_ROOT "/export/file-compression",            m_cfg.file_compression},
        {SYSCONF_CFG_ROOT "/export/pcap-export",                 m_cfg.pcap_export},
        {SYSCONF_CFG_ROOT "/export/export-format",               m_cfg.export_format},
        {SYSCONF_CFG_ROOT "/export/parquet-records-per-file",    m_cfg.parquet_records},
        {SYSCONF_CFG_ROOT "/export/cdns-fields",                 m_cfg.cdns_fields},
        {SYSCONF_CFG_ROOT "/export/cdns-records-per-block",      m_cfg.cdns_records_per_block},
        {SYSCONF_CFG_ROOT "/export/cdns-blocks-per-file",        m_cfg.cdns_blocks_per_file},
        {SYSCONF_CFG_ROOT "/dns-port",                           m_cfg.dns_port},
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

    auto tree = m_sysrepo_session->get_data(SYSCONF_CFG_ROOT);

    for (auto&&[xpath, cfg]: m_path_map) {
        try {
            auto val = tree->find_path(xpath.c_str())->data()[0];

            if (val) {
                m_logger.debug() << "Setting new value for " << xpath << " (old value: " << cfg.string() << ")";
                cfg.from_sysrepo(conv_sysrepo_data(val));
                m_logger.debug() << "New value for " << xpath << " is " << cfg.string();
            } else
                m_logger.warning() << "Config for path '" << xpath << "' not found!";
        } catch (sysrepo::sysrepo_exception& e) {
            m_logger.warning() << "Getting config for path '" << xpath << "' failed! (" << e.what() << ")";
        }
    }

    try {
        m_sysrepo_subscribe->module_change_subscribe(SYSCONF_MODULE, m_sysrepo_callback, nullptr, nullptr, 0,
                                                     SR_SUBSCR_NO_THREAD);
        m_sysrepo_session->session_switch_ds(SR_DS_OPERATIONAL);
        m_sysrepo_subscribe->oper_get_items_subscribe(SYSCONF_MODULE, SYSCONF_STATS_ROOT,
                                                      m_sysrepo_callback, nullptr, SR_SUBSCR_NO_THREAD);
        m_sysrepo_subscribe->rpc_subscribe("/" SYSCONF_MODULE ":restart", m_sysrepo_callback, nullptr, 0,
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
                                                       const char* module_name [[maybe_unused]],
                                                       const char* xpath [[maybe_unused]],
                                                       sr_event_t event,
                                                       uint32_t request_id [[maybe_unused]],
                                                       void* private_data [[maybe_unused]])
{
    auto it = session->get_changes_iter("//.");

    while (auto change = session->get_change_tree_next(it)) {
        if (change->oper() == SR_OP_CREATED || change->oper() == SR_OP_MODIFIED) {
            auto node = change->node();
            try {
                auto& cfg = m_cfg.m_path_map.at(node->path());

                if (event == SR_EV_DONE) {
                    m_cfg.m_logger.info() << "New configuration '" << node->path()
                                          << "' with value: '" << libyang::Data_Node_Leaf_List(node).value_str()
                                          << " replacing '"
                                          << cfg.string() << "'";

                    cfg.from_sysrepo(conv_sysrepo_data(node));
                } else if (event == SR_EV_CHANGE) {

                }
            } catch (std::out_of_range& e) {
                m_cfg.m_logger.info() << "New configuration '" << node->path()
                                      << "' with value: '" << libyang::Data_Node_Leaf_List(node).value_str()
                                      << "'. Cannot be applied because this path doesn't have associated config item.";
            }
        }
    }

    Probe::getInstance().update_config();
    return SR_ERR_OK;
}

int DDP::ConfigSysrepo::SysrepoCallback::oper_get_items(sysrepo::S_Session session,
                                                        const char* module_name [[maybe_unused]],
                                                        const char* path [[maybe_unused]],
                                                        const char* request_xpath [[maybe_unused]],
                                                        uint32_t request_id [[maybe_unused]],
                                                        libyang::S_Data_Node& parent [[maybe_unused]],
                                                        void* private_data [[maybe_unused]])
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

    for (auto&&[name, val]: stats_map) {
        libyang::S_Data_Node element(new libyang::Data_Node(parent, mod, name.c_str(), val.c_str()));
    }

    return SR_ERR_OK;
}

int DDP::ConfigSysrepo::SysrepoCallback::rpc(sysrepo::S_Session session [[maybe_unused]],
                                         const char* op_path [[maybe_unused]],
                                         const sysrepo::S_Vals input [[maybe_unused]],
                                         sr_event_t event [[maybe_unused]],
                                         uint32_t request_id [[maybe_unused]],
                                         sysrepo::S_Vals_Holder output [[maybe_unused]],
                                         void* private_data [[maybe_unused]])
{
    m_cfg.m_logger.info() << "Received request to restart.";
    Probe::getInstance().stop(true);
    return SR_ERR_OK;
}
