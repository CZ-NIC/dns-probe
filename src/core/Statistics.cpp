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

#include <algorithm>
#include <list>
#include <cmath>

#include "Statistics.h"

namespace DDP {
    Statistics& Statistics::operator+=(const Statistics& rhs)
    {
        packets += rhs.packets;
        transactions += rhs.transactions;
        exported_records += rhs.exported_records;
        active_tt_records += rhs.active_tt_records;
        exported_to_pcap += rhs.exported_to_pcap;

        // Entropy
        for (auto index = 0u; index < ENTROPY_ARRAY_SIZE; index++) {
            ipv4_src_entropy_cnts[index] += rhs.ipv4_src_entropy_cnts[index];
        }

        // Overall stats
        for (auto i = 0u; i < QUERY_STATS_SIZE; i++) {
            queries[i] += rhs.queries[i];
        }

        // IPv4 stats
        for (auto& ipv4 : rhs.queries_ipv4) {
            for (auto i = 0u; i < QUERY_STATS_SIZE; i++) {
                queries_ipv4[ipv4.first][i] += ipv4.second[i];
            }
        }

        // IPv6 stats
        for (auto& ipv6 : rhs.queries_ipv6) {
            for (auto i = 0u; i < QUERY_STATS_SIZE; i++) {
                queries_ipv6[ipv6.first][i] += ipv6.second[i];
            }
        }

        return *this;
    }

    std::string Statistics::string()
    {
        std::stringstream str;
        str << "       Processed packets: " << packets << std::endl;
        str << "  Processed transactions: " << transactions << std::endl;
        str << "        Exported records: " << exported_records << std::endl;
        str << "     Active transactions: " << active_tt_records << std::endl;
        str << "Exported packets to PCAP: " << exported_to_pcap << std::endl;
        str << "            IPv4 Queries: " << queries[Q_IPV4] << std::endl;
        str << "            IPv6 Queries: " << queries[Q_IPV6] << std::endl;
        str << "          TCP/53 Queries: " << queries[Q_TCP] << std::endl;
        str << "             UDP Queries: " << queries[Q_UDP] << std::endl;
        str << "             DoT Queries: " << queries[Q_DOT] << std::endl;
        str << "             DoH Queries: " << queries[Q_DOH] << std::endl;
        str << "                 Queries: " << queries[Q_IPV4] + queries[Q_IPV6] << std::endl;

        return str.str();
    }

    uint64_t AggregatedStatistics::get_timestamp()
    {
        timespec time{};
        if (clock_gettime(CLOCK_MONOTONIC, &time) != 0) {
            throw std::runtime_error("Cannot get clock!");
        }
        return time.tv_sec;
    }

    void AggregatedStatistics::aggregate(const std::vector<Statistics>& container)
    {

        packets = 0;
        transactions = 0;
        exported_records = 0;
        active_tt_records = 0;
        exported_to_pcap = 0;
        std::memset(ipv4_src_entropy_cnts, 0, sizeof(ipv4_src_entropy_cnts));

        queries.fill(0);
        queries_ipv4 = Ipv4StatsMap();
        queries_ipv6 = Ipv6StatsMap();

        for (auto& stat: container) {
            operator+=(stat);
        }
    }

    void AggregatedStatistics::recalculate_qps()
    {
        auto time_window = static_cast<double>(get_timestamp() - m_qps_timestamp);

        QueryStatsArray qps_tmp;
        Ipv4StatsMap ipv4_qps_tmp;
        Ipv6StatsMap ipv6_qps_tmp;
        if (time_window) {
            // Overall stats
            for (auto i = 0u; i < QUERY_STATS_SIZE; i++) {
                qps_tmp[i] = (queries[i] - m_old_aggregated_queries[i]) / time_window;
            }

            // IPv4 stats
            for (auto& ipv4 : queries_ipv4) {
                for (auto i = 0u; i < QUERY_STATS_SIZE; i++) {
                    ipv4_qps_tmp[ipv4.first][i] = (ipv4.second[i] - m_old_ipv4_aggregated_queries[ipv4.first][i])
                        / time_window;
                }
            }

            // IPv6 stats
            for (auto& ipv6 : queries_ipv6) {
                for (auto i = 0u; i < QUERY_STATS_SIZE; i++) {
                    ipv6_qps_tmp[ipv6.first][i] = (ipv6.second[i] - m_old_ipv6_aggregated_queries[ipv6.first][i])
                        / time_window;
                }
            }
        }
        else {
            qps_tmp.fill(0);
        }

        m_qps_timestamp = get_timestamp();
        m_old_aggregated_queries = queries;
        m_old_ipv4_aggregated_queries = queries_ipv4;
        m_old_ipv6_aggregated_queries = queries_ipv6;

        // Overall stats
        while (m_moving_avg.size() >= m_moving_avg_window) {
            m_moving_avg.pop_front();
        }

        // IPv4 stats
        while (m_ipv4_moving_avg.size() > m_moving_avg_window) {
            m_ipv4_moving_avg.pop_front();
        }

        // IPv6 stats
        while (m_ipv6_moving_avg.size() > m_moving_avg_window) {
            m_ipv6_moving_avg.pop_front();
        }

        m_moving_avg.emplace_back(qps_tmp);
        m_ipv4_moving_avg.emplace_back(ipv4_qps_tmp);
        m_ipv6_moving_avg.emplace_back(ipv6_qps_tmp);
    }

    void AggregatedStatistics::get(const std::vector<Statistics>& container)
    {
        aggregate(container);
        qps.fill(0);
        ipv4_qps = Ipv4StatsMap();
        ipv6_qps = Ipv6StatsMap();

        // Overall stats
        for (auto& avg : m_moving_avg) {
            for (auto i = 0u; i < QUERY_STATS_SIZE; i++) {
                qps[i] += avg[i];
            }
        }

        if (m_moving_avg.size() > 1) {
            for (auto i = 0u; i < QUERY_STATS_SIZE; i++) {
                qps[i] = qps[i] / m_moving_avg.size();
            }
        }

        // IPv4 stats
        for (auto& avg : m_ipv4_moving_avg) {
            for (auto& ipv4 : avg) {
                for (auto i = 0u; i < QUERY_STATS_SIZE; i++) {
                    ipv4_qps[ipv4.first][i] += ipv4.second[i];
                }
            }
        }

        if (m_ipv4_moving_avg.size() > 1) {
            for (auto& ipv4 : ipv4_qps) {
                for (auto i = 0u; i < QUERY_STATS_SIZE; i++) {
                    ipv4.second[i] = ipv4.second[i] / m_ipv4_moving_avg.size();
                }
            }
        }

        // IPv6 stats
        for (auto& avg : m_ipv6_moving_avg) {
            for (auto& ipv6 : avg) {
                for (auto i = 0u; i < QUERY_STATS_SIZE; i++) {
                    ipv6_qps[ipv6.first][i] += ipv6.second[i];
                }
            }
        }

        if (m_ipv6_moving_avg.size() > 1) {
            for (auto& ipv6 : ipv6_qps) {
                for (auto i = 0u; i < QUERY_STATS_SIZE; i++) {
                    ipv6.second[i] = ipv6.second[i] / m_ipv6_moving_avg.size();
                }
            }
        }

        // Entropy
        ipv4_src_entropy = 0.0;
        uint64_t all_count = 0;

        for (auto index = 0u; index < ENTROPY_ARRAY_SIZE; index++) {
            all_count += (ipv4_src_entropy_cnts[index] - m_old_ipv4_src_entropy_cnts[index]);
        }

        if (all_count > 0) {
            for (auto index = 0u; index < ENTROPY_ARRAY_SIZE; index++) {
                double probability = (ipv4_src_entropy_cnts[index] - m_old_ipv4_src_entropy_cnts[index]) / static_cast<double>(all_count);
                if (probability > 0.0)
                    ipv4_src_entropy += (probability * std::log2(probability));
            }

            if (ipv4_src_entropy != 0.0)
                ipv4_src_entropy = -1 * ipv4_src_entropy;
        }

        std::memcpy(m_old_ipv4_src_entropy_cnts, ipv4_src_entropy_cnts, sizeof(ipv4_src_entropy_cnts));
    }
}
