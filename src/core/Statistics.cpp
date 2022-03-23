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

#include "Statistics.h"

namespace DDP {
    Statistics& Statistics::operator+=(const Statistics& rhs)
    {
        packets += rhs.packets;
        transactions += rhs.transactions;
        exported_records += rhs.exported_records;
        active_tt_records += rhs.active_tt_records;
        exported_to_pcap += rhs.exported_to_pcap;

        for (auto index = 0u; index < queries.size(); index++) {
            for (auto i = 0u; i < 4; i++) {
                queries[index][i] += rhs.queries[index][i];
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
        for (auto i = 0u; i < queries.size(); i++) {
            str << "            IPv4 Queries[" << std::to_string(i) << "]: " << queries[i][Q_IPV4] << std::endl;
            str << "            IPv6 Queries[" << std::to_string(i) << "]: " << queries[i][Q_IPV6] << std::endl;
            str << "             TCP Queries[" << std::to_string(i) << "]: " << queries[i][Q_TCP] << std::endl;
            str << "             UDP Queries[" << std::to_string(i) << "]: " << queries[i][Q_UDP] << std::endl;
            str << "                 Queries[" << std::to_string(i) << "]: " << queries[i][Q_IPV4] + queries[i][Q_IPV6] << std::endl;
        }

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

        for (auto& item: queries) {
            item.fill(0);
        }

        for (auto& stat: container) {
            operator+=(stat);
        }
    }

    void AggregatedStatistics::recalculate_qps()
    {
        auto time_window = static_cast<double>(get_timestamp() - m_qps_timestamp);

        std::vector<std::array<uint64_t, 4>> qps_tmp(qps.size());
        if (time_window)
            for (auto index = 0u; index < qps.size(); index++) {
                for (auto i = 0u; i < 4; i++) {
                    qps_tmp[index][i] = (queries[index][i] - m_old_aggregated_queries[index][i]) / time_window;
                }
            }
        else {
            for (auto& item: qps_tmp) {
                item.fill(0);
            }
        }

        m_qps_timestamp = get_timestamp();
        std::copy(queries.begin(), queries.end(), m_old_aggregated_queries.begin());

        while (m_moving_avg.size() >= m_moving_avg_window) {
            m_moving_avg.pop_front();
        }

        m_moving_avg.emplace_back(qps_tmp);
    }

    void AggregatedStatistics::get(const std::vector<Statistics>& container)
    {
        aggregate(container);
        for (auto& item: qps) {
            item.fill(0);
        }
        for (auto& avg : m_moving_avg) {
            for (auto index = 0u; index < qps.size(); index++) {
                for (auto i = 0u; i < 4; i++) {
                    qps[index][i] += avg[index][i];
                }
            }
        }

        if (m_moving_avg.size() > 1) {
            for (auto index = 0u; index < qps.size(); index++) {
                for (auto i = 0u; i < 4; i++) {
                    qps[index][i] = qps[index][i] / m_moving_avg.size();
                }
            }
        }
    }
}
