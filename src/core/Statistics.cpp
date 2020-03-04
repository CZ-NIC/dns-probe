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

#include <algorithm>

#include "Statistics.h"

namespace DDP {
    Statistics& Statistics::operator+=(const Statistics& rhs)
    {
        packets += rhs.packets;
        transactions += rhs.transactions;
        exported_records += rhs.exported_records;
        active_tt_records += rhs.active_tt_records;
        exported_to_pcap += rhs.exported_to_pcap;

        for (auto i = 0u; i < 4; i++) {
            queries[i] += rhs.queries[i];
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
        str << "             TCP Queries: " << queries[Q_TCP] << std::endl;
        str << "             UDP Queries: " << queries[Q_UDP] << std::endl;
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
        queries.fill(0);

        for (auto& stat: container) {
            operator+=(stat);
        }
    }

    void AggregatedStatistics::recalculate_qps()
    {
        auto time_window = static_cast<double>(get_timestamp() - m_qps_timestamp);

        if (time_window)
            for (auto i = 0u; i < 4; i++) {
                qps[i] = static_cast<double >(queries[i] - m_old_aggregated_queries[i]) / time_window;
            }
        else
            qps.fill(0);

        m_qps_timestamp = get_timestamp();
        std::copy(queries.begin(), queries.end(), m_old_aggregated_queries.begin());
    }
}