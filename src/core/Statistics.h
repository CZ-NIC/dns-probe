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

#include <cstdint>
#include <string>
#include <sstream>
#include <atomic>
#include <vector>
#include <array>
#include <list>
#include <cstring>

namespace DDP {
    /**
     * Statistics for collection information from workers.
     */
    struct alignas(64) Statistics
    {
        constexpr static auto Q_IPV4 = 0u;
        constexpr static auto Q_IPV6 = 1u;
        constexpr static auto Q_TCP = 2u;
        constexpr static auto Q_UDP = 3u;
        constexpr static auto Q_DOT = 4u;
        constexpr static auto Q_DOH = 5u;

        constexpr static auto QUERY_STATS_SIZE = 6u;
        constexpr static auto ENTROPY_ARRAY_SIZE = 256u;

        using QueryStatsArray = std::array<uint64_t, QUERY_STATS_SIZE>;

        /**
         * Constructor
         * @param size Number of distinct query statistics instances to track. Depends on value of
         * export_stats configuration and number of IPs in ipv4_allowlist and ipv6_allowlist.
         */
        Statistics(std::size_t size = 1) : packets(), transactions(), exported_records(),
            active_tt_records(), exported_to_pcap(), ipv4_src_entropy_cnts(), queries(size, {0,0,0,0,0,0}) {
                std::memset(ipv4_src_entropy_cnts, 0, sizeof(ipv4_src_entropy_cnts));
        }

        /**
         * Copy constructor.
         * @param stats Data source.
         */
        Statistics(const Statistics& stats) = default;

        /**
         * Add and assign operator used for aggregating statistics.
         * @param rhs Added statistic instance.
         * @return Reference to accumulated statistics
         */
        Statistics& operator+=(const Statistics& rhs);

        /**
         * Creates string representation of the config.
         * @return Text representation of the config.
         */
        std::string string();

        /**
         * Accumulate statistics.
         * @param lhs Left side of the plus operator.
         * @param rhs Right side of the plus operator.
         * @return Acummulated statistics.
         */
        friend Statistics operator+(Statistics lhs, const Statistics& rhs) { return lhs += rhs; }

        uint64_t packets; //!< Number of processed packets.
        uint64_t transactions; //!< Number of processed transactions.
        uint64_t exported_records; //!< Number of exported records.
        uint64_t active_tt_records; //!< Number of active records in transaction table.
        uint64_t exported_to_pcap; //!< Number of packets exported to PCAP.
        uint64_t ipv4_src_entropy_cnts[ENTROPY_ARRAY_SIZE]; //!< Number of queries for each source "A" class IP block
        std::vector<QueryStatsArray> queries; //!< Number of processed queries for IPv4, IPv6, UDP, TCP/53, DoT and DoH.
    };

    /**
     * Hold aggregated statistics from all workers and calculates queries per seconds.
     */
    struct AggregatedStatistics : public Statistics
    {
    public:
        /**
         * Constructor.
         * @param size Number of distinct query statistics instances to track. Depends on value of
         * export_stats configuration and number of IPs in ipv4_allowlist and ipv6_allowlist.
         */
        AggregatedStatistics(std::size_t size = 1) : Statistics(size), qps(size, {0,0,0,0,0,0}),
             ipv4_src_entropy(0.0), m_qps_timestamp(get_timestamp()),
             m_old_aggregated_queries(size, {0,0,0,0,0,0}), m_moving_avg(), m_moving_avg_window(300) {
                std::memset(m_old_ipv4_src_entropy_cnts, 0, sizeof(m_old_ipv4_src_entropy_cnts));
        }

        /**
         * Copy constructor.
         * @param stats Source for copy.
         */
        AggregatedStatistics(const AggregatedStatistics& stats) = default;

        /**
         * @brief Accumulate all statistics from given vector.
         * @param container Container with statistics to accumulate.
         */
        void aggregate(const std::vector<Statistics>& container);

        /**
         * @brief Calculate new qps value from last saved timestamp and save it
         * to moving average list.
         */
        void recalculate_qps();

        /**
         * @brief Accumulate all statistics from given vector and calculate current
         * moving average of queries per second.
         * @param container Container with statistics to accumulate.
         */
        void get(const std::vector<Statistics>& container);

        /**
         * @brief Update moving average window for calculating qps statistics.
         * @param new_window New window in seconds.
         */
        void update_window(uint32_t new_window) {
            if (new_window <= 0)
                return;

            m_moving_avg_window = new_window;
        }

    private:
        static uint64_t get_timestamp(); //!< Provides timestamp in seconds.

    public:
        std::vector<QueryStatsArray> qps; //!< Queries per second.
        double ipv4_src_entropy; //!< Entropy for highest byte of source IPv4 addresses of queries.

    private:
        uint64_t m_qps_timestamp; //!< Last timestamp used for calculating qps.
        std::vector<QueryStatsArray> m_old_aggregated_queries; //!< Last aggregated count of queries.
        std::list<std::vector<QueryStatsArray>> m_moving_avg; //!< Last m_moving_avg_window values of avg qps for calculating moving average.
        uint32_t m_moving_avg_window; //!< Moving average window in seconds.
        uint64_t m_old_ipv4_src_entropy_cnts[ENTROPY_ARRAY_SIZE]; //!< Last aggregated count of queries per highest byte of IPv4 client address.
    };
}
