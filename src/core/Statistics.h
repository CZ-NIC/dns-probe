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

#pragma once

#include <cstdint>
#include <string>
#include <sstream>
#include <atomic>
#include <vector>
#include <array>

namespace DDP {
    /**
     * Statistics for collection information from workers.
     */
    struct alignas(64) Statistics
    {
        /**
         * Constructor
         */
        Statistics() : packets(), transactions(), exported_records(), active_tt_records(), exported_to_pcap(),
                       queries() {}

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
        std::array<uint64_t, 4> queries; //!< Number of processed queries for IPv4, IPv6, TCP and UDP.

        constexpr static auto Q_IPV4 = 0u;
        constexpr static auto Q_IPV6 = 1u;
        constexpr static auto Q_TCP = 2u;
        constexpr static auto Q_UDP = 3u;
    };

    /**
     * Hold aggregated statistics from all workers and calculates queries per seconds.
     */
    struct AggregatedStatistics : public Statistics
    {
    public:
        /**
         * Constructor.
         */
        AggregatedStatistics() : Statistics(), qps(), m_qps_timestamp(get_timestamp()),
                                 m_old_aggregated_queries({0, 0, 0, 0}) {}

        /**
         * Copy constructor.
         * @param stats Source for copy.
         */
        AggregatedStatistics(const AggregatedStatistics& stats) = default;

        /**
         * Accumulate all statistics from given vector.
         * @param container Container with statistics to accumulate.
         */
        void aggregate(const std::vector<Statistics>& container);

        /**
         * Calculate new queries per second from last saved timestamp.
         */
        void recalculate_qps();

    private:
        static uint64_t get_timestamp(); //!< Provides timestamp in seconds.

    public:
        std::array<double, 4> qps; //!< Queries per second.

    private:
        uint64_t m_qps_timestamp; //!< Last timestamp used for calculating qps.
        std::array<uint64_t, 4> m_old_aggregated_queries; //!< Last aggravated count of queries.
    };
}
