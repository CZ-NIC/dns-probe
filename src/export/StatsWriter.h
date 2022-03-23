/*
 *  Copyright (C) 2021 CZ.NIC, z. s. p. o.
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

#include <bitset>
#include <functional>

#include "config/Config.h"
#include "core/Statistics.h"
#include "BaseWriter.h"

namespace DDP {
    /**
     * @brief Class for writing run-time statistics in JSON format to output
     */
    class StatsWriter : public BaseWriter {
    public:
        /**
         * @brief Construct a new Stats Writer object
         * @param cfg Configuration of the output
         * @param process_id Process ID used for generating names of the output files (unused)
         * @throw std::runtime_error
         */
        StatsWriter(Config& cfg, uint32_t process_id = 0)
            : BaseWriter(cfg, process_id, ".json") {}

        ~StatsWriter() {
            for (auto&& th : m_threads) {
                th.wait();
            }
        }

        /**
         * @brief Write given item with run-time statistics to JSON output
         * @param item Item with run-time statistics ready for export to ouput
         * @return Number of bytes written to output
         */
        int64_t write(boost::any item) {
            if (item.type() != typeid(AggregatedStatistics))
                return 0;

            return write(boost::any_cast<AggregatedStatistics>(item));
        }

        /**
         * @brief Write given aggregated run-time statistics to JSON output
         * @param item Aggregated statistics ready for export to output
         * @return Number of bytes written to output
         */
        int64_t write(AggregatedStatistics item);

        /**
         * @brief Generate filename for JSON file with run-time statistics
         * @return Newly generated filename
         */
        std::string filename();

        /**
         * @brief Unused BaseWriter virtual method
         */
        void rotate_output() {}

    private:
        /**
         * @brief Write run-time statistics about queries to JSON ouptut
         * @param output Output stream
         * @param comma Check to write a comma before new JSON item
         * @param cb Callback to optionally write IP address as part of item name
         * @param queries Array of cummulative query statistics
         * @param qps Array of queries per second statistics
         */
        void write_queries_stats(std::ofstream& output, bool& comma, std::function<void()> cb,
            std::array<uint64_t, 4>& queries, std::array<uint64_t, 4>& qps);
    };
}
