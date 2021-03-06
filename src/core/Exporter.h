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

#include <memory>
#include <unordered_map>

#include "config/Config.h"
#include "utils/Logger.h"
#include "Statistics.h"
#include "Process.h"
#include "export/BaseWriter.h"

#ifdef PROBE_PARQUET
#include "export/parquet/ParquetWriter.h"
#endif

#ifdef PROBE_CDNS
#include "export/cdns/CdnsWriter.h"
#endif

namespace DDP {

    /**
     * @brief Return codes for DNS record export
     */
    enum class ExporterRetCode : uint8_t {
        EXPORTER_OK = 0,
        EXPORTER_WRITE_ERROR
    };

    /**
     * @brief Class to read objects containing DNS records from ring buffer and write them to file
     */
    class Exporter : public Process {
    public:
        /**
         * @brief Exporter constructor. Sets up writer and all other necessary configuration
         * @param cfg Configuration
         * @param stats Reference to object with traffic statistics
         * @param rings Collection of export ring buffers containing objects with buffered DNS records
         * @param comm_link Communication queue with configuration lcore
         * @param process_id Process identifier, used in generation of exported file's names
         */
        Exporter(Config& cfg, Statistics& stats,
                 std::unordered_map<unsigned, PollAbleRingFactory<boost::any>>& factory_rings,
                 CommLink::CommLinkEP& comm_link, unsigned process_id);

        /**
         * @brief Exporter destructor. Write everything currently in ring buffers before destruction
         */
        ~Exporter() override;

        /**
         * @brief Main export lcore loop.
         * @return Returns 0 because DPDK
         */
        int run() override;

        /**
         * @brief Dequeue one object containing DNS records from ring buffer and write them to file
         * @param ring Export ring of one of the workers
         * @param worker_id Number of the ring in m_received_worker_mark vector
         * @return If successful EXPORTER_OK, otherwise corresponding error code
         */
        ExporterRetCode dequeue(Ring<boost::any>& ring, unsigned worker_id);

    protected:
        void new_config(Config& cfg) override;

    private:
        std::unique_ptr<BaseWriter> m_writer;
        unsigned m_process_id;
        std::vector<Ring<boost::any>*> m_rings;

        bool m_rotation_in_progress;
        std::vector<bool> m_received_worker_mark;
        uint64_t m_current_mark;
        uint8_t m_mark_count;
    };
}