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

#include <sys/stat.h>
#include "Exporter.h"
#include "utils/Logger.h"
#include "utils/Ring.h"
#include "utils/PollAbleRing.h"
#include "Probe.h"


DDP::Exporter::Exporter(DDP::Config& cfg, DDP::Statistics& stats,
                        std::unordered_map<unsigned, PollAbleRingFactory<boost::any>>& rings_factories,
                        DDP::CommLink::CommLinkEP& comm_link, unsigned process_id) :
        Process(cfg, stats, comm_link),
        m_writer(nullptr),
        m_process_id(process_id),
        m_rings(),
        m_rotation_in_progress(false),
        m_received_worker_mark(rings_factories.size(), false),
        m_current_mark(0),
        m_mark_count(0)
{
    if (cfg.export_format.value() == ExportFormat::PARQUET) {
        m_writer = new ParquetWriter(cfg, process_id);
    }
    else {
        m_writer = new CdnsWriter(cfg, process_id);
    }

    // Prepare PollAble rings
    int i = 0;
    auto number_of_rings = rings_factories.size();
    for(auto&& ring_factory: rings_factories)
    {
        auto dequeue_cb = [this, i, number_of_rings](Ring<boost::any>& ring){
            // Try to dequeue item from ring
            // Skip if file rotation is going on and this ring already sent a mark
            if (!m_rotation_in_progress || (m_rotation_in_progress && !m_received_worker_mark[i]))
                dequeue(ring, i);

            // Rotate output if marks from all rings have been received
            if (m_mark_count == number_of_rings) {
                m_rotation_in_progress = false;
                for (auto&& mark : m_received_worker_mark)
                    mark = false;

                m_mark_count = 0;
                m_writer->rotate_output();
                Logger("Export").debug() << "Output file rotated";
            }
        };
        m_poll.emplace<PollAbleRing<boost::any, decltype(dequeue_cb)>>(ring_factory.second.get_poll_able_ring_cb(dequeue_cb));
        m_rings.push_back(&ring_factory.second.ring());
        i++;
    }
}

DDP::Exporter::~Exporter()
{
    int i = 0;
    for (auto&& ring : m_rings) {
        while (!ring->empty()) {
            dequeue(*ring, i);
        }
        i++;
    }

    delete m_writer;
}

int DDP::Exporter::run()
{
    try {
        m_poll.loop();
        return 0;
    }
    catch (std::exception& e) {
        Logger("ExportWorker").error() << "Export worker on core " << m_process_id << " crashed. Cause: " << e.what();
        m_comm_link.send(Message(Message::Type::STOP));
        return -1;
    }
}

DDP::ExporterRetCode DDP::Exporter::dequeue(Ring<boost::any>& ring, unsigned worker_id) {
    try {
        // dequeue from ring buffer
        auto item = ring.pop();

        // try to write DNS records to file
        if (item) {
            // Output rotation mark received
            if (item.value().type() == typeid(uint64_t)) {
                m_rotation_in_progress = true;
                m_received_worker_mark[worker_id] = true;
                m_current_mark = boost::any_cast<uint64_t>(item.value());
                m_mark_count++;
            }
            // Item with DNS records received
            else {
                m_stats.exported_records += m_writer->write(item.value());
            }
        }
    }
    catch(std::exception& e) {
        Logger("Writer").debug() << "Couldn't write to file";
        return ExporterRetCode::EXPORTER_WRITE_ERROR;
    }

    return ExporterRetCode::EXPORTER_OK;
}

void DDP::Exporter::new_config(Config& cfg)
{
    m_cfg = cfg;
    m_writer->update_configuration(cfg);
}
