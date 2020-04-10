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

#include <set>
#include "export/DnsExport.h"
#include "export/DnsWriter.h"
#include "core/DnsRecord.h"
#include "Process.h"
#include "utils/Logger.h"
#include "config/Config.h"
#include "core/TransactionTable.h"
#include "core/DnsParser.h"
#include "core/DnsTcpConnection.h"
#include "export/ParquetExport.h"
#include "export/ParquetWriter.h"
#include "export/CdnsExport.h"
#include "export/CdnsWriter.h"
#include "export/PcapWriter.h"
#include "utils/PollAbleRing.h"
#include "core/Statistics.h"
#include "core/Port.h"

namespace DDP {
    // Number of processed packets after which transaction table timetout is triggered
    constexpr static int TT_TIMEOUT_COUNT = 1024;

    /**
     * @brief Return codes for packet processing
     */
    enum class WorkerRetCode : uint8_t {
        WORKER_OK = 0,
        WORKER_PARSE_ERROR,
        WORKER_EXPORT_ERROR,
        WORKER_NON_DNS_PACKET,
    };

    class Worker : public Process {
        class PortPollAble : public PollAble {
        public:
            PortPollAble(Worker& worker, int port_pos) :
                    PollAble(PollEvents::READ),
                    m_worker(worker),
                    m_port(*m_worker.m_ports[port_pos]),
                    m_port_pos(port_pos),
                    m_queue(m_worker.m_lcore_queue) {}

            void ready_read() override;

            int fd() override { return m_port.fds()[m_queue]; }

        private:
            Worker& m_worker;
            Port& m_port;
            int m_port_pos;
            unsigned m_queue;
        };
    public:
        /**
         * @brief Constructor. Creates worker core object with packet processing loop
         * @param cfg Dynamic configuration
         * @param ring Export queue
         * @param comm_link Communication queue to configuration lcore
         * @param record_mempool Mempool for DNS record structures
         * @param tcp_mempool Mempool for TCP connection structures
         * @param lcore_queue NIC RX/TX queue for given process
         * @param ports Network ports to handle for given process
         * @param match_qname True if records should be matched by QNAME
         * @param process_id ID of core where Worker is spawned
         * @throw std::bad_alloc From calling TransactionTable constructor
         * @throw std::invalid_argument From calling TransactionTable constructor
         * @throw DnsParserConstructor From calling DnsParser constructor
         */
        Worker(Config& cfg, Statistics& stats, PollAbleRing<boost::any> ring,
               CommLink::CommLinkEP& comm_link, Mempool<DnsRecord>& record_mempool,
               Mempool<DnsTcpConnection>& tcp_mempool, unsigned lcore_queue, std::vector<std::shared_ptr<DDP::Port>> ports,
               bool match_qname, unsigned process_id) :
                Process(cfg, stats, comm_link),
                m_record_mempool(record_mempool),
                m_tcp_mempool(tcp_mempool),
                m_export_ring(std::move(ring)),
                m_tt_timeout_count(0),
                m_transaction_table(cfg.tt_size, cfg.tt_timeout,
                                    cfg.match_qname),
                m_parser(cfg, process_id, record_mempool, tcp_mempool, stats),
                m_exporter(nullptr),
                m_output_rotation_counter(0),
                m_pcap_all(cfg, cfg.pcap_export.value() == PcapExportCfg::INVALID, process_id),
                m_lcore_queue(lcore_queue),
                m_ports(std::move(ports)),
                m_match_qname(match_qname),
                m_total_rx_count(0),
                m_process_id(process_id)
        {
            if (cfg.export_format.value() == ExportFormat::PARQUET)
                m_exporter = new ParquetExport(cfg.parquet_records.value());
            else
                m_exporter = new CdnsExport(cfg.cdns_fields.value(), cfg.cdns_records_per_block.value());
        }

        /**
         * @brief Destructor. Writes leftover buffered records to Parquet file
         */
        ~Worker() override {
            DnsWriter* writer = nullptr;
            try {
                if (m_cfg.export_format.value() == ExportFormat::PARQUET)
                    writer = new ParquetWriter(m_cfg, m_process_id);
                else
                    writer = new CdnsWriter(m_cfg, m_process_id);

                m_exporter->write_leftovers(writer, m_stats);
                delete writer;
            }
            catch (std::exception& e) {
                delete writer;
                Logger("Export").debug() << "Couldn't write leftovers on worker " << m_process_id
                                         << " (" << e.what() << ")";
            }

            delete m_exporter;
        }

        // Delete copy constructor and assignment operator
        Worker(const Worker&) = delete;
        Worker& operator=(const Worker) = delete;

        /**
         * @brief Main worker lcore loop.
         * @return Returns 0 because DPDK
         */
        int run() override;

        /**
         * @brief Main processing method. Parses given packet, matches query-response pair in transaction table
         * and if matched buffers DNS record and if there's enough DNS records buffered tries to enqueue
         * ExporterFormat object containing buffered DNS records to export ring buffer
         * @param pkt Packet to process
         * @return Returns PROBE_OK if successful, otherwise returns corresponding error code
         */
        WorkerRetCode process_packet(const Packet& pkt);

        /**
         * @brief Clears everything from transaction table and sends all cleared DNS records for export
         */
        void tt_cleanup() {
            try {
                m_transaction_table.cleanup([this](DnsRecord& rec){this->m_parser.put_back_record(rec);});
            }
            catch (std::exception& e) {
                Logger("TT").debug() << "Cleanup failed: " << e.what();
            }
        }

        /**
         * @brief Enqueue buffered DNS records to export ring buffer
         * @param item Object containing buffered DNS records
         */
        template<typename T>
        void enqueue(T item) {
            try {
                m_export_ring.push(std::move(item));
            }
            catch(std::exception& e) {
                Logger("Export").debug() << "Export ring is full. Couldn't enqueue "
                                            "export object on lcore " << m_process_id;
            }
        }

    protected:
        void stop() override;
        /**
         * @brief Updated Probe's dynamic configuration
         * @param cfg New dynamic configuration
         */
        void new_config(Config& cfg) override;
        void rotate_output() override;
        void close_port(int pos);

    private:
        Mempool<DnsRecord>& m_record_mempool; //!< Mempool used for saving records extracted from DNS packets.
        Mempool<DnsTcpConnection>& m_tcp_mempool; //!< Mempool used for tracking TCP connections.
        PollAbleRing<boost::any> m_export_ring; //!< Export ring used for delivering data to exporter.
        uint32_t m_tt_timeout_count; //!< Currently processed packets before triggering timeout check.
        TransactionTable<DnsRecord> m_transaction_table; //!< Transaction table for records extracted from DNS packets.
        DnsParser m_parser; //!< DnsParser for creating records into transaction table.
        DnsExport* m_exporter; //!< Exporter instance preparing records for exporter thread.
        uint64_t m_output_rotation_counter; //!< Distinct different files when export file has time based rotation enabled.
        PcapWriter m_pcap_all; //!< PCAP writer for saving processed packets.
        unsigned m_lcore_queue; //!< Specify packet queue for worker.
        std::vector<std::shared_ptr<DDP::Port>> m_ports; //!< List of reading ports for DNS analysis.
        bool m_match_qname; //!< Enable comparing QNAME for matching in transaction table.
        uint32_t m_total_rx_count; //!< Maximal number of packets read from queue in one run.
        unsigned m_process_id; //!< Lcore of the worker.
    };
}