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

#include <set>
#include <memory>
#include <maxminddb.h>
#include "export/BaseExport.h"
#include "export/BaseWriter.h"
#include "core/DnsRecord.h"
#include "Process.h"
#include "utils/Logger.h"
#include "config/Config.h"
#include "core/TransactionTable.h"
#include "core/DnsParser.h"
#include "core/DnsTcpConnection.h"
#include "export/PcapWriter.h"
#include "utils/PollAbleRing.h"
#include "core/Statistics.h"
#include "core/Port.h"

#ifdef PROBE_DNSTAP
#include "dnstap/DnstapUnixReader.h"
#endif

#ifdef PROBE_PARQUET
#include "export/parquet/ParquetExport.h"
#include "export/parquet/ParquetWriter.h"
#endif

#ifdef PROBE_CDNS
#include "export/cdns/CdnsExport.h"
#include "export/cdns/CdnsWriter.h"
#endif

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
        /**
         * @brief Class polling for incoming packets on a network port
         */
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

        /**
         * @brief Class polling for incoming connections on a socket
         */
        class SocketPollAble : public PollAble {
        public:
            SocketPollAble(Worker& worker, int sock_pos) :
                    PollAble(PollEvents::READ),
                    m_worker(worker),
                    m_port(*m_worker.m_sockets[sock_pos]),
                    m_sock_pos(sock_pos),
                    m_queue(m_worker.m_lcore_queue) {}

            void ready_read() override;

            int fd() override { return m_port.fds()[0]; }
        private:
            Worker& m_worker;
            Port& m_port;
            int m_sock_pos;
            unsigned m_queue;
        };

        /**
         * @brief Class polling for incoming dnstap messages on a socket
         */
#ifdef PROBE_DNSTAP
        class DnstapPollAble : public PollAble {
        public:
            DnstapPollAble(Worker& worker, int fd) :
                PollAble(PollEvents::READ),
                m_worker(worker),
                m_fd(fd),
                m_reader(fd) {}

            void ready_read() override;

            int fd() override { return m_fd; }
        private:
            Worker& m_worker;
            int m_fd;
            DnstapUnixReader m_reader;
        };
#endif

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
               std::vector<std::shared_ptr<DDP::Port>> sockets, bool match_qname, unsigned process_id, MMDB_s& country_db,
               MMDB_s& asn_db) :
                Process(cfg, stats, comm_link),
                m_record_mempool(record_mempool),
                m_tcp_mempool(tcp_mempool),
                m_export_ring(std::move(ring)),
                m_tt_timeout_count(0),
                m_transaction_table(cfg.tt_size, cfg.tt_timeout,
                                    cfg.match_qname),
                m_parser(cfg, process_id, record_mempool, tcp_mempool, stats),
                m_exporter(nullptr),
                m_writer(nullptr),
                m_output_rotation_counter(0),
                m_pcap_all(cfg, false, process_id),
                m_lcore_queue(lcore_queue),
                m_ports(std::move(ports)),
                m_sockets(std::move(sockets)),
                m_match_qname(match_qname),
                m_total_rx_count(0),
                m_process_id(process_id)
        {
            if (cfg.export_format.value() == ExportFormat::PARQUET) {
#ifdef PROBE_PARQUET
                m_exporter = std::make_unique<ParquetExport>(cfg,country_db, asn_db);
                m_writer = std::make_unique<ParquetWriter>(cfg, process_id);
#else
                throw std::runtime_error("DNS Probe was built without Parquet support!");
#endif
            }
            else {
#ifdef PROBE_CDNS
                m_exporter = std::make_unique<CdnsExport>(cfg, country_db, asn_db);
                m_writer = std::make_unique<CdnsWriter>(cfg, process_id);
#else
                throw std::runtime_error("DNS Probe was built without C-DNS support!");
#endif
            }
        }

        /**
         * @brief Destructor. Writes leftover buffered records to Parquet file
         */
        ~Worker() override {
            try {
                m_writer->rotate_output();
                m_exporter->write_leftovers(m_writer.get(), m_stats);
            }
            catch (std::exception& e) {
                Logger("Export").warning() << "Couldn't write leftovers on worker " << m_process_id
                                         << " (" << e.what() << ")";
            }
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
        std::unique_ptr<BaseExport> m_exporter; //!< Exporter instance preparing records for exporter thread.
        std::unique_ptr<BaseWriter> m_writer; //!< Writer instance for writing leftover records on Worker shutdown.
        uint64_t m_output_rotation_counter; //!< Distinct different files when export file has time based rotation enabled.
        PcapWriter m_pcap_all; //!< PCAP writer for saving processed packets.
        unsigned m_lcore_queue; //!< Specify packet queue for worker.
        std::vector<std::shared_ptr<DDP::Port>> m_ports; //!< List of reading ports for DNS analysis.
        std::vector<std::shared_ptr<DDP::Port>> m_sockets; //!< List of reading sockets for DNS analysis.
        bool m_match_qname; //!< Enable comparing QNAME for matching in transaction table.
        uint32_t m_total_rx_count; //!< Maximal number of packets read from queue in one run.
        unsigned m_process_id; //!< Lcore of the worker.
    };
}