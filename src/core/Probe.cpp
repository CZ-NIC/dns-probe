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

#include <iostream>
#include <cstdint>
#include <utility>
#include <tuple>
#include <getopt.h>

#ifdef PROBE_CRYPTOPANT
#include <cryptopANT.h>
#endif

#include "Probe.h"
#include "Worker.h"
#include "Exporter.h"
#include "core/Port.h"
#include "config/ConfigFile.h"
#include "utils/Timer.h"
#include "utils/Logger.h"
#include "platform/Platform.h"
#include "platform/Mempool.h"
#include "export/BaseWriter.h"
#include "export/StatsWriter.h"

namespace DDP {
    class CommLinkProxy : public PollAble
    {
    public:
        explicit CommLinkProxy(CommLink::CommLinkEP& ep) : m_ep(ep) {}

        int fd() override { return m_ep.fd(); };

        void ready_read() override
        {
            auto message = m_ep.recv();
            if (!message)
                return;

            auto& app = Probe::getInstance();

            switch (message->type()) {
                case Message::Type::NEW_CONFIG:
                    break;

                case Message::Type::STOP:
                    app.stop();
                    break;

                case Message::Type::LOG:
                    logwriter.log(dynamic_cast<MessageLog*>(message.get())->msg.str());
                    break;

                case Message::Type::WORKER_STOPPED:
                    app.worker_stopped(dynamic_cast<MessageWorkerStopped*>(message.get())->lcore);
                    break;
                case Message::Type::ROTATE_OUTPUT:
                    break;
            }
        }

    private:
        CommLink::CommLinkEP& m_ep;
    };
}


DDP::Probe::Probe() : m_cfg_loaded(false), m_initialized(false), m_running(false), m_poll(), m_cfg(),
                      m_aggregated_timer(nullptr), m_output_timer(nullptr), m_comm_links(),
                      m_log_link(), m_dns_record_mempool(), m_export_rings(), m_factory_rings(),
                      m_country(), m_asn(), m_stats(), m_aggregated_stats(), m_stats_writer(),
                      m_stopped_workers(0), m_ret_value(ReturnValue::STOP) {}

DDP::Probe::~Probe()
{
    MMDB_close(&m_country);
    MMDB_close(&m_asn);
}

DDP::ParsedArgs DDP::Probe::process_args(int argc, char** argv)
{
    DDP::Arguments args{};
    args.app = argv[0];
    args.knot_socket_count = 0;
    int opt;

    while ((opt = getopt(argc, argv, "hi:p:rd:k:s:l:n:c:")) != EOF) {

        switch (opt) {
            case 'h':
                DDP::Probe::print_help(argv[0]);
                args.exit = true;
                break;

            case 'i':
                args.interfaces.emplace_back(optarg);
                break;

            case 'p':
                args.pcaps.emplace_back(optarg);
                break;

            case 'r':
                args.raw_pcap = true;
                break;

            case 'd':
                args.dnstap_sockets.emplace_back(optarg);
                break;

            case 'k':
                args.knot_socket_count = std::stoul(optarg);
                break;

            case 's':
                args.knot_socket_path = optarg;
                break;

            case 'l':
                logwriter.set_output(std::string(optarg));
                args.log_file = optarg;
                break;

            case 'n':
                args.instance_name = optarg;
                break;

            case 'c':
                args.conf_file = optarg;
                break;

            default:
                throw std::invalid_argument("Invalid arguments");
        }
    }

    ParsedArgs ret{args, static_cast<unsigned>(optind)};
    optind = 1;
    return ret;
}

void DDP::Probe::print_help(const char* app)
{
    if (app == nullptr) {
        app = "dns-probe";
    }

    std::string interface;
    if (BACKEND == PacketBackend::Socket)
        interface = "interface name e.g. eth0";
    else
        interface = "interface name e.g. eth0 or PCI ID e.g. 00:1f.6";

    std::cout << std::endl << app << std::endl
              << "\t-p PCAP             : input pcap files. Parameter can repeat." << std::endl
              << "\t-i INTERFACE        : " << interface << ". Parameter can repeat." << std::endl
              << "\t-r                  : indicates RAW PCAPs as input. Can't be used together with -i parameter." << std::endl
              << "\t-d DNSTAP_SOCKET    : path to input dnstap unix socket. Parameter can repeat." << std::endl
              << "\t-k KNOT_SOCKET_COUNT: number of Knot interface sockets to create" << std::endl
              << "\t-s KNOT_SOCKET_PATH : path to directory in which to create Knot interface sockets. Default \"/tmp\"." << std::endl
              << "\t-l LOGFILE          : redirect probe's logs to LOGFILE instead of standard output" << std::endl
              << "\t-n INSTANCE         : Unique identifier (for config purposes) for given instance of DNS Probe" << std::endl
              << "\t-c CONFIG_FILE      : YAML file to load initial configuration from." << std::endl
              << "\t-h                  : this help message" << std::endl;
}

DDP::Probe& DDP::Probe::getInstance()
{
    static DDP::Probe instance;
    return instance;
}

void DDP::Probe::load_config(Arguments& args)
{
    if (m_cfg_loaded)
        return;

    // Init logging
    m_log_link = std::make_unique<DDP::CommLink>(32, false);

    try {
        // Init configuration
        ConfigFile::load_configuration(m_cfg, args.conf_file, args.instance_name);
        m_cfg.instance.add_value(args.instance_name);

        if (args.raw_pcap)
            m_cfg.raw_pcap.add_value(args.raw_pcap);

        if (args.log_file.empty() && !m_cfg.log_file.value().empty())
            logwriter.set_output(m_cfg.log_file.value());

        for (auto& intf : m_cfg.interface_list.value()) {
            args.interfaces.emplace_back(intf);
        }

        for (auto& pcap : m_cfg.pcap_list.value()) {
            args.pcaps.emplace_back(pcap);
        }

        for (auto& dt_socket : m_cfg.dnstap_socket_list.value()) {
            args.dnstap_sockets.emplace_back(dt_socket);
        }

        if (args.knot_socket_count <= 0)
            args.knot_socket_count = m_cfg.knot_socket_count.value();

        if (args.knot_socket_path.empty())
            args.knot_socket_path = m_cfg.knot_socket_path.value();

#ifndef PROBE_DNSTAP
        if (!args.dnstap_sockets.empty())
            throw std::runtime_error("DNS Probe was built without dnstap support!");
#endif

#ifndef PROBE_KNOT
        if (args.knot_socket_count > 0)
            throw std::runtime_error("DNS Probe was built without Knot interface support!");
#endif

        if (args.interfaces.empty() && args.pcaps.empty() && args.dnstap_sockets.empty() && args.knot_socket_count <= 0)
            throw std::invalid_argument("At least one interface or pcap should be specified!");

        m_cfg_loaded = true;
    }
    catch (...) {
        process_log_messages();
        throw;
    }
}

void DDP::Probe::init(const Arguments& args)
{
    if (!m_cfg_loaded)
        throw std::runtime_error("Configuration was not loaded from configuration file yet!");

    if (m_initialized)
        return;

    try {
        init_platform(args, m_cfg);

        m_thread_manager = std::make_unique<ThreadManager>(m_cfg.coremask);
        m_dns_record_mempool = std::make_unique<Mempool<DnsRecord>>(m_cfg.tt_size, "dns_record_pool");
        m_tcp_connection_mempool = std::make_unique<Mempool<DnsTcpConnection>>(m_cfg.tcp_ct_size,
                                                                               "tcp_connection_pool");

        auto workers = m_thread_manager->slave_lcores();
        workers.erase(workers.begin());
        for (auto worker : workers) {
            m_export_rings[worker] = std::make_unique<Ring<boost::any>>(4, RING::SINGLE_PRODUCER);

            if (!m_export_rings[worker])
                throw std::runtime_error("Couldn't initialize export rings!");

            m_factory_rings.emplace(worker, PollAbleRingFactory<boost::any>(*m_export_rings[worker]));
        }

        m_poll.emplace<CommLinkProxy>(m_log_link->config_endpoint());

        // Creates communication channels for workers
        for (auto slave: m_thread_manager->slave_lcores()) {
            auto cl = m_comm_links.emplace(std::piecewise_construct,
                                           std::forward_as_tuple(slave),
                                           std::forward_as_tuple(32, true));
            m_poll.emplace<CommLinkProxy>(cl.first->second.config_endpoint());
            m_stats.push_back(Statistics());
        }
        m_aggregated_stats = AggregatedStatistics();

        if (m_cfg.moving_avg_window.value() < 1 || m_cfg.moving_avg_window.value() > 3600) {
            Logger("Probe").warning() << "Moving-avg-window value " << m_cfg.moving_avg_window.value()
                << " outside bounds (1 - 3600), setting to default 300!";
            m_cfg.moving_avg_window.add_value(300);
        }
        m_aggregated_stats.update_window(m_cfg.moving_avg_window.value());
        auto cb = [this] {
            m_aggregated_stats.aggregate(m_stats);
            m_aggregated_stats.recalculate_qps();
        };
        m_aggregated_timer = &m_poll.emplace<Timer<decltype(cb)>>(cb);

        if (m_cfg.file_rot_timeout.value() > 0) {
            auto sender = [this]() {
                for (auto& link : m_comm_links) {
                    link.second.config_endpoint().send(Message(Message::Type::ROTATE_OUTPUT));
                }
            };
            m_output_timer = &m_poll.emplace<Timer<decltype(sender)>>(sender);
        }

#ifndef PROBE_KAFKA
        if (m_cfg.export_location.value() == ExportLocation::KAFKA)
            throw std::runtime_error("DNS Probe was built without Apache Kafka support! Use 'local' or 'remote' options for DNS export!");

        if (m_cfg.stats_location.value() == ExportLocation::KAFKA)
            throw std::runtime_error("DNS Probe was built without Apache Kafka support! Use 'local' or 'remote' options for stats export!");
#endif

        m_stats_writer = std::make_unique<StatsWriter>(m_cfg);
        if (m_cfg.export_stats.value()) {
            auto export_cb = [this] {
                m_aggregated_stats.get(m_stats);
                m_stats_writer->write(m_aggregated_stats);
                Logger("Export").debug() << "Run-time statistics exported.";
            };
            m_export_aggregated_timer = &m_poll.emplace<Timer<decltype(export_cb)>>(export_cb);
        }

#ifndef PROBE_PARQUET
        if (m_cfg.export_format.value() == ExportFormat::PARQUET)
            throw std::runtime_error("DNS Probe was built without Parquet support! Use C-DNS as export format!");
#endif

#ifndef PROBE_CDNS
        if (m_cfg.export_format.value() == ExportFormat::CDNS)
            throw std::runtime_error("DNS Probe was built without C-DNS support! Use Parquet as export format!");
#endif

        if (m_cfg.anonymize_ip) {
#ifdef PROBE_CRYPTOPANT
            if (scramble_init_from_file(m_cfg.ip_enc_key.value().c_str(),
                static_cast<scramble_crypt_t>(m_cfg.ip_encryption.value()),
                static_cast<scramble_crypt_t>(m_cfg.ip_encryption.value()), nullptr) != 0)
                throw std::runtime_error("Couldn't initialize IP address anonymization!");
#else
            throw std::runtime_error("DNS Probe was built without IP anonymization support!");
#endif
        }

        if (!m_cfg.country_db.value().empty()) {
            int status = MMDB_open(m_cfg.country_db.value().c_str(), MMDB_MODE_MMAP, &m_country);
            if (status != MMDB_SUCCESS) {
                Logger("Probe").warning() << "Couldn't open Maxmind Country database!";
                m_country.filename = nullptr;
            }
        }
        else {
            m_country.filename = nullptr;
        }

        if (!m_cfg.asn_db.value().empty()) {
            int status = MMDB_open(m_cfg.asn_db.value().c_str(), MMDB_MODE_MMAP, &m_asn);
            if (status != MMDB_SUCCESS) {
                Logger("Probe").warning() << "Couldn't open Maxmind ASN database!";
                m_asn.filename = nullptr;
            }
        }
        else {
            m_asn.filename = nullptr;
        }

        if (m_cfg.export_location.value() == ExportLocation::REMOTE)
            TlsCtx::getInstance().init(TlsCtxIndex::TRAFFIC, m_cfg.export_ca_cert.value());

        if (m_cfg.export_stats.value() && m_cfg.stats_location.value() == ExportLocation::REMOTE)
            TlsCtx::getInstance().init(TlsCtxIndex::STATISTICS, m_cfg.stats_ca_cert.value());

        m_initialized = true;
    } catch (...) {
        process_log_messages();
        throw;
    }
}


DDP::Probe::ReturnValue DDP::Probe::run(PortVector& ports, PortVector& sockets, PortVector& knots)
{
    if (!m_initialized)
        throw std::runtime_error("Application is not initialized!");

    Logger logger("Probe");

    auto worker_runner = [this, &ports](unsigned worker, Statistics& stats, unsigned queue, PortVector w_sockets, PortVector w_knots) {
        try {
            Worker w(m_cfg, stats, m_factory_rings.at(worker).get_poll_able_ring(), m_comm_links[worker].worker_endpoint(),
                    *m_dns_record_mempool, *m_tcp_connection_mempool, queue, ports, w_sockets, w_knots,
                    m_cfg.match_qname, worker, m_country, m_asn);
            Logger logger("Worker");
            logger.info() << "Starting worker on lcore " << ThreadManager::current_lcore() << ".";
            w.run();
            logger.info() << "Worker on lcore " << ThreadManager::current_lcore() << " stopped.";
        }
        catch (std::exception& e) {
            Logger("Worker").error() << "Worker on core " << worker << " crashed. Cause: " << e.what();
            m_comm_links[worker].worker_endpoint().send(Message(Message::Type::STOP));
            return -1;
        }

        return 0;
    };

    auto exporter_runner = [this](unsigned exporter, Statistics& stats) {
        try {
            Exporter p(m_cfg, stats, m_factory_rings, m_comm_links[exporter].worker_endpoint(), exporter);
            Logger logger("Exporter");
            logger.info() << "Starting exporter on lcore " << ThreadManager::current_lcore() << ".";
            p.run();
            logger.info() << "Exporter on lcore " << ThreadManager::current_lcore() << " stopped.";
            }
        catch (std::exception& e) {
            Logger("Exporter").error() << "Export worker on core " << exporter << " crashed. Cause: " << e.what();
            m_comm_links[exporter].worker_endpoint().send(Message(Message::Type::STOP));
            return -1;
        }

        return 0;
    };

    auto stats_index = 0u;

    auto slaves = m_thread_manager->slave_lcores();
    m_thread_manager->run_on_thread(slaves[0], exporter_runner, slaves[0], std::ref(m_stats[stats_index++]));
    slaves.erase(slaves.begin());

    unsigned queue = 0;
    for (auto worker: slaves) {
        PortVector worker_sockets;
        auto index = queue;
        while (index < sockets.size()) {
            worker_sockets.push_back(sockets[index]);
            index += slaves.size();
        }

        PortVector worker_knots;
        index = queue;
        while (index < knots.size()) {
            worker_knots.push_back(knots[index]);
            index += slaves.size();
        }
        m_thread_manager->run_on_thread(worker, worker_runner, worker, std::ref(m_stats[stats_index++]),
            queue++, worker_sockets, worker_knots);
    }

    logger.info() << "Slave threads started.";

    m_aggregated_timer->arm(1000);
    if (m_output_timer)
        m_output_timer->arm(m_cfg.file_rot_timeout.value() * 1000);

    if (m_export_aggregated_timer && m_cfg.stats_timeout.value() > 0)
        m_export_aggregated_timer->arm(m_cfg.stats_timeout.value() * 1000);

    m_running = true;
    m_poll.enable();
    m_poll.loop();

    logger.info() << "Loop stopped. Waiting for workers to join.";
    process_log_messages();

    m_thread_manager->join_all_threads();

    // Write final statistics if enabled
    if (m_cfg.export_stats.value()) {
        m_aggregated_stats.get(m_stats);
        m_stats_writer->write(m_aggregated_stats);
        logger.debug() << "Run-time statistics exported.";
    }

    process_log_messages();

    return m_ret_value;
}

void DDP::Probe::process_log_messages() const
{
    std::unique_ptr<DDP::Message> message;
    while ((message = std::move(this->m_log_link->config_endpoint().recv())).get())
        logwriter.log(dynamic_cast<DDP::MessageLog*>(message.get())->msg.str());
}

void DDP::Probe::stop(bool restart)
{
    if ( !m_cfg_loaded || !m_initialized || !m_running)
        return;

    //Send stop message to all workers
    Logger("Probe").info() << "Sending stop to slaves.";
    for (auto& link : m_comm_links) {
        link.second.config_endpoint().send(Message(Message::Type::STOP));
    }

    m_running = false;
    m_poll.disable();
    m_ret_value = restart ? ReturnValue::RESTART : ReturnValue::STOP;
}

void DDP::Probe::update_config()
{
    // Send new config to all slave threads
    for (auto& link : m_comm_links) {
        link.second.config_endpoint().send(MessageNewConfig(m_cfg));
    }

    // Update output rotation timer if changed
    if (m_output_timer && (m_output_timer->get_interval() / 1000 != m_cfg.file_rot_timeout.value())) {
        m_output_timer->disarm();
        if (m_cfg.file_rot_timeout.value() > 0) {
            for (auto& link : m_comm_links) {
                link.second.config_endpoint().send(Message(Message::Type::ROTATE_OUTPUT));
            }
            m_output_timer->arm(m_cfg.file_rot_timeout.value() * 1000);
        }
    }
    else if (!m_output_timer && (m_cfg.file_rot_timeout.value() > 0)) {
        auto sender = [this]() {
            for (auto& link : m_comm_links) {
                link.second.config_endpoint().send(Message(Message::Type::ROTATE_OUTPUT));
            }
        };
        m_output_timer = &m_poll.emplace<Timer<decltype(sender)>>(sender, m_cfg.file_rot_timeout.value() * 1000);
    }

    // Update run-time statistics export if changed
    if (m_cfg.export_stats.value()) {
        if (m_aggregated_timer && (m_aggregated_timer->get_interval() / 1000 != m_cfg.stats_timeout.value())) {
            m_aggregated_timer->disarm();
            if (m_cfg.stats_timeout.value() > 0)
                m_aggregated_timer->arm(m_cfg.stats_timeout.value() * 1000);
        }
        else if (!m_aggregated_timer && (m_cfg.stats_timeout.value() > 0)) {
            auto export_cb = [this] {
                m_aggregated_stats.get(m_stats);
                m_stats_writer->write(m_aggregated_stats);
                Logger("Export").debug() << "Run-time statistics exported.";
            };
            m_export_aggregated_timer = &m_poll.emplace<Timer<decltype(export_cb)>>(export_cb, m_cfg.stats_timeout.value() * 1000);
        }
    }
    else {
        if (m_aggregated_timer)
            m_aggregated_timer->disarm();
    }

    // Update moving average window for run-time statistics calculation
    m_aggregated_stats.update_window(m_cfg.moving_avg_window.value());
}

DDP::AggregatedStatistics DDP::Probe::statistics()
{
    m_aggregated_stats.get(m_stats);
    return m_aggregated_stats;
}

void DDP::Probe::worker_stopped(unsigned)
{
    m_stopped_workers++;
    if(m_stopped_workers == slaves_cnt() - 1)
        stop();
}
