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
#include "config/ConfigSysrepo.h"
#include "utils/Timer.h"
#include "utils/Logger.h"
#include "platform/Platform.h"
#include "platform/Mempool.h"
#include "export/BaseWriter.h"

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
                      m_sysrepo(nullptr), m_aggregated_timer(nullptr), m_output_timer(nullptr), m_comm_links(),
                      m_log_link(), m_dns_record_mempool(), m_export_rings(), m_factory_rings(), m_stats(),
                      m_stopped_workers(0), m_ret_value(ReturnValue::STOP) {}

DDP::ParsedArgs DDP::Probe::process_args(int argc, char** argv)
{
    DDP::Arguments args{};
    args.app = argv[0];
    int opt;

    while ((opt = getopt(argc, argv, "hi:p:rl:n:")) != EOF) {

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

            case 'l':
                logwriter.set_output(std::string(optarg));
                args.log_file = optarg;
                break;

            case 'n':
                args.instance_name = optarg;
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
              << "\t-p PCAP      : input pcap files. Parameter can repeat." << std::endl
              << "\t-i INTERFACE : " << interface << ". Parameter can repeat." << std::endl
              << "\t-r           : indicates RAW PCAPs as input. Can't be used together with -i parameter." << std::endl
              << "\t-l LOGFILE   : redirect probe's logs to LOGFILE instead of standard output" << std::endl
              << "\t-h           : this help message" << std::endl;
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
        m_sysrepo = &m_poll.emplace<DDP::ConfigSysrepo>(args.instance_name, m_cfg);
        if (args.raw_pcap)
            m_cfg.raw_pcap.from_sysrepo(args.raw_pcap);

        if (args.log_file.empty() && !m_cfg.log_file.value().empty())
            logwriter.set_output(m_cfg.log_file.value());

        for (auto& intf : m_cfg.interface_list.value()) {
            args.interfaces.emplace_back(intf);
        }

        for (auto& pcap : m_cfg.pcap_list.value()) {
            args.pcaps.emplace_back(pcap);
        }

        if (args.interfaces.empty() && args.pcaps.empty())
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
        throw std::runtime_error("Configuration was not loaded from Sysrepo yet!");

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

        if (m_cfg.export_location.value() == ExportLocation::REMOTE)
            TlsCtx::getInstance().init(m_cfg.export_ca_cert.value());

        m_initialized = true;
    } catch (...) {
        process_log_messages();
        throw;
    }
}


DDP::Probe::ReturnValue DDP::Probe::run(std::vector<std::shared_ptr<DDP::Port>>& ports)
{
    if (!m_initialized)
        throw std::runtime_error("Application is not initialized!");

    Logger logger("Probe");

    auto worker_runner = [this, &ports](unsigned worker, Statistics& stats, unsigned queue) {
        try {
            Worker w(m_cfg, stats, m_factory_rings.at(worker).get_poll_able_ring(), m_comm_links[worker].worker_endpoint(),
                    *m_dns_record_mempool, *m_tcp_connection_mempool, queue, ports,
                    m_cfg.match_qname, worker);
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

    auto queue = 0;
    for (auto worker: slaves) {
        m_thread_manager->run_on_thread(worker, worker_runner, worker, std::ref(m_stats[stats_index++]), queue++);
    }

    logger.info() << "Slave threads started.";

    m_aggregated_timer->arm(1000);
    if (m_output_timer)
        m_output_timer->arm(m_cfg.file_rot_timeout.value() * 1000);

    m_running = true;
    m_poll.enable();
    m_poll.loop();

    logger.info() << "Loop stopped. Waiting for workers to join.";
    process_log_messages();

    m_thread_manager->join_all_threads();
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
}

DDP::AggregatedStatistics DDP::Probe::statistics()
{
    m_aggregated_stats.aggregate(m_stats);
    return m_aggregated_stats;
}

void DDP::Probe::worker_stopped(unsigned)
{
    m_stopped_workers++;
    if(m_stopped_workers == slaves_cnt() - 1)
        stop();
}
