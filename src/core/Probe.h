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

#include <unordered_map>
#include <functional>
#include <vector>
#include <set>

#include "utils/Poll.h"
#include "utils/RingFwdDecl.h"
#include "config/Config.h"
#include "communication/CommLink.h"
#include "Statistics.h"
#include "core/DnsRecord.h"
#include "core/DnsTcpConnection.h"
#include "core/Arguments.h"
#include "platform/MempoolFwdDecl.h"
#include "utils/PollAbleRing.h"

namespace DDP {
    class TimerInterface;
    class Port;
    class ConfigFile;
    class CommLinkProxy;

    /**
     * Wrapper for application arguments and number of processed arguments.
     */
    struct ParsedArgs {
        Arguments args; //!< Parsed program arguments.
        unsigned parsed_arguments{}; //!< Number of parsed arguments from argv.
    };

    /**
     * @brief Singleton class representing DDP library
     */
    class Probe
    {
        friend CommLinkProxy;
    public:

        /**
         * Return values from run method
         */
        enum class ReturnValue {
            STOP, //!< Application gracefully stopped.
            RESTART, //!< Application stopped due to restart request.
            ERROR, //!< Application gracefully stopped due to caught error
            UNCAUGHT_ERROR = 128 //!< Application stopped due to uncaught error
        };

        Probe(const Probe&) = delete;
        Probe& operator=(const Probe&) = delete;

        /**
         * @brief Get instance of Probe singleton
         */
        static Probe& getInstance();

        /**
         * Process program arguments .
         * @param argc Number of arguments.
         * @param argv Array with arguments.
         * @return Structure with parsed arguments.
         */
        static ParsedArgs process_args(int argc, char** argv);

        /**
         * Print help on standard output
         * @param app Name of the application.
         */
        static void print_help(const char* app = nullptr);

        /**
         * @brief Loads configuration from configuration file.
         * @param args Program arguments to be filled with network ports and PCAPs to process
         */
        void load_config(Arguments& args);

        /**
         * @brief Initialize Probe singleton. Creates necessary memory pools and rings
         * @param workers Vector with IDs of worker cores
         * @throw std::runtime_error From multiple sources
         * @throw std::range_error From calling Ring constructor
         * @throw NMempoolException From non-DPDK Mempool constructor
         * @throw DPDKMempoolException From DPDK Mempool constructor
         */
        void init(const Arguments& args);

        /**
         * @brief Run configuration core loop on master core
         * @throw std::runtime_error
         * @return Reason why the runner stopped.
         */
        ReturnValue run(std::vector<std::shared_ptr<DDP::Port>>& ports);

        /**
         * Access main loop
         * @return Main loop object
         */
        Poll& loop() { return m_poll; }

        /**
         * @brief Stop Probe library. Sends STOP messages to all worker and exporter threads and stops configuration core loop
         */
        void stop(bool restart = false);

        /**
         * @brief Update library configuration. Sends new configuration to all worker and exporter threads.
         */
        void update_config();

        /**
         * Provides modifiable access to application config.
         * @return
         */
        Config& config() { return m_cfg; }

        /**
         * Aggregate statistics from workers.
         * @return Aggregated statistics from all workers.
         */
        AggregatedStatistics statistics();

        /**
         * Provides access to communication link for sending log messages.
         * @return Endpoint for sending messages.
         */
        CommLink::CommLinkEP& log_link() { return m_log_link->worker_endpoint(); }

        /**
         * @brief Get number of slave threads
         */
        auto slaves_cnt() { return m_thread_manager->count() - 1; }

        /**
         * Access the thread manager.
         * @return Thread manager used for managing threads.
         */
        const ThreadManager& thread_manager() {return *m_thread_manager; }

        /**
         * Inform application that worker stopped.
         * @param lcore LCore of stopped worker.
         */
        void worker_stopped(unsigned lcore);

    protected:
        /**
         * Constructor
         */
        Probe();

        /**
         * Read all messages from log commlink and writes them to the output.
         */
        void process_log_messages() const;

        bool m_cfg_loaded; //!< Information that application loaded configuration file.
        bool m_initialized; //!< Information that application is initialized with call DDP::Probe::init.
        bool m_running; //!< Information that main application is in main loop.

        Poll m_poll; //!< Backend for main loop.
        Config m_cfg; //!< Application configuration.
        ConfigFile* m_cfgfile;
        TimerInterface* m_aggregated_timer; //!< Timer for automatic aggregating statistics and calculating qps.
        TimerInterface* m_output_timer; //!< Timer for automatic rotation of output files

        std::unique_ptr<ThreadManager> m_thread_manager; //!< Thread manager for worker cores.
        std::unordered_map<unsigned, CommLink> m_comm_links; //!< Communication links between master core and workers.
        std::unique_ptr<CommLink> m_log_link; //!< Communication for sending log messages.
        std::unique_ptr<Mempool<DnsRecord>> m_dns_record_mempool; //!< Mempool for DNS records.
        std::unique_ptr<Mempool<DnsTcpConnection>> m_tcp_connection_mempool; //!< Mempool for TCP connections.
        std::unordered_map<unsigned, std::unique_ptr<Ring<boost::any>>> m_export_rings; //!< Rings for sending data from workers to exporter.
        std::unordered_map<unsigned, PollAbleRingFactory<boost::any>> m_factory_rings;

        std::vector<Statistics> m_stats; //!< Statistics structure for workers. One item in vector per worker.
        AggregatedStatistics m_aggregated_stats; //!< Aggregated statistics from workers.

        unsigned m_stopped_workers; //!< Number of stopped workers.
        ReturnValue m_ret_value; //!< Return value from runner.
    };
}
