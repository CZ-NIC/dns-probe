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

#include <iostream>
#include <csignal>
#include <set>
#include <vector>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "core/Probe.h"
#include "dpdk/DpdkPort.h"
#include "dpdk/DpdkPcapPort.h"

static void signal_handler(int signum)
{
    std::cout << "App exiting on signal " << signum << std::endl;
    DDP::Probe::getInstance().stop();
}

int main(int argc, char** argv)
{
    DDP::ParsedArgs arguments;
    try {
        arguments = DDP::Probe::process_args(argc, argv);
    } catch(std::invalid_argument& e) {
        DDP::Probe::print_help(argv[0]);
        std::cout << e.what() << std::endl;
        return 1;
    }

    if(arguments.args.exit)
        return 0;

    auto& runner = DDP::Probe::getInstance();

    try {
        runner.init(arguments.args);
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl << "Probe init failed!" << std::endl;
        return 2;
    }

    std::vector<std::shared_ptr<DDP::Port>> ready_ports;
    try {
        // Port initialization
        std::set<uint16_t> ports;
        for (uint16_t i = 0; i < rte_eth_dev_count_avail(); i++) {
                ports.insert(i);
        }

        DDP::rte_mempool_t interface_mempool = {
            rte_pktmbuf_pool_create("rx_mbuf_pool", runner.config().tt_size,
                                    DDP::DPDKPort::MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id()),
            rte_mempool_free
        };

        if (!interface_mempool)
            throw std::runtime_error(std::string("Cannot init rx mbuf pool: ") + rte_strerror(rte_errno));

        for (auto port: ports) {
            rte_eth_dev_info info{};
            rte_eth_dev_info_get(port, &info);

            if(strcmp(info.driver_name, "net_pcap") == 0)
                ready_ports.emplace_back(new DDP::DPDKPcapPort(port, interface_mempool));
            else
                ready_ports.emplace_back(new DDP::DPDKPort(port, runner.slaves_cnt() - 1, interface_mempool));
        }

        // Set up signal handlers to print stats on exit
        struct sigaction sa{};
        sa.sa_handler = &signal_handler;
        sigfillset(&sa.sa_mask);

        sigaction(SIGINT, &sa, nullptr);
        sigaction(SIGTERM, &sa, nullptr);

        // Poll on configuration core
        try {
            return static_cast<int>(runner.run(ready_ports));
        } catch (std::exception &e) {
            std::cerr << "Uncaught exception: " << e.what() << std::endl;
            return 128;
        }
    } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 128;
    }
}