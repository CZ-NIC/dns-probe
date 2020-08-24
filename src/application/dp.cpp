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
#include <csignal>
#include <set>
#include <vector>
#include <thread>
#include <pthread.h>
#include "core/Probe.h"
#include "utils/Logger.h"
#include "non-dpdk/PcapPort.h"
#include "non-dpdk/AfPacketPort.h"

constexpr int PCAP_THREADS = 3;
DDP::LogWriter logwriter;

static void signal_handler(int signum)
{
    logwriter.log_lvl("INFO", "App exiting on signal ", signum);
    DDP::Probe::getInstance().stop();
}

int main(int argc, char** argv)
{
    DDP::ParsedArgs arguments;
    try {
        arguments = DDP::Probe::process_args(argc, argv);
    } catch(std::invalid_argument& e) {
        DDP::Probe::print_help(argv[0]);
        logwriter.log_lvl("ERROR", e.what());
        return static_cast<uint8_t>(DDP::Probe::ReturnValue::ERROR);
    }

    if(arguments.args.exit)
        return static_cast<uint8_t>(DDP::Probe::ReturnValue::STOP);

    auto& runner = DDP::Probe::getInstance();

    try {
        runner.load_config(arguments.args);
        runner.init(arguments.args);
    } catch (std::exception& e) {
        logwriter.log_lvl("ERROR", "Probe init failed: ", e.what());
        return static_cast<uint8_t>(DDP::Probe::ReturnValue::ERROR);
    }

    std::vector<std::shared_ptr<DDP::Port>> ready_ports;
    try {
        // Port initialization
        uint16_t id = 0;
        for (auto& port: arguments.args.interfaces) {
            ready_ports.emplace_back(new DDP::AFPacketPort(port.c_str(), runner.slaves_cnt() - 1, id));
            id++;
        }

        for (auto& port: arguments.args.pcaps) {
            ready_ports.emplace_back(new DDP::PCAPPort(port.c_str(), runner.slaves_cnt() - 1));
        }

        // Set up signal handlers to print stats on exit
        struct sigaction sa = {};
        sa.sa_handler = &signal_handler;
        sigfillset(&sa.sa_mask);
        sigaction(SIGINT, &sa, nullptr);
        sigaction(SIGTERM, &sa, nullptr);
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGPIPE);
        pthread_sigmask(SIG_BLOCK, &set, NULL);

        // Poll on configuration core
        try {
            return static_cast<int>(runner.run(ready_ports));
        } catch (std::exception &e) {
            logwriter.log_lvl("ERROR", "Uncaught exception: ", e.what());
            return static_cast<uint8_t>(DDP::Probe::ReturnValue::UNCAUGHT_ERROR);
        }

    } catch (std::exception& e) {
        logwriter.log_lvl("ERROR", e.what());
        return static_cast<uint8_t>(DDP::Probe::ReturnValue::UNCAUGHT_ERROR);
    }
}
