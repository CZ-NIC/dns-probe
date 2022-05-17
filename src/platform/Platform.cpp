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

#include "platform/Platform.h"

#ifdef USE_DPDK
#include <vector>
#include <string>
#include <iostream>
#include <rte_lcore.h>
#include "utils/Logger.h"
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
void DDP::init_platform(const DDP::Arguments& args, const Config& cfg)
{
#ifdef USE_DPDK
    std::stringstream conv;
    conv << cfg.coremask.string();

    std::vector<std::string> argv;
    argv.emplace_back(args.app);
#ifdef DPDK_LEGACY_MEM
    argv.emplace_back("--legacy-mem");
#endif
    argv.emplace_back("-c");
    argv.emplace_back(conv.str());

    for(auto& interface: args.devices) {
#ifdef DPDK_21_11
        argv.emplace_back("-a");
#else
        argv.emplace_back("-w");
#endif
        argv.emplace_back(interface.pci_id.c_str());
    }

    auto i = 0;
    for(auto& pcap: args.pcaps) {
        argv.emplace_back("--vdev");
        std::stringstream net_pcap;
        net_pcap << "net_pcap" << i << ",rx_pcap=" << pcap;
        argv.emplace_back(net_pcap.str());
        i++;
    }

    if(!args.pcaps.empty() && args.interfaces.empty())
        argv.emplace_back("--no-pci");

    std::vector<char*> argv_char;
    for(auto& arg: argv) {
        argv_char.push_back(const_cast<char*>(arg.data()));
    }

    std::string cmd = "Running EAL with parameters: ";
    for(auto arg: argv_char) {
        cmd += arg + std::string(" ");
    }
    logwriter.log_lvl("INFO", cmd);

    if(rte_eal_init(argv_char.size(), argv_char.data()) < 0) {
        throw std::runtime_error("Initialization of eal failed!");
    }
#endif
}
#pragma GCC diagnostic pop
