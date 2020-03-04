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

#include "platform/Platform.h"

#ifdef USE_DPDK
#include <vector>
#include <string>
#include <iostream>
#include <rte_lcore.h>
#endif

void DDP::init_platform(const DDP::Arguments& args [[maybe_unused]], const Config& cfg [[maybe_unused]])
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

    for(auto& interface: args.interfaces) {
        argv.emplace_back("-w");
        argv.emplace_back(interface.c_str());
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
        argv_char.push_back(arg.data());
    }

    std::cerr << "Running EAL with parameters: ";
    for(auto arg: argv_char) {
        std::cerr << arg << " ";
    }
    std::cerr << std::endl;

    if(rte_eal_init(argv_char.size(), argv_char.data()) < 0) {
        throw std::runtime_error("Initialization of eal failed!");
    }
#endif
}