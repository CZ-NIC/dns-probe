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

#ifndef PROBE_CONFIG
#define PROBE_CONFIG ""
#endif

#include <cstdint>
#include <string>
#include <list>

namespace DDP {
    /**
     * @brief Structure representing a PCI device
     */
    struct PciDevice {
        std::string driver;
        std::string orig_driver;
        std::string class_;
        std::string vendor;
        std::string pci_id;
        std::list<std::string> if_name;
    };
    /**
     * @brief Structure for unified program arguments
     */
    struct Arguments
    {
        bool exit; //!< Signals that application should exit
        const char* app = "app"; //<! Contains name of currently running application (usually argv[0])
        std::list<std::string> interfaces; //<! List of interfaces used for listening for incoming DNS data
        std::list<PciDevice> devices; //<! List of PCI devices corresponding to interfaces list (used in DPDK version)
        std::list<std::string> pcaps; //<! List of PCAPs with data for processing
        std::list<std::string> dnstap_sockets; //<! List of unix sockets to process dnstap data from
        std::string knot_socket_path; //<! Path to directory in which to create Knot interface sockets
        uint32_t knot_socket_count; //<! Number of Knot interface sockets to create
        std::string log_file; //!< Log file to store probe's logs
        std::string instance_name = "default"; //!< Instance name used for getting YAML configuration
        std::string conf_file = PROBE_CONFIG; //!< YAML file to load initial configuration from
        bool raw_pcap;
    };
}
