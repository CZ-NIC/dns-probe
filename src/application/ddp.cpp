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
#include <cstring>
#include <fstream>
#include <dirent.h>
#include <sys/stat.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_errno.h>

#include "core/Probe.h"
#include "utils/Logger.h"
#include "dpdk/DpdkPort.h"
#include "dpdk/DpdkPcapPort.h"
#include "core/UnixSocket.h"

#ifdef PROBE_KNOT
#include "knot/KnotSocket.h"
#endif

DDP::LogWriter logwriter;

static void signal_handler(int signum)
{
    logwriter.log_lvl("INFO", "App exiting on signal ", signum);
    DDP::Probe::getInstance().stop();
}

/**
 * @brief Check if 'uio_pci_generic' module is loaded
 * @return TRUE if module is loaded, FALSE otherwise
 */
static bool check_module()
{
    if (auto dir = opendir("/sys/module/")) {
        while (auto f = readdir(dir)) {
            if (!f || f->d_name[0] == '.')
                continue;

            if (std::strcmp("uio_pci_generic", f->d_name) == 0) {
                closedir(dir);
                return true;
            }
        }
        closedir(dir);
    }

    return false;
}

/**
 * @brief Unbind PCI device from its current driver
 * @param dev PCI device to unbind
 */
static void unbind(DDP::PciDevice& dev) {
    if (!dev.driver.empty()) {
        std::ofstream ofs("/sys/bus/pci/drivers/" + dev.driver + "/unbind", std::ios_base::app);
        if (ofs.fail())
            throw std::runtime_error("Couldn't unbind interface " + dev.pci_id + " from driver " + dev.driver);

        ofs.write(dev.pci_id.data(), dev.pci_id.size());
        ofs.close();
    }
}

/**
 * @brief Bind PCI device to given driver
 * @param dev PCI device to bind
 * @param driver Driver for PCI device
 */
static void bind(DDP::PciDevice& dev, std::string driver)
{
    // Unbind device from existing driver first
    if (dev.driver == driver)
        return;
    else
        unbind(dev);

    if (driver.empty())
        return;

    struct stat buffer;
    // For kernel >= 3.15
    if (stat(("/sys/bus/pci/devices/" + dev.pci_id + "/driver_override").c_str(), &buffer) == 0) {
        std::ofstream drv_ovr("/sys/bus/pci/devices/" + dev.pci_id + "/driver_override");
        if (drv_ovr.fail())
            throw std::runtime_error("Bind failed for " + dev.pci_id + "! Can't open driver_override file!");

        drv_ovr.write(driver.data(), driver.size());
        drv_ovr.close();
    }
    // For kernel < 3.15
    else {
        std::ofstream new_id("/sys/bus/pci/drivers/" + driver + "/new_id");
        if (new_id.fail())
            throw std::runtime_error("Bind failed for " + dev.pci_id + "! Can't open new_id file!");

        new_id.write(dev.vendor.data(), dev.vendor.size());
        new_id.close();
    }

    std::ofstream drv_bind("/sys/bus/pci/drivers/" + driver + "/bind", std::ios_base::app);
    if (drv_bind.fail())
        throw std::runtime_error("Bind failed for " + dev.pci_id + "! Can't open bind file!");

    drv_bind.write(dev.pci_id.data(), dev.pci_id.size());
    drv_bind.close();

    // For kernel >= 3.15
    if (stat(("/sys/bus/pci/devices/" + dev.pci_id + "/driver_override").c_str(), &buffer) == 0) {
        std::ofstream drv_ovr("/sys/bus/pci/devices/" + dev.pci_id + "/driver_override");
        if (drv_ovr.fail())
            throw std::runtime_error("Bind failed for " + dev.pci_id + "! Can't open driver_override file!");

        drv_ovr.write("\00", 1);
        drv_ovr.close();
    }

    dev.driver = driver;
}

/**
 * @brief Bind interfaces given to probe to DPDK drivers
 * @param args Probe's input arguments containing list of interfaces to use
 */
static void bind_interfaces(DDP::Arguments& args)
{
    // Check if uio_pci_generic module is loaded
    bool module = check_module();

    // Get list of network PCI devices on this machine
    std::list<DDP::PciDevice> dev_list;
    if (auto dir = opendir("/sys/bus/pci/devices/")) {
        while (auto f = readdir(dir)) {
            if (!f || f->d_name[0] == '.')
                continue;

            DDP::PciDevice tmp;
            std::ifstream uevent("/sys/bus/pci/devices/" + std::string(f->d_name) + "/uevent");
            if (uevent.fail())
                continue;

            std::string line;
            while (std::getline(uevent, line)) {
                std::string name = line.substr(0, line.find("="));
                std::string value = line.substr(line.find("=") + 1, line.size() - 1);
                if (name == "DRIVER")
                    tmp.orig_driver = tmp.driver = value;
                else if (name == "PCI_CLASS")
                    tmp.class_ = value;
                else if (name == "PCI_ID") {
                    std::replace(value.begin(), value.end(), ':', ' ');
                    tmp.vendor = value;
                }
                else if (name == "PCI_SLOT_NAME") {
                    std::transform(value.begin(), value.end(), value.begin(), tolower);
                    tmp.pci_id = value;
                }
            }
            uevent.close();

            if (auto dir2 = opendir(("/sys/bus/pci/devices/" + std::string(f->d_name) + "/net").c_str())) {
                while (auto g = readdir(dir2)) {
                    if (!g || g->d_name[0] == '.')
                        continue;

                    tmp.if_name.push_back(g->d_name);
                }
                closedir(dir2);
            }

            if (tmp.class_ == "20000")
                dev_list.push_back(tmp);
        }
        closedir(dir);
    }

    // Match interfaces given as input arguments with list of available PCI devices
    std::list<DDP::PciDevice> tobind;
    for (auto dev : args.interfaces) {
        bool found = false;
        std::string lower_dev(dev);
        std::transform(dev.begin(), dev.end(), lower_dev.begin(), tolower);
        for (auto pci : dev_list) {
            if (lower_dev == pci.pci_id || ("0000:" + lower_dev) == pci.pci_id) {
                tobind.push_back(pci);
                found = true;
                break;
            }

            for (auto ifn : pci.if_name) {
                if (dev == ifn) {
                    tobind.push_back(pci);
                    found = true;
                    break;
                }
            }

            if (found)
                break;
        }

        if (!found)
            throw std::runtime_error("Couldn't find interface: " + dev);
    }

    // Bind input interfaces to DPDK drivers
    for (auto& dev : tobind) {
        if (dev.driver == "uio_pci_generic" || dev.driver == "igb_uio" || dev.driver == "vfio-pci" ||
            dev.driver == "vfio_pci") {
            continue;
        }

        if (module)
            bind(dev, "uio_pci_generic");
        else
            throw std::runtime_error("Can't bind interface " + dev.pci_id + " to DPDK driver." +
                                      " Module uio_pci_generic not loaded!");
    }

    args.devices = tobind;
}

/**
 * @brief Unbind interfaces given to probe from DPDK drivers to their original ones
 * @param args Probe's input arguments containing list of interfaces to use
 */
static void unbind_interfaces(DDP::Arguments& args)
{
    for (auto& dev : args.devices) {
        bind(dev, dev.orig_driver);
    }
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
        bind_interfaces(arguments.args);
        runner.init(arguments.args);
    } catch (std::exception& e) {
        logwriter.log_lvl("ERROR", "Probe init failed: ", e.what());
        try {
            unbind_interfaces(arguments.args);
        }
        catch (std::exception& e) {
            logwriter.log_lvl("ERROR", "Couldn't unbind interfaces: ", e.what());
        }
        return static_cast<uint8_t>(DDP::Probe::ReturnValue::ERROR);
    }

    DDP::PortVector ready_ports;
    DDP::PortVector ready_sockets;
    DDP::PortVector ready_knots;
    try {
        // Port initialization
        std::set<uint16_t> ports;

#ifndef DPDK_LEGACY
        for (uint16_t i = 0; i < rte_eth_dev_count_avail(); i++) {
#else
        for (uint16_t i = 0; i < rte_eth_dev_count(); i++) {
#endif
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

            if(strcmp(info.driver_name, "net_pcap") == 0 || strcmp(info.driver_name, "Pcap PMD") == 0)
                ready_ports.emplace_back(new DDP::DPDKPcapPort(port, interface_mempool));
            else
                ready_ports.emplace_back(new DDP::DPDKPort(port, runner.slaves_cnt() - 1, interface_mempool));
        }

        for (auto& port : arguments.args.dnstap_sockets) {
            ready_sockets.emplace_back(new DDP::UnixSocket(port.c_str(), runner.config().dnstap_socket_group.value()));
        }

#ifdef PROBE_KNOT
        for (unsigned i = 0; i < arguments.args.knot_socket_count; i++) {
            ready_knots.emplace_back(new DDP::KnotSocket(arguments.args.knot_socket_path, i + 1));
        }
#endif

        // Set up signal handlers to print stats on exit
        struct sigaction sa{};
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
            auto ret = static_cast<int>(runner.run(ready_ports, ready_sockets, ready_knots));
            try {
                unbind_interfaces(arguments.args);
            }
            catch (std::exception& e) {
                logwriter.log_lvl("ERROR", "Couldn't unbind interfaces: ", e.what());
            }
            return ret;
        } catch (std::exception &e) {
            logwriter.log_lvl("ERROR", "Uncaught exception: ", e.what());
            try {
                unbind_interfaces(arguments.args);
            }
            catch (std::exception& e) {
                logwriter.log_lvl("ERROR", "Couldn't unbind interfaces: ", e.what());
            }
            return static_cast<uint8_t>(DDP::Probe::ReturnValue::UNCAUGHT_ERROR);
        }
    } catch (std::exception& e) {
        logwriter.log_lvl("ERROR", e.what());
        try {
            unbind_interfaces(arguments.args);
        }
        catch (std::exception& e) {
            logwriter.log_lvl("ERROR", "Couldn't unbind interfaces: ", e.what());
        }
        return static_cast<uint8_t>(DDP::Probe::ReturnValue::UNCAUGHT_ERROR);
    }
}