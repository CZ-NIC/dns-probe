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
#include <sstream>
#include <sys/eventfd.h>

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>

#include "core/Port.h"
#include "DpdkPort.h"

DDP::DPDKPort::DPDKPort(uint16_t port, uint16_t num_queues, rte_mempool_t& mbuf_mempool) :
                        Port(num_queues), m_port(port), m_mempool(mbuf_mempool)
{
    // RSS hash key for symmetric flow distribution to the same core
    uint8_t rss_hash_key[] = {
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    };

    // Port configuration
    rte_eth_conf port_conf{};
    port_conf.rxmode.split_hdr_size = 0;

#ifndef DPDK_LEGACY
    port_conf.rxmode.offloads = 0;

    if (port >= rte_eth_dev_count_avail())
#else
    port_conf.rxmode.jumbo_frame = 1;
    port_conf.rxmode.hw_ip_checksum = 1;
    port_conf.rxmode.max_rx_pkt_len = 9192;

    if (port >= rte_eth_dev_count())
#endif
        throw std::runtime_error("Trying to initialize a non-existing port");

    rte_eth_dev_info info{};
    rte_eth_dev_info_get(port, &info);
    info.default_rxconf.rx_drop_en = 1;
    if ((strcmp(info.driver_name, "net_pcap") != 0 && strcmp(info.driver_name, "Pcap PMD") != 0) &&
        ((info.flow_type_rss_offloads & (ETH_RSS_UDP | ETH_RSS_TCP)) != (ETH_RSS_UDP | ETH_RSS_TCP)))
        throw std::runtime_error("Minimal required RSS hash calculation level not supported by NIC");

    port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
    port_conf.rx_adv_conf.rss_conf.rss_key = rss_hash_key;
    port_conf.rx_adv_conf.rss_conf.rss_hf = info.flow_type_rss_offloads;

#ifndef DPDK_LEGACY
    if (info.rx_offload_capa & DEV_RX_OFFLOAD_CHECKSUM)
        port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_CHECKSUM;

    if (info.rx_offload_capa & DEV_RX_OFFLOAD_JUMBO_FRAME) {
        port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
        port_conf.rxmode.max_rx_pkt_len = 9192;
    }
#endif

    if (rte_eth_dev_configure(port, num_queues, 0, &port_conf) < 0) {
        throw std::runtime_error("Cannot configure interfaces!");
    }
    
    uint16_t nb_rxd = RX_RING_SIZE;
    rte_eth_rxconf rxq_conf{};
    rxq_conf = info.default_rxconf;

#ifndef DPDK_LEGACY
    rxq_conf.offloads = port_conf.rxmode.offloads;

    if (rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, nullptr) < 0)
        throw std::runtime_error("Cannot modify rx/tx descriptor count!");
#endif

    /* Initialize RX queues for each port */
    for (unsigned i = 0; i < num_queues; i++) {
        if (rte_eth_rx_queue_setup(port, i, nb_rxd, rte_eth_dev_socket_id(port), &rxq_conf,
                                   mbuf_mempool.get()) < 0)
            throw std::runtime_error("Cannot setup queue for RX");

        int dummy = eventfd(0, EFD_SEMAPHORE | EFD_NONBLOCK);
        if (dummy == -1)
            throw std::runtime_error("Cannot setup queue for RX");

        m_fds.push_back(FileDescriptor(dummy));
        uint64_t buffer = 1;
        ::write(dummy, &buffer, sizeof(uint64_t));
    }

    rte_eth_promiscuous_enable(port);

    // Start initialized port
    if (rte_eth_dev_start(port) < 0)
        throw std::runtime_error("Cannot start port");
    
    // Check if port is up and running
    selected_link_status();
}

uint16_t DDP::DPDKPort::read(Packet* batch, unsigned queue)
{
    std::array<rte_mbuf*, Port::BATCH_SIZE> rx_buffer{};
    uint16_t rx_count = rte_eth_rx_burst(m_port, queue, rx_buffer.data(), Port::BATCH_SIZE);
    uint16_t err = 0;
    for (int i = 0; i < rx_count; i++) {
        try {
            batch[i] = Packet(rx_buffer[i]);
            rte_pktmbuf_free(rx_buffer[i]);
        }
        catch (std::exception& e) {
            std::cerr << "[WARNING] Packet: Unable to read packet data." << std::endl;
            err++;
        }
    }

    uint64_t buffer = 1;
    ::write(m_fds[queue], &buffer, sizeof(uint64_t));

    return rx_count - err;
}

std::vector<int> DDP::DPDKPort::fds() {
    std::vector<int> ret;
    for (auto&& fd: m_fds) {
        ret.push_back(fd);
    }
    return ret;
}

std::string DDP::DPDKPort::selected_link_status()
{
    constexpr int check_interval = 100;
    constexpr int max_check_time = 90;

    bool print_flag = false;
    rte_eth_link link{};

    std::stringstream status;

    for (unsigned count = 0; count <= max_check_time; count++) {
        bool port_up = true;

        memset(&link, 0, sizeof(link));
        rte_eth_link_get_nowait(m_port, &link);

        /* print link status if flag set */
        if (print_flag) {
            if (link.link_status) {
                status << "Port " << m_port << "link is up. Speed " << link.link_speed << "Mbps - "
                        << (link.link_duplex == ETH_LINK_FULL_DUPLEX ? "full-duplex" : "half-duplex") << '.'
                        << std::endl;
            }
            else {
                status << "Port " << m_port << "link  is down.";
            }

            continue;
        }

        /* clear port_up flag if link down */
        if (link.link_status == ETH_LINK_DOWN) {
            port_up = false;
            break;
        }

        /* after finally printing link status, get out */
        if (print_flag)
            break;

        if (!port_up) {
            rte_delay_ms(check_interval);
        }

        /* set the print_flag if port is up or timeout */
        if (port_up || count == (max_check_time - 1)) {
            print_flag = true;
        }
    }

    return status.str();
}