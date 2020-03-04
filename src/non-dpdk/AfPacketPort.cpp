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

#include <cstring>

#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <iostream>

#include "AfPacketPort.h"

 DDP::AFPacketPort::AFPacketPort(const char* port, uint16_t num_queues, uint16_t port_ID) : Port(num_queues)
{
    m_info.resize(num_queues);

    // Prepare PACKET_FANOUT group to distribute packets between cores based on flow hash
    int err;
    int fanout_id = (getpid() + port_ID) & 0xffff;
    int fanout_type = PACKET_FANOUT_HASH;
    int fanout_arg = (fanout_id | (fanout_type << 16) | (PACKET_FANOUT_FLAG_DEFRAG << 16));

    // Create AF_PACKET raw socket for each worker queue
    for (unsigned i = 0; i < num_queues; i++) {
        // Create socket
        int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd < 0)
            throw std::runtime_error("Couldn't open socket!");

        // Set TPACKET V3
        int version = TPACKET_V3;
        err = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
        if (err < 0)
            throw std::runtime_error("Couldn't set socket to TPACKET V3!");

        // Get interface ID
        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        std::strcpy(ifr.ifr_name, port);
        err = ioctl(fd, SIOCGIFINDEX, &ifr);
        if (err < 0)
            throw std::runtime_error("Couldn't get interface identifier");

        // Set socket for non-blocking read
        int opts = fcntl(fd, F_GETFL, 0);
        err = fcntl(fd, F_SETFL, opts | O_NONBLOCK);
        if (err)
            throw std::runtime_error("Couldn't set socket options!");

        // Set promiscuous
        struct packet_mreq llp;
        std::memset(&llp, 0, sizeof(llp));
        llp.mr_type = PACKET_MR_PROMISC;
        llp.mr_ifindex = ifr.ifr_ifindex;
        err = setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, reinterpret_cast<void*>(&llp), sizeof(llp));
        if (err < 0)
            throw std::runtime_error("Couldn't set socket options!");

        // Create and set RX ring buffer
        struct tpacket_req3 req;
        std::memset(&req, 0, sizeof(req));
        req.tp_block_size = BLOCK_SIZE;
        req.tp_frame_size = FRAME_SIZE;
        req.tp_block_nr = NUM_BLOCKS;
        req.tp_frame_nr = NUM_FRAMES;
        req.tp_retire_blk_tov = 60; // miliseconds
        req.tp_retire_blk_tov = TP_FT_REQ_FILL_RXHASH;
        err = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
        if (err < 0)
            throw std::runtime_error("Couldn't set socket's RX buffer!");

        // mmap RX ring buffer
        uint8_t* buffer = nullptr;

        buffer = static_cast<uint8_t*>(mmap(nullptr, req.tp_block_size * req.tp_block_nr,
                                            PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0));
        if (buffer == MAP_FAILED)
            throw std::runtime_error("Couldn't mmap RX ring buffer!");

        m_info[i].buffer = buffer;

        // Bind socket to interface
        struct sockaddr_ll ll;
        std::memset(&ll, 0, sizeof(ll));
        ll.sll_family = AF_PACKET;
        ll.sll_protocol = htons(ETH_P_ALL);
        ll.sll_ifindex = ifr.ifr_ifindex;
        err = bind(fd, reinterpret_cast<struct sockaddr*>(&ll), sizeof(ll));
        if (err < 0)
            throw std::runtime_error("Couldn't bind socket to interface " + std::string(port));

        // Join PACKET_FANOUT group
        err = setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg));
        if (err)
            throw std::runtime_error("Couldn't set socket options!");

        // Save socket associated with queue i
        m_info[i].socket = fd;
        m_info[i].curr_block = 0;
    }
}

uint16_t DDP::AFPacketPort::read(Packet* batch, unsigned queue)
{
    uint16_t rx_count = 0;
    tpacket3_hdr* ppd = nullptr;
    m_info[queue].start_block = m_info[queue].curr_block;

    // Read packets until BATCH_SIZE packets is read or there are no more packets available
    while (rx_count < Port::BATCH_SIZE) {
        tpacket_block_desc* pbd = reinterpret_cast<tpacket_block_desc*>(m_info[queue].buffer +
                                  m_info[queue].curr_block * BLOCK_SIZE);
        // Check if next ring buffer block was released by kernel to user space
        if ((pbd->hdr.bh1.block_status & TP_STATUS_USER) == TP_STATUS_USER) {
            if (m_info[queue].next_packet == nullptr) {
                // Read from the beginning of the block
                ppd = reinterpret_cast<tpacket3_hdr*>(reinterpret_cast<uint8_t*>(pbd) +
                      pbd->hdr.bh1.offset_to_first_pkt);
                m_info[queue].pkts_read = 0;
            }
            else {
                // Read from last read packet of the block
                ppd = m_info[queue].next_packet;
            }

            // Read packets from one ring buffer block
            int unread_pkts = pbd->hdr.bh1.num_pkts - m_info[queue].pkts_read;
            for (int i = 0; i < unread_pkts; i++) {
                // Stop reading this block if BATCH_SIZE packets have been read
                if (rx_count == Port::BATCH_SIZE) {
                    m_info[queue].next_packet = ppd;
                    return rx_count;
                }

                // Load packet to Packet object (zero-copy approach, only pointer to ring buffer is saved)
                try {
                    batch[rx_count] = Packet(reinterpret_cast<uint8_t*>(ppd) + ppd->tp_mac, ppd->tp_snaplen, false);
                    rx_count++;
                }
                catch (std::exception& e) {
                    std::cerr << "[WARNING] Packet: Unable to read packet data." << std::endl;
                }

                ppd = reinterpret_cast<tpacket3_hdr*>(reinterpret_cast<uint8_t*>(ppd) + ppd->tp_next_offset);
                m_info[queue].pkts_read++;
            }

            // Set next ring buffer block
            m_info[queue].curr_block = (m_info[queue].curr_block + 1) % NUM_BLOCKS;
            m_info[queue].next_packet = nullptr;
        }
        else {
            break;
        }
    }

    return rx_count;
}

void DDP::AFPacketPort::free_packets(unsigned queue) {
    // Handle when curr_block overflowed back to 0 but start_block haven't yet
    int limit = m_info[queue].start_block > m_info[queue].curr_block ? m_info[queue].curr_block +
                NUM_BLOCKS : m_info[queue].curr_block;

    // Release processed ring buffer blocks back to kernel
    for (int i = m_info[queue].start_block; i < limit; i++) {
        tpacket_block_desc* pbd = reinterpret_cast<tpacket_block_desc*>(m_info[queue].buffer +
                                  i * BLOCK_SIZE);

        pbd->hdr.bh1.block_status = TP_STATUS_KERNEL;
    }
}
