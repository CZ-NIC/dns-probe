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

#pragma once

#include "dpdk/DpdkPort.h"

namespace DDP {
    class DPDKPcapPort : public DPDKPort
    {
    public:
        explicit DPDKPcapPort(uint16_t port, rte_mempool_t& mbuf_mempool) : DPDKPort(port, 1, mbuf_mempool){}

        uint16_t read(Packet* batch, unsigned queue) override
        {
            if(queue != 0)
                throw PortEOF();

            auto read_cnt = DPDKPort::read(batch, queue);
            if(read_cnt == 0)
                throw PortEOF();
            return read_cnt;
        }
    };
}