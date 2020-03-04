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

#include <sys/eventfd.h>

#include "CommLink.h"
#include "utils/Ring.h"

DDP::CommLink::CommLink(unsigned size, bool single_producer) : m_rings(), m_event_fd(), m_worker_ep(*this), m_config_ep(*this)
{
    for (auto& ring: m_rings) {
        unsigned producer_settings = single_producer ? 0 : RING::MULTI_PRODUCER;

        try {
            ring = std::make_unique<Ring<DDP::Message*>>(size, producer_settings);
        }
        catch (std::exception& e) {
            throw std::runtime_error("Ring initialization failed!");
        }
    }

    m_event_fd = eventfd(0, EFD_SEMAPHORE | EFD_NONBLOCK);
    if (!m_event_fd.is_valid())
        throw std::runtime_error("Cannot create eventfd device!");
}

DDP::CommLink::~CommLink()
{
    for (auto& ring: m_rings) {
        while (!ring->empty()) {
            auto msg = ring->pop();
            if (msg)
                delete msg.value();
        }
    }
}

void DDP::CommLink::CommLinkConfigEP::send(DDP::Message& msg)
{
    auto ring = m_cl_owner.m_rings[static_cast<int>(RingDirection::TO_WORKER)].get();
    auto msg_clone = msg.clone();
    try {
        ring->emplace(msg_clone);
    }
    catch (std::exception& e) {
        delete msg_clone;
        throw std::runtime_error("Message ring is full!");
    }
}

std::unique_ptr<DDP::Message> DDP::CommLink::CommLinkConfigEP::recv()
{
    uint64_t cnt = 0;
    while (::read(m_cl_owner.m_event_fd, &cnt, sizeof(cnt)) < 0) {
        if (errno == EINTR)
            continue;
        else if (errno == EAGAIN)
            return std::unique_ptr<DDP::Message>(nullptr);
        else
            throw std::runtime_error("Read on eventfd failed!");
    }

    auto ring = m_cl_owner.m_rings[static_cast<int>(RingDirection::FROM_WORKER)].get();
    auto msg = ring->pop();
    if (msg)
        return std::unique_ptr<DDP::Message>(msg.value());
    else
        return std::unique_ptr<DDP::Message>(nullptr);
}

void DDP::CommLink::CommLinkWorkerEP::send(DDP::Message& msg)
{
    auto ring = m_cl_owner.m_rings[static_cast<int>(RingDirection::TO_CONFIG)].get();
    auto msg_clone = msg.clone();
    try {
        ring->emplace(msg_clone);
    }
    catch (std::exception& e) {
        delete msg_clone;
        throw std::runtime_error("Message ring is full!");
    }

    uint64_t cnt = 1;
    if (::write(m_cl_owner.m_event_fd, &cnt, sizeof(cnt)) < 0)
        throw std::runtime_error("Sending notification to the config thread failed!");
}

std::unique_ptr<DDP::Message> DDP::CommLink::CommLinkWorkerEP::recv()
{
    auto ring = m_cl_owner.m_rings[static_cast<int>(RingDirection::FROM_CONFIG)].get();
    auto msg = ring->pop();
    if (msg)
        return std::unique_ptr<DDP::Message>(msg.value());
    else
        return std::unique_ptr<DDP::Message>(nullptr);
}
