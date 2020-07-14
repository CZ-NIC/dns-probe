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
#include <stdexcept>
#include <cstring>
#include <sys/eventfd.h>

#include "Poll.h"

DDP::Poll::PollAbleInterrupt::PollAbleInterrupt() : PollAble(), m_fd(eventfd(0, EFD_SEMAPHORE))
{
    if (!m_fd.is_valid())
        throw std::runtime_error("Cannot create eventfd.");
}

void DDP::Poll::PollAbleInterrupt::ready_read()
{
    uint64_t cnt = 0;
    auto ret = read(m_fd, &cnt, sizeof(cnt));
    if (ret == -1)
        std::runtime_error("Poll: Couldn't read from file descriptor!");
}

void DDP::Poll::PollAbleInterrupt::interrupt()
{
    uint64_t cnt = 1;
    auto ret = write(m_fd, &cnt, sizeof(cnt));
    if (ret == -1)
        std::runtime_error("Poll: Couldn't write to file descriptor!");
}

DDP::Poll::Poll() : m_stop(false), m_pollables(), m_poll_fds(), m_interrupt(nullptr), m_poll_version(0)
{
    m_interrupt = &emplace<PollAbleInterrupt>();
}

void DDP::Poll::rebuild_poll_fds()
{
    m_poll_fds.clear();

    for (auto&& pollable : m_pollables) {
        pollfd pfd{};
        pfd.fd = pollable.first;
        pfd.events = 0;

        if(pollable.second->events() == PollEvents::READ)
            pfd.events |= POLLIN;

        if(pollable.second->events() == PollEvents::WRITE)
            pfd.events |= POLLOUT;

        m_poll_fds.push_back(pfd);
    }

    m_poll_version++;
}

void DDP::Poll::poll()
{
    auto version = m_poll_version;

    auto ret = ::poll(m_poll_fds.data(), m_poll_fds.size(), -1);

    if (ret == 0 || (ret < 0 && (errno == EINTR || errno == EAGAIN)))
        return;
    else if (ret < 0)
        throw std::runtime_error(strerror(errno));

    for (auto& ready: m_poll_fds) {
        if (ready.revents == 0)
            continue;

        auto& pollable = m_pollables.at(ready.fd);
        if (ready.revents & POLLIN || ready.revents & POLLPRI) {
            pollable->ready_read();
        }
        else if(ready.revents & POLLOUT) {
            pollable->ready_write();
        }
        else if (ready.revents & POLLHUP) {
            pollable->hup();
        }
        else {
            if ((ready.revents & POLLERR) != 0) {
                pollable->error();
            }
        }

        if(version != m_poll_version)
            break;
    }
}

void DDP::PollAble::set_events(DDP::PollEvents events) {
    if(m_events == events)
        return;

    m_events = events;
    if(m_poll)
        m_poll->rebuild_poll_fds();
}
