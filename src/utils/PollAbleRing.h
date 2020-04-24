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
#include <functional>
#include <utils/Poll.h>
#include <utils/Ring.h>
#include <sys/eventfd.h>


namespace DDP {
    template<typename T> class PollAbleRingFactory;

    template<typename T, typename F = std::function<void(Ring<T>&)>>
    class PollAbleRing : public PollAble
    {
    public:
        /**
         * Creates new ring.
         * @param size Maximal number of items in the ring.
         * @param flags Flags specifying if the ring is used by multiple producers and/or multiple consumers.
         */
        PollAbleRing(Ring<T>& ring, int fd, F ready_cb = [](Ring<T>&){}) :
            PollAble(PollEvents::READ),
            m_ring(ring),
            m_read_cb(std::move(ready_cb)),
            m_fd(fd)
            {}


        PollAbleRing(PollAbleRing&& other) noexcept :
            m_ring(other.m_ring),
            m_read_cb(std::move(other.m_read_cb)),
            m_fd(other.m_fd) {}

        PollAbleRing(const PollAbleRing& other) noexcept :
                m_ring(other.m_ring),
                m_read_cb(other.m_read_cb),
                m_fd(other.m_fd) {}

        ~PollAbleRing() override = default;

        int fd() override { return m_fd; }

        void ready_read() override
        {
            uint64_t buffer;
            auto read = ::read(m_fd, &buffer, sizeof(uint64_t));
            if(read == EAGAIN)
                return;

            m_read_cb(m_ring);
        }

        /**
         * Emplace new item into ring.
         * @tparam Args Type of arguments for emplaced item (will be deduced).
         * @param args Arguments for emplaced item.
         * @return Pointer to newly inserted item into ring.
         */
        template<typename... Args>
        T* emplace(Args&& ... args)
        {
            auto item = m_ring.emplace(std::forward<Args>(args)...);
            fire_event();
            return item;
        }

        /**
         * Insert new item into ring.
         * @param item Inserted item.
         * @return Reference to inserted item.
         */
        T& push(T&& item)
        {
            auto& item_ref = m_ring.push(std::forward<T>(item));
            fire_event();
            return item_ref;
        }

        /**
         * Read item from ring.
         * @return Optional containing read item. If the ring was empty then optional is also empty.
         */
        boost::optional<T> pop()
        {
            return m_ring.pop();
        }

        /**
         * Informs if the ring is empty.
         * @return True if the ring is empty otherwise false.
         */
        bool empty() { return m_ring.empty(); }

    private:
        void fire_event()
        {
            uint64_t buffer = 1;
            ::write(m_fd, &buffer, sizeof(uint64_t));
        }

        Ring<T>& m_ring;
        F m_read_cb;
        int m_fd;
    };

    template<typename T>
    class PollAbleRingFactory {
    public:
        explicit PollAbleRingFactory(Ring<T>& ring) :
            m_ring(ring),
            m_eventfd(eventfd(0, EFD_SEMAPHORE | EFD_NONBLOCK)) {}

        Ring<T>& ring() { return m_ring; }
        int fd() { return m_eventfd; }

        auto get_poll_able_ring() { return PollAbleRing<T>(m_ring, m_eventfd); }

        template<typename F>
        auto get_poll_able_ring_cb(F&& read_cb)
        {
            return PollAbleRing<T, std::decay_t<F>>(m_ring, m_eventfd,std::forward<F>(read_cb));
        }

    private:
        Ring<T>& m_ring;
        FileDescriptor m_eventfd;
    };
}
