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

#include <unordered_map>
#include <memory>
#include <vector>
#include <atomic>

#include <poll.h>

#include "FileDescriptor.h"

namespace DDP {

    /**
     * List of possible monitored events in DDP::Poll.
     */
    enum class PollEvents
    {
        NONE = 0x0, //!< Ignore all events.
        READ = 0x1, //!< Monitor read events.
        WRITE = 0x2 //!< Monitor write events.
    };

    /**
     * Bitwise OR operator between DDP::PollEvents.
     * @param a First operand.
     * @param b Second operand.
     * @return OR-ed events.
     */
    inline PollEvents operator|(PollEvents a, PollEvents b)
    {
        using underlying_type = std::underlying_type_t<PollEvents>;
        return static_cast<PollEvents>(static_cast<underlying_type>(a) | static_cast<underlying_type>(b));
    }

    /**
     * Bitwise OR operator between DDP::PollEvents.
     * @param a First operand.
     * @param b Second operand.
     * @return OR-ed events.
     */
    inline PollEvents& operator|=(PollEvents& a, const PollEvents& b)
    {
        a = a | b;
        return a;
    }

    /**
     * Bitwise AND operator between DDP::PollEvents.
     * @param a First operand.
     * @param b Second operand.
     * @return AND-ed events.
     */
    inline PollEvents operator&(PollEvents a, PollEvents b)
    {
        using underlying_type = std::underlying_type_t<PollEvents>;
        return static_cast<PollEvents>(static_cast<underlying_type>(a) & static_cast<underlying_type>(b));
    }

    /**
     * Bitwise AND operator between DDP::PollEvents.
     * @param a First operand.
     * @param b Second operand.
     * @return AND-ed events.
     */
    inline PollEvents& operator&=(PollEvents& a, const PollEvents& b)
    {
        a = a & b;
        return a;
    }

    /**
     * Bitwise NOT operator on DDP::PollEvents.
     * @param a Operand.
     * @return Negated result.
     */
    inline PollEvents operator~(PollEvents a)
    {
        return static_cast<PollEvents>(~static_cast<std::underlying_type_t<PollEvents>>(a));
    }

    class Poll;

    /**
     * Interface for poll able objects. For more details please see DDP::Poll.
     */
    class PollAble
    {
        friend Poll;
    public:
        /**
         * Constructor.
         * @param poll Associated DDP:Poll. Can be nullptr if the pollable object will not change monitored events.
         * @param events Monitored events for DDP::Poll.
         */
        explicit PollAble(PollEvents events = PollEvents::READ) : m_poll(nullptr), m_events(events) {}

        /**
         * Method called when some data are ready to read from associated UNIX file descriptor.
         */
        virtual void ready_read() {};

        /**
         * Method called when data can be written into UNIX file descriptor without blocking.
         */
        virtual void ready_write() {};

        /**
         * Method called when some error occured on the file descriptor.
         */
        virtual void error() {};

        /**
         * Method called on hang up on the file descriptor.
         */
        virtual void hup() {};

        /*
         * Define events for listening in poll
         * @return Required monitored events in poll
         */
        PollEvents events() const { return m_events; }

        /**
         * Set events for monitoring in poll
         * @param events Monitored events in poll
         */
        void set_events(PollEvents events);

        /**
         * Getter to associated UNIX file descriptor.
         * @return Associated UNIX file descriptor.
         */
        virtual int fd() = 0;

        /**
         * Destructor.
         */
        virtual ~PollAble() = default;

        /**
         * Pointer to associated DDP::Poll object.
         * @return Pointer to associated DDP::Poll if available otherwise nullptr.
         */
        Poll* poll() { return m_poll; }

    private:
        /**
         * Assign DDP::Poll object managing this pollable.
         * @param poll Manager of this object.
         */
        void assign_poll(Poll* poll) { m_poll = poll; }

        Poll* m_poll; //!< Associated DDP::Poll.
        PollEvents m_events; //!< Monitored events.
    };

    /**
     * Class for polling on DDP::PollAble objects. The polling is blocking and doesn't consume processor time.
     */
    class Poll
    {
        friend PollAble;
    private:
        /**
         * Helper DDP::PollAble used for interrupt main poll loop.
         */
        class PollAbleInterrupt : public PollAble
        {
        public:
            /**
             * Constructor.
             */
            PollAbleInterrupt();

            /**
             * Read data from associated file descriptor.
             */
            void ready_read() override;
            /**
             * Interrupt blocking poll call so DDP:Poll can checked set flags and if necessary stop.
             */
            void interrupt();

            /**
             * Associated file descriptor.
             * @return Associated file descriptor.
             */
            int fd() override { return m_fd; }

        private:
            DDP::FileDescriptor m_fd; //!< Associated file descriptor.
        };

    public:
        using pollable_p = std::unique_ptr<PollAble>; //!< Type of items saved in private container.

        /**
         * Construct new DDP::Poll with empty list of associated PollAble objects.
         */
        Poll();

        /**
         * The DPP:Poll is not copyable.
         */
        Poll(const Poll&) = delete;

        /**
         * Move constructor of the DDP::Poll.
         * @param p Moved object.
         */
        Poll(Poll&& p) noexcept : m_stop(static_cast<bool>(p.m_stop)), m_pollables(std::move(p.m_pollables)),
                                  m_poll_fds(std::move(p.m_poll_fds)), m_interrupt(p.m_interrupt), m_poll_version(0) {}

        /**
         * Move assignment operator.
         * @param p Moved object.
         * @return Reference to target DDP::Poll instance.
         */
        Poll& operator=(Poll&& p) noexcept
        {
            m_stop = static_cast<bool>(p.m_stop);
            m_pollables = std::move(p.m_pollables);
            m_poll_fds = std::move(p.m_poll_fds);
            return *this;
        }

        virtual ~Poll() = default;

        /**
         * Register DDP::PollAble object for polling. This method also take ownership of the DDP::PollAble.
         * @param p Registered DDP::PollAble.
         * @return Reference to registered item.
         */
        PollAble& add(pollable_p&& p)
        {
            auto pair = m_pollables.emplace(p->fd(), std::move(p));
            pair.first->second->assign_poll(this);
            rebuild_poll_fds();
            return *pair.first->second;
        }

        /**
         * Creates new PollAble directly inside the DDP::Poll and register it for polling.
         * @tparam T Type of the PollAble object.
         * @param args Constructor arguments for given type.
         * @return Reference to emplaced item.
         */
        template<typename T, typename... Args>
        T& emplace(Args&& ... args)
        {
            static_assert(std::is_base_of<PollAble, T>::value, "You can only create PollAble descendants!");

            pollable_p p = std::make_unique<T>(std::forward<Args>(args)...);
            auto pair = m_pollables.emplace(p->fd(), std::move(p));
            pair.first->second->assign_poll(this);

            rebuild_poll_fds();
            return *static_cast<T*>(pair.first->second.get());
        }

        /**
         * Removes given DDP::PollAble from polling.
         * @param pollable Unregistered DDP::PollAble.
         */
        void unregister(PollAble& pollable) { return unregister_pollable(m_pollables.find(pollable.fd())); }

        /**
         * Removes DDP::PollAble from polling. The DDP::PollAble is identified by UNIX file descriptor
         * which is associated with it.
         * @param fd UNIX file descriptor identifying DDP::PollAble which will be unregistered from polling.
         */
        void unregister(int fd) { return unregister_pollable(m_pollables.find(fd)); }

        /**
         * Search for pollable identified by UNIX file descriptor
         * @param fd UNIX file descriptor
         * @return Reference to Pollable
         * @throw std::out_of_range when pollable with given fd is not found
         */
        PollAble& find(int fd) { return *m_pollables.at(fd).get(); }

        /**
         * Enable polling (can be called from another thread).
         */
        void enable() { m_stop = false; }

        /**
         * Disable currently running polling (can be called from another thread)
         */
        void disable()
        {
            m_stop = true;
            if (m_interrupt)
                m_interrupt->interrupt();
        }

        /**
         * Start polling on registered DDP::PollAble.
         */
        void loop()
        {
            while (!m_stop) {
                poll();
            }
        }

        /**
         * Start polling on registered DDP::PollAble. Stop when given callback return true
         * @param event Tested callback.
         */
        template<typename CB>
        void wait_for(CB event)
        {
            while (!m_stop && !event()) {
                poll();
            }
        }

    private:
        /**
         * Remove given DDP::PollAble from private container.
         * @param pollable Iterator identifying remove DDP::PollAble.
         */
        void unregister_pollable(std::unordered_map<int, pollable_p>::iterator pollable)
        {
            m_pollables.erase(pollable);
            rebuild_poll_fds();
        }

        /**
         * Wait for incoming events and process them.
         */
        void poll();

        /**
         * Creates data structure from pollables used in system call poll.
         */
        void rebuild_poll_fds();

        std::atomic<bool> m_stop; //!< Flag informing DDP::Poll::loop to leave function.
        std::unordered_map<int, pollable_p> m_pollables; //!< Maps file descriptors to DDP::PollAble.
        std::vector<pollfd> m_poll_fds; //!< Data structure used in the system call poll.
        PollAbleInterrupt* m_interrupt; //!< Interrupt object for asynchronous stop of the main loop.
        unsigned m_poll_version; //!< Version of data structure used in the system call poll.
    };
}
