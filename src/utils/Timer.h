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

#include <sys/timerfd.h>
#include "Poll.h"

namespace DDP {
    /**
     * Timer interface for general use of timers.
     */
    class TimerInterface
    {
    public:
        /**
         * Constructor.
         */
        TimerInterface() = default;

        /**
         * Activate timer with given interval.
         * @param interval Interval in milliseconds between trigger timer.
         */
        virtual void arm(int64_t interval) = 0;

        /**
         * Deactivate timer.
         */
        virtual void disarm() = 0;

        /**
         * Destructor.
         */
        virtual ~TimerInterface() = default;
    };

    /**
     * Implementation of timer which on the timeout event send notification over file descriptor. This class implement
     * DDP::PollAble interface so it can be used with DDP::Poll.
     *
     * When the Timer is used without DDP::Poll then for trigger associated callback user has to call
     * DDP::Timer::ready_read method when associated file descriptor is ready to read.
     *
     * When is triggered timer it will call callback passed in constructor to the object.
     * @tparam CB Type of callback which will be triggered.
     */
    template<typename CB>
    class Timer : public TimerInterface, public PollAble
    {
    public:
        /**
         * Constructor.
         * @param cb Called callback on timers timeout.
         */
        Timer(CB cb) : TimerInterface(), PollAble(), m_cb(cb), m_fd()
        {
            auto timer = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
            if (timer < 0)
                throw std::runtime_error("Creating timer failed!");
            m_fd = timer;
        }

        /**
         * Allows create timer and immediately arm it.
         * @param cb Called callback on timers timeout.
         * @param interval Timers interval in milliseconds.
         */
        Timer(CB cb, int64_t interval) : Timer(cb)
        {
            arm_impl(interval);
        }

        /**
         * Process timer timeout when associated file descriptor is ready to read. Otherwise do nothing.
         */
        void ready_read() override
        {
            uint64_t triggered = 0;
            auto data = read(m_fd, &triggered, sizeof(triggered));
            if (data < 0) {
                if (errno == EAGAIN)
                    return;
                else
                    throw std::runtime_error("Read on timer failed!");
            }

            m_cb();
        }

        /**
         * Activate timer with given interval.
         * @param interval Timers interval in milliseconds.
         */
        void arm(int64_t interval) override
        {
            arm_impl(interval);
        }

        /**
         * Deactivate timer.
         */
        void disarm() override
        {
            itimerspec timer_spec{{0, 0},
                                  {0, 0}};
            auto ret = timerfd_settime(m_fd, 0, &timer_spec, nullptr);
            if (ret < 0)
                throw std::runtime_error("Disarming timer failed!");
        }

        /**
         * Provides access to associated file descriptor.
         * @return File descripto connected to the timer.
         */
        int fd() override
        {
            return m_fd;
        }

    private:
        /**
         * Activate timer with given interval.
         * @param interval Timers interval in milliseconds.
         */
        void arm_impl(int64_t interval)
        {
            auto interval_sec = interval / 1000;
            auto interval_nsec = (interval - (interval_sec * 1000)) * 1000000;

            itimerspec timer_spec{{interval_sec, interval_nsec},
                                  {interval_sec, interval_nsec}};
            auto ret = timerfd_settime(m_fd, 0, &timer_spec, nullptr);
            if (ret < 0)
                throw std::runtime_error("Arming timer failed!");
        }

        CB m_cb; //!< Callback called on timers timeout.
        FileDescriptor m_fd; //!< File descriptor used for notifying timeout.
    };
}
