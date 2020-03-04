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

#include <ctime>
#include <cstdint>
#include <type_traits>

namespace DDP {

    /**
     * @brief Wrapper class over C timespec
     * which supports various operations with timestamps
     */
    class Time
    {
        public:
            using milliseconds_t = time_t;

            /**
             * @brief Supported clock types
             */
            enum class Clock : clockid_t
            {
                MONOTONIC = CLOCK_MONOTONIC,
                MONOTONIC_COARSE = CLOCK_MONOTONIC_COARSE,
                REALTIME = CLOCK_REALTIME,
            };

            /**
             * @brief Initialize "0" timestamp
             */
            Time()
            {
                m_timespec.tv_sec = 0;
                m_timespec.tv_nsec = 0;
            }

            /**
             * @brief Initialize timestamp containing current time of specified clock
             * @param clock Type of clock to use
             */
            explicit Time(Clock clock)
            {
                setCurrent(clock);
            }

            /**
             * @brief Initialize timestamp from milliseconds
             * @param millis Milliseconds (since UNIX epoch)
             */
            explicit Time(milliseconds_t millis)
            {
                setMillis(millis);
            }

            /**
             * @brief Initialize timestamp from struct timespec
             * @param ts C timespec struct
             */
            explicit Time(const timespec& ts) : m_timespec(ts) {}

            /**
             * @brief Set current time of specified clock
             * @param clock Reference clock
             */
            void setCurrent(Clock clock)
            {
                clock_gettime(static_cast<std::underlying_type<Clock>::type>(clock), &m_timespec);
            }

            /**
             * @brief Set time from milliseconds
             * @param millis Milliseconds
             */
            void setMillis(milliseconds_t millis)
            {
                m_timespec.tv_sec = millis / 1000;
                m_timespec.tv_nsec = (millis % 1000) * 1000000;
            }

            /**
             * @brief Convert timestamp to milliseconds
             * @return Current timestamp in milliseconds
             */
            milliseconds_t getMillis()
            {
                return m_timespec.tv_sec * 1000 + m_timespec.tv_nsec / 1000000;
            }

            /**
             * @brief Convert timestamp to microseconds
             * @return Current timestamp in microseconds
             */
            int64_t getMicros()
            {
                return (m_timespec.tv_sec * 1000000) + (m_timespec.tv_nsec / 1000);
            }

            /**
             * @brief Get seconds part of the timestamp
             * @return Seconds part of the timestamp
             */
            int64_t getSeconds()
            {
                return m_timespec.tv_sec;
            }

            /**
             * @brief Get nanoseconds part of the timestamp
             * @return Nanocesonds part of the timestamp
             */
            int64_t getNanoseconds()
            {
                return m_timespec.tv_nsec;
            }

            /**
             * @brief Get microseconds part of the timestamp
             * @return Microseconds part of the timestamp
             */
            int64_t getMicroseconds()
            {
                return m_timespec.tv_nsec / 1000;
            }

            friend Time operator-(Time first, const Time& second)
            {
                if(first.m_timespec.tv_nsec - second.m_timespec.tv_nsec < 0) {
                    first.m_timespec.tv_sec -= second.m_timespec.tv_sec - 1;
                    first.m_timespec.tv_nsec = first.m_timespec.tv_nsec + 1000000000 - second.m_timespec.tv_nsec;
                }
                else {
                    first.m_timespec.tv_sec -= second.m_timespec.tv_sec;
                    first.m_timespec.tv_nsec -= second.m_timespec.tv_nsec;
                }

                return first;
            }

        private:
            timespec m_timespec;
    };

}
