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

#include <cstdint>
#include <type_traits>
#include <vector>
#include <bitset>
#include <stdexcept>

namespace DDP {
    class ThreadManagerBasePrivate
    {
    public:
        ThreadManagerBasePrivate()
        {
            if(initialized)
                throw std::runtime_error("Only one thread manager can exist!");

            initialized = true;
        };

        virtual ~ThreadManagerBasePrivate() { initialized = false; }

    private:
        static bool initialized;
    };

    template<typename T, uint64_t max_cpus = sizeof(uintmax_t) * 8>
    class ThreadManagerBase : public ThreadManagerBasePrivate
    {
    public:
        using MaskType = std::bitset<max_cpus>;
    protected:
        /**
         * Create thread manager running on threads given by mask
         * @param cores Mask of used cores
         */
        explicit ThreadManagerBase(MaskType cores) : ThreadManagerBasePrivate(), m_mask(cores)
        {
            if (m_mask.count() == 0)
                throw std::runtime_error("Requiring at least one core!");
        }

    public:
        /**
         * Provides access to logical core id of master core
         * @return Logical ID of master core
         */
        [[nodiscard]] static unsigned master_lcore() { return T::master_lcore_impl(); }

        /**
        * Provides access to logical core id of current thread
        * @return Logical ID of current thread
        */
        [[nodiscard]] static unsigned current_lcore() { return T::current_lcore_impl(); }

        /**
        * Provides access to index of current thread calculated from 0
        * @return Index current thread
        */
        [[nodiscard]] static unsigned index() { return T::index_impl(); }

        /**
         * Start given callback on selected lcore.
         * @tparam CB Type of callback (will be deduced)
         * @tparam Args Types of arguments for callback (will be deduced)
         * @param thread_id Thread ID of required lcore
         * @param f Pointer to function or lambda which will be used as cb inside new thread
         * @param args Arguments for callback
         */
        template<typename CB, typename... Args>
        void run_on_thread(uintmax_t lcore, CB&& f, Args&& ... args)
        {
            check_slave_lcore_id(lcore);

            static_assert(std::is_same<std::invoke_result_t<CB, Args...>, int>::value,
                          "Core function has to return int!");

            static_cast<T*>(this)->run_on_thread_impl(lcore, std::forward<CB>(f), std::forward<Args>(args)...);
        }

        /**
         * Run given callback on all threads except master core and those where some function already running
         * @tparam CB Type of callback (will be deduced)
         * @tparam Args Types of arguments for callback (will be deduced)
         * @param f Pointer to function or lambda which will be used as cb inside new thread
         * @param args Arguments for callback
         */
        template<typename CB, typename... Args>
        void run_on_all(CB&& f, Args&& ... args)
        {
            static_assert(std::is_same<std::invoke_result_t<CB, Args...>, int>::value,
                          "Core function has to return int!");

            static_cast<T*>(this)->run_on_thread_impl(std::forward<CB>(f), std::forward<Args>(args)...);
        }

        /**
        * Wait for thread until it finish
        * @param lcore lcore ID
        * @return Return value of terminated thread
        */
        int join_thread(int lcore)
        {
            check_slave_lcore_id(lcore);
            return static_cast<T*>(this)->join_thread_impl(lcore);
        }

        /**
         * Wait until all threads finish
         */
        void join_all_threads() { static_cast<T*>(this)->join_all_threads_impl(); }

        /**
         * Count of all threads
         * @return Count of all threads
         */
        uintmax_t count() const { return m_mask.count(); }

        /**
         * Provides list of all slave lcores.
         * @return List of slave lcores.
         */
        virtual std::vector<uintmax_t> slave_lcores() const = 0;

        /**
         * Destructor
         */
        ~ThreadManagerBase() override = default;

    protected:
        /**
         * Check if given lcore ID is valid.
         * @param lcore Checked lcore.
         */
        virtual void check_slave_lcore_id(uintmax_t lcore) = 0;

        MaskType m_mask; //!< Mask used for selecting cores.
    };
}