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

#include <vector>
#include <cstdint>
#include <thread>
#include <utility>
#include <vector>
#include <functional>
#include <type_traits>

#include "rte_launch.h"
#include "rte_lcore.h"

#include "utils/CCallback.h"
#include "utils/Finally.h"
#include "core/ThreadManagerBase.h"

namespace DDP {
    class DPDKThreadManager : public ThreadManagerBase<DPDKThreadManager>
    {
    public:
        /**
         * Create thread manager running on threads given by mask
         * @param cores Mask of used cores
         */
        explicit DPDKThreadManager(ThreadManagerBase::MaskType cores) : ThreadManagerBase(cores), m_slave_lcores()
        {
            unsigned lcore;
#ifdef DPDK_21_11
            RTE_LCORE_FOREACH_WORKER(lcore) {
#else
            RTE_LCORE_FOREACH_SLAVE(lcore) {
#endif
                m_slave_lcores.push_back(lcore);
            }
        }

        /**
         * Provides access to logical core id of master core
         * @return Logical ID of master core
         */
        static unsigned master_lcore_impl() {
#ifdef DPDK_21_11
            return rte_get_main_lcore();
#else
            return rte_get_master_lcore();
#endif
        }

        /**
        * Provides access to logical core id of current thread
        * @return Logical ID of current thread
        */
        static unsigned current_lcore_impl() { return rte_lcore_id(); }

        /**
        * Provides access to index of current thread calculated from 0
        * @return Index current thread
        */
        static unsigned index_impl()
        {
            auto index = rte_lcore_index(rte_lcore_id());
            if(index < 0)
                throw std::runtime_error("Getting index of the core is not supported.");
            return index;
        }

        /**
         * Start given callback on selected lcore.
         * @tparam CB Type of callback (will be deduced)
         * @tparam Args Types of arguments for callback (will be deduced)
         * @param lcore Thread ID of required lcore
         * @param f Pointer to function or lambda which will be used as cb inside new thread
         * @param args Arguments for callback
         */
        template<typename CB, typename... Args>
        void run_on_thread_impl(int lcore, CB&& f, Args&& ... args) {
            auto eal_launch_wrapper = [lcore](int (*cb)(void*), void* data){
                rte_eal_remote_launch(cb, data, lcore);
            };

            CCallback(eal_launch_wrapper, f, std::forward<Args>(args)...);
        }

        /**
         * Run given callback on all threads except master core
         * @tparam CB Type of callback (will be deduced)
         * @tparam Args Types of arguments for callback (will be deduced)
         * @param f Pointer to function or lambda which will be used as cb inside new thread
         * @param args Arguments for callback
         */
        template<typename CB, typename... Args>
        void run_on_all_impl(CB&& f, Args&& ... args) {
            for(auto lcore: m_slave_lcores) {
                if(rte_eal_get_lcore_state(lcore) != WAIT)
                    continue;

                auto eal_launch_wrapper = [lcore](int (*cb)(void*), void* data){
                    rte_eal_remote_launch(cb, data, lcore);
                };

                CCallback(eal_launch_wrapper, f, std::forward<Args>(args)...);
            }
        }

        /**
         * Wait for thread until it finish
         * @param lcore lcore ID
         * @return Return value of terminated thread
         */
        static int join_thread_impl(int lcore) { return rte_eal_wait_lcore(lcore); };

        /**
         * Wait until all threads finish
         */
        static void join_all_threads_impl() { return rte_eal_mp_wait_lcore(); };

        /**
         * Provides list of all slave lcores.
         * @return List of slave lcores.
         */
        std::vector<uintmax_t> slave_lcores() const override { return m_slave_lcores; }

    protected:
        /**
         * Check if given lcore ID is valid.
         * @param lcore Checked lcore.
         */
        void check_slave_lcore_id(uintmax_t lcore) override
        {
#ifdef DPDK_21_11
            if (lcore == rte_get_main_lcore())
#else
            if (lcore == rte_get_master_lcore())
#endif
                throw std::runtime_error("LCore cannot be master core!");
            else if (lcore >= RTE_MAX_LCORE || !rte_lcore_is_enabled(lcore))
                throw std::runtime_error("Invalid LCore ID!");
        }

    private:
        std::vector<uintmax_t> m_slave_lcores; //!< Linear map of lcores to actual DPDK lcore ID.
    };
}