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

#include <vector>
#include <cstdint>
#include <pthread.h>
#include <thread>
#include <utility>
#include <vector>
#include <functional>
#include <type_traits>

#include "utils/CCallback.h"
#include "utils/Finally.h"

#include "core/ThreadManagerBase.h"

namespace DDP {
    class PosixThreadManager : public ThreadManagerBase<PosixThreadManager>
    {
        /**
         * Represent single thread
         */
        struct Thread {
            Thread(unsigned logical_core, uint64_t physical_core, pthread_t pthread = 0) :
                logical_core(logical_core), physical_core(physical_core), pthread(pthread), running(false), ret_val() {}
            Thread(const Thread& other) = default;
            Thread& operator=(const Thread& other) = default;

            unsigned logical_core;
            uint64_t physical_core;
            pthread_t pthread;
            bool running;
            int ret_val;
        };

        struct CallbackWrapper {
            int (*cb)(void*);
            void* data;
            unsigned thread_id;
        };

    public:
        /**
         * Create thread manager running on threads given by mask
         * @param cores Mask of used cores
         */
        explicit PosixThreadManager(ThreadManagerBase::MaskType cores);

        /**
         * Provides access to logical core id of master core
         * @return Logical ID of master core
         */
        [[nodiscard]] static unsigned master_lcore() { return 0; }

        /**
        * Provides access to logical core id of current thread
        * @return Logical ID of current thread
        */
        [[nodiscard]] static unsigned current_lcore() { return m_thread_local_id; }

        /**
        * Provides access to index of current thread calculated from 0
        * @return Index current thread
        */
        [[nodiscard]] static unsigned index_impl() { return m_thread_local_id; }

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
            auto& thread = m_threads_map[lcore];

            if(thread.running)
                throw std::runtime_error("Core is already used!");

            auto pthread_wrapper = [&thread](int (*cb)(void*), void* data){
                pthread_t pthread;

                // Set thread for running on assigned physical core
                cpu_set_t cpuset;
                CPU_ZERO(&cpuset);
                CPU_SET(thread.physical_core, &cpuset);

                pthread_attr_t pthread_attr;
                pthread_attr_init(&pthread_attr);
                auto clean_pthread_attr = Finally([&pthread_attr](){pthread_attr_destroy(&pthread_attr);});
                auto pthread_op = pthread_attr_setaffinity_np(&pthread_attr, sizeof(cpu_set_t), &cpuset);
                if(pthread_op < 0)
                    throw std::runtime_error("Cannot set affinity for new thread!");

                // Start thread
                // First set thread local variable containing lcore id
                // Also fix cb return type. Because cb returns int but pthread requires void* so it's wrapped
                // in lambda which provides required conversions
                auto cb_wrapper = new CallbackWrapper{cb, data, thread.logical_core};

                pthread_op = pthread_create(&pthread, &pthread_attr, [](void* data)->void*{
                    std::unique_ptr<CallbackWrapper> cb_wrapper(reinterpret_cast<CallbackWrapper*>(data));
                    PosixThreadManager::m_thread_local_id = cb_wrapper->thread_id;
                    return reinterpret_cast<void*>(cb_wrapper->cb(cb_wrapper->data));
                }, reinterpret_cast<void*>(cb_wrapper));

                if(pthread_op != 0) {
                    delete cb_wrapper;
                    throw std::runtime_error("Cannot create new thread!");
                }

                thread.running = true;
                thread.pthread = pthread;
            };

            CCallback(pthread_wrapper, f, std::forward<Args>(args)...);
        }

        /**
         * Run given callback on all threads except master core and those where some function already running
         * @tparam CB Type of callback (will be deduced)
         * @tparam Args Types of arguments for callback (will be deduced)
         * @param f Pointer to function or lambda which will be used as cb inside new thread
         * @param args Arguments for callback
         */
        template<typename CB, typename... Args>
        void run_on_all_impl(CB&& f, Args&& ... args) {
            for (auto& thread: m_threads_map) {
                // Skip master core
                if(thread.logical_core == master_lcore() || thread.running)
                    continue;

                run_on_thread(thread.logical_core, std::forward<CB>(f), std::forward<Args>(args)...);
            }
        }

        /**
         * Wait for thread until it finish
         * @param lcore lcore ID
         * @return Return value of terminated thread
         */
        int join_thread_impl(int lcore);

        /**
         * Wait until all threads finish
         */
        void join_all_threads_impl();

        std::vector<uintmax_t> slave_lcores() const override;
    protected:
        void check_slave_lcore_id(uintmax_t lcore) override
        {
            if (lcore == 0)
                throw std::runtime_error("LCore cannot be master core!");
            else if (lcore >= m_mask.count())
                throw std::runtime_error("Invalid LCore ID!");
        }

    private:
        static thread_local unsigned m_thread_local_id; /*!< Local variable holding lcore id */
        std::vector<Thread> m_threads_map; /*!< Map lcore to Thread structure */
    };
}