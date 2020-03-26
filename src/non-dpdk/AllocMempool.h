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

#include <iostream>
#include <new>
#include <string>
#include <cerrno>

#include "utils/MempoolBase.h"

namespace DDP {
    /**
     * Mempool DPDK independent implementation. This template creates factory
     * for receiving initialized objects from mempool.
     * @tparam T The type of the object which will be allocated from mempool.
     */
    template<typename T>
    class AllocMempool : public MempoolBase<AllocMempool<T>, T>
    {
    public:
        /**
         * Prepare mempool for receiving new objects.
         * @param elements Number of elements preallocated in the mempool.
         * @param name Unused (keep to conform interface with DPDK mempool)
         * @throw MempoolException
         */
        explicit AllocMempool(unsigned, const char*) {}

        /**
         * Destructor.
         */
        virtual ~AllocMempool() noexcept = default;

        /**
         * Allocate and construct new object in the mempool.
         * @param args Arguments passed to constructor of the new object.
         * @return Reference to newly constructed object.
         */
        template<typename... Args>
        [[nodiscard]] T& get_impl(Args&& ...args)
        {
            try {
                return *new T(std::forward<Args>(args)...);
            } catch (std::exception& e) {
                throw MempoolException("Out of memory!");
            }
        }

        /**
         * Destroy and return it's space to the mempool.
         * @param obj Deallocated object.
         */
        void free_impl(T* obj) noexcept { delete obj; }
    };
}