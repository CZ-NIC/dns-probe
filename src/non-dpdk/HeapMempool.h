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
#include "utils/Ring.h"

#include "core/Probe.h"

namespace DDP {
    /**
     * Mempool allocated on heap.
     * @tparam T
     */
    template<typename T>
    class HeapMempool : public MempoolBase<HeapMempool<T>, T>
    {
    public:
        using base_t = MempoolBase<HeapMempool<T>, T>; //!< Type of base class.

    private:
        class alignas(64) CoreCache
        {
        public:
            CoreCache() : m_cache{}, m_unused_pos(0) {}

            [[nodiscard]] T* get() { return m_unused_pos ? m_cache[--m_unused_pos] : nullptr; }

            bool put(T* item)
            {
                if (m_unused_pos < m_cache.size()) {
                    m_cache[m_unused_pos++] = item;
                    return true;
                }
                return false;
            }

        private:
            std::array<T*, base_t::MEMPOOL_CACHE_SIZE> m_cache;
            unsigned m_unused_pos;
        };

    public:
        /**
         * Prepare mempool for receiving new objects.
         * @param elements Number of elements preallocated in the mempool.
         * @param name Unused (keep to conform interface with DPDK mempool).
         * @throw MempoolException
         */
        explicit HeapMempool(unsigned elements, const char* name [[maybe_unused]]) :
                m_mempool(std::make_unique<char[]>(elements * sizeof(T))),
                m_mempool_fields(elements, RING::MULTI_PRODUCER | RING::MULTI_CONSUMER),
                m_core_cache(Probe::getInstance().thread_manager().count())
        {
            for(auto i = 0u; i < elements; i++) {
                m_mempool_fields.push(reinterpret_cast<T*>(m_mempool.get() + i * sizeof(T)));
            }
        }

        /**
         * Destructor.
         */
        virtual ~HeapMempool() noexcept = default;

        /**
         * Allocate and construct new object in the mempool.
         * @param args Arguments passed to constructor of the new object.
         * @return Reference to newly constructed object.
         */
        template<typename... Args>
        [[nodiscard]] T& get_impl(Args&& ...args)
        {
            T* space = nullptr;

            if constexpr (base_t::MEMPOOL_CACHE_SIZE > 0) {
                space = m_core_cache[ThreadManager::index()].get();
            }

            if (space == nullptr) {
                auto item = m_mempool_fields.pop();
                if (item) {
                    space = item.value();
                } else {
                    throw MempoolException("Out of memory!");
                }
            }

            return *new(space) T(std::forward<Args>(args)...);
        }

        /**
         * Destroy and return it's space to the mempool.
         * @param obj Deallocated object.
         */
        void free_impl(T* obj) noexcept
        {
            obj->~T();

            if constexpr (base_t::MEMPOOL_CACHE_SIZE > 0) {
                if (!m_core_cache[ThreadManager::index()].put(obj)) {
                    m_mempool_fields.emplace(obj);
                }
            } else {
                m_mempool_fields.emplace(obj);
            }
        }

    private:
        std::unique_ptr<char[]> m_mempool;
        Ring<T*> m_mempool_fields;
        std::vector<CoreCache> m_core_cache;
    };
}