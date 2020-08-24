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

#include <rte_mempool.h>
#include <rte_errno.h>

#include <cerrno>

#include "utils/MempoolBase.h"

namespace DDP {
    /**
     * Wrapper around RTE mempool. This template creates factory for receiving initialized objects from mempool.
     * @tparam T The type of the object which will be allocated from mempool.
     */
    template<typename T>
    class DPDKMempool : public MempoolBase<DPDKMempool<T>, T>
    {
    public:
        using base_t = MempoolBase<DPDKMempool<T>, T>; //!< Type of base class.

        /**
         * Prepare mempool for receiving new objects.
         * @param elements Number of elements preallocated in the mempool.
         * @param name See DPDK doc for rte_mempool_create.
         * @throw MempoolException
         */
        explicit DPDKMempool(unsigned elements, const char* name) : m_mempool(
                rte_mempool_create(name, elements, sizeof(T), base_t::MEMPOOL_CACHE_SIZE, 0, nullptr, nullptr, nullptr,
                                   nullptr, SOCKET_ID_ANY, 0))
        {
            if (m_mempool == nullptr)
                throw MempoolException(rte_strerror(rte_errno));
        }

        /**
         * Free allocated mempool.
         */
        virtual ~DPDKMempool() noexcept
        {
            rte_mempool_obj_iter(m_mempool, [](rte_mempool*, void*, void* obj, unsigned) {
                reinterpret_cast<T*>(obj)->~T();
            }, nullptr);
            rte_mempool_free(m_mempool);
        }

        /**
         * Allocate and construct new object in the mempool.
         * @param args Arguments passed to constructor of the new object.
         * @throw DPDKMempoolException
         * @throw MempoolException
         * @return Reference to newly constructed object.
         */
        template<typename... Args>
        T& get_impl(Args&& ...args)
        {
            void* space = nullptr;
            auto ret = rte_mempool_get(m_mempool, &space);
            if (ret == 0) {
                try {
                    auto obj = new(space) T(std::forward<Args>(args)...);
                    return *obj;
                } catch (std::exception& e) {
                    rte_mempool_put(m_mempool, space);
                    throw;
                }
            } else {
                throw MempoolException(rte_strerror(rte_errno));
            }
        }

        /**
         * Destroy and return it's space to the mempool.
         * @param obj Deallocated object.
         */
        void free_impl(T* obj) noexcept
        {
            obj->~T();
            rte_mempool_put(m_mempool, obj);
        }

    private:
        rte_mempool* m_mempool; //!< Associated DPDK mempool.
    };
}
