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

#include <cstdint>
#include <memory>
#include <functional>
#include <vector>
#include <limits>

namespace DDP {
    /**
     * Creates mempool with arbitrary count of elements of arbitrary size. Mempool allowes requesteing new items even
     * if it is full. In that case new items are allocated. Also if is requested more bytes then element's size
     * specified in constructor than new memory is also allocated.
     */
    class DynamicMempool
    {
    protected:
        constexpr static auto LIMITER = std::numeric_limits<uint32_t>::max(); //!< Marker for full mempool
    public:
        /**
         * Constructor.
         * @param element_size Size of single element in mempool.
         * @param count Number of elements preallocated in the mempool.
         */
        DynamicMempool(uint32_t element_size, uint32_t count);

        /**
         * Return element from mempool or when the mempool is full or requested item
         * is too big returned address is dynamically allocated.
         * @param size Size in bytes of requested space.
         * @return Requested space.
         */
        void* get(uint32_t size);

        /**
         * Return element into mempool or deallocate it if it was dynamically allocated.
         * @param element Element ready to release.
         */
        void free(void* element);

        /**
         * Informs that mempool is full.
         * @return True if mempool is full otherwise false.
         */
        bool full() { return m_available_item == LIMITER; }

        /**
         * Informs if given address is inside preallocated mempool.
         * @param address Checked address.
         * @return True if given address is in mempool otherwise false.
         * @note Mainly intended for testing purposes.
         */
        bool in_mempool(void* address) { return address >= m_mempool.get() && address < m_mempool_boundary; }

    private:
        uint32_t m_element_size; //!< Size of single element in the mempool.
        uint32_t m_elements_count; //!< Number of elements in mempool.
        std::unique_ptr<char[]> m_mempool; //!< Space holder for mempool.
        char* m_mempool_boundary; //!< First address out of the mempool.
        std::vector<uint32_t> m_free_list; //!< Linked list with free elements in mempool.
        uint32_t m_available_item; //!< First position of available item in the mempool.
    };
}