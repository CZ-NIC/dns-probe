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

#include <rte_malloc.h>

namespace DDP {
    /**
     * @brief Allocate and free memory with DPDK rte_malloc library
     */
    class DPDKAlloc {
        public:
        DPDKAlloc() = delete;
        DPDKAlloc(const DPDKAlloc&) = delete;
        DPDKAlloc& operator=(const DPDKAlloc) = delete;

        /**
         * @brief Allocate "size" bytes of memory in hugepages
         * @param size Number of bytes to allocate in hugepages
         * @return Pointer to start of allocated memory
         */
        static void* malloc(std::size_t size) {
            return rte_malloc(nullptr, size, 0);
        }

        /**
         * @brief Free given memory block from hugepages
         * @param ptr Pointer to memory that is to be freed
         */
        static void free(void* ptr) {
            rte_free(ptr);
        }
    };
}