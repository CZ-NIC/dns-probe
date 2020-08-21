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

#include <new>

namespace DDP {
    /**
     * @brief Allocate and free memory on heap with C++ new and delete
     */
    class MAlloc {
    public:
        MAlloc() = delete;
        MAlloc(const MAlloc&) = delete;
        MAlloc& operator=(const MAlloc) = delete;

        /**
         * @brief Allocate "size" bytes of memory on heap
         * @param size Number of bytes to allocate on heap
         * @return Pointer to start of allocated memory
         */
        static void* malloc(std::size_t size) {
            return ::operator new(size, std::nothrow);
        }

        /**
         * @brief Free given memory block on heap
         * @param ptr Pointer to memory that is to be freed
         */
        static void free(void* ptr) {
            ::operator delete(ptr);
        }
    };
}