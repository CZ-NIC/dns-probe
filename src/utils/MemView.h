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
#include <utility>

namespace DDP {
    /**
     * Provides read-only access to part of memory specified by pointer and number of consecutive elements. Size of
     * element is deduced from type of the pointer.
     * @tparam T Type of elements covered by the DDP::MemView (will be deduced).
     */
    template<typename T>
    class MemView
    {
    public:
        /**
         * Creates empty view.
         */
        MemView() : m_ptr(nullptr), m_count(0) {}

        /**
         * Creates view on given elements.
         * @param ptr Start of memory view.
         * @param count Number of elements in memory.
         */
        MemView(const T* ptr, uint64_t count) : m_ptr(ptr), m_count(count) {}

        /**
         * Creates copy of DDP::MemView.
         * @param other Copied object.
         */
        MemView(const MemView& other) : m_ptr(other.m_ptr), m_count(other.m_count) {}

        /**
         * Copy DDP::MemView through assignment operator.
         * @param other Copied object.
         * @return Reference to modified object.
         */
        MemView& operator=(MemView other)
        {
            swap(*this, other);
            return *this;
        }

        /**
         * Swap two DDP::MemView objects.
         * @param view1 First object.
         * @param view2 Second object.
         */
        friend void swap(MemView& view1, MemView& view2) noexcept
        {
            using std::swap;

            swap(view1.m_ptr, view2.m_ptr);
            swap(view1.m_count, view2.m_count);
        }

        /**
         * Creates new DDP::MemView started from given offset.
         * @param offset Offset from start of current instance.
         * @return New mem view covered part of previous mem view.
         */
        MemView offset(uint64_t offset) const { return {m_ptr + offset, m_count - offset}; }

        /**
         * Set new address and size.
         * @param ptr New address.
         * @param size New size.
         */
        void set(const T* ptr, uint64_t size)
        {
            m_ptr = ptr;
            m_count = size;
        }

        /**
         * Provides access to elements covered by instance of DDP::MemView.
         * @return Pointer to start of space covered by this instance.
         */
        const T* ptr() const { return m_ptr; }

        /**
         * Return number of elements covered by DDP::MemView.
         * @return Number of elements covered by DDP::MemView.
         */
        uint64_t count() const { return m_count; }

    private:
        const T* m_ptr; //!< Pointer to memory covered by instance of DDP::MemView.
        uint64_t m_count; //!< Number of elements in covered memory.
    };
}