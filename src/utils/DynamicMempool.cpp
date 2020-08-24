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

#include <stdexcept>
#include "DynamicMempool.h"

DDP::DynamicMempool::DynamicMempool(uint32_t element_size, uint32_t count) : m_element_size(element_size),
                                                                             m_elements_count(count),
                                                                             m_mempool(),
                                                                             m_mempool_boundary(),
                                                                             m_free_list(m_elements_count),
                                                                             m_available_item(0)
{
    if (count < 1)
        throw std::invalid_argument("Count has to be at least 1");

    m_mempool = std::make_unique<char[]>(m_element_size * m_elements_count);
    m_mempool_boundary = m_mempool.get() + (m_element_size * m_elements_count);

    for (uint32_t i = 0; i < m_elements_count; i++) {
        m_free_list[i] = i + 1;
    }

    m_free_list[m_elements_count - 1] = LIMITER;
}

void* DDP::DynamicMempool::get(uint32_t size)
{
    if (size > m_element_size || full()) {
        return new char[size];
    }

    void* element = m_mempool.get() + (m_available_item * m_element_size);
    m_available_item = m_free_list[m_available_item];
    return element;
}

void DDP::DynamicMempool::free(void* element)
{
    if(!in_mempool(element)) {
        delete[] static_cast<char*>(element);
        return;
    }

    uint32_t pos = (static_cast<char*>(element) - m_mempool.get()) / m_element_size;
    m_free_list[pos] = m_available_item;
    m_available_item = pos;
}
