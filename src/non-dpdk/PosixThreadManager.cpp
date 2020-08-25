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

#include "PosixThreadManager.h"
#include <cstdint>

thread_local unsigned DDP::PosixThreadManager::m_thread_local_id = 0;

DDP::PosixThreadManager::PosixThreadManager(DDP::ThreadManagerBase<PosixThreadManager>::MaskType cores) :
    ThreadManagerBase(cores), m_threads_map()
{
    // Fill mapping lcores to thread structures
    for(uintmax_t i = 0; i < m_mask.size(); i++)
        if(m_mask[i])
            m_threads_map.emplace_back(m_threads_map.size(), i);

    // Set thread_local variable to master lcore (currently always 0)
    m_thread_local_id = 0;

    // Fill master core record
    auto& master_thread = m_threads_map[0];
    master_thread.pthread = pthread_self();
    master_thread.running = true;

    // Set affinity for master core
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(master_thread.physical_core, &cpuset);
    auto pthread_op = pthread_setaffinity_np(master_thread.pthread, sizeof(cpu_set_t), &cpuset);
    if (pthread_op != 0)
        throw std::runtime_error("Cannot set affinity for master core!");
}

int DDP::PosixThreadManager::join_thread_impl(int lcore)
{
    auto& thread = m_threads_map[lcore];
    if(thread.running) {
        void* ret = nullptr;
        pthread_join(thread.pthread, &ret);
        auto converted_ret = static_cast<int>(reinterpret_cast<intptr_t>(ret));
        thread.ret_val = converted_ret;
        thread.running = false;
        return converted_ret;
    } else {
        return thread.ret_val;
    }
}

void DDP::PosixThreadManager::join_all_threads_impl()
{
    for(auto& thread: m_threads_map) {
        if(thread.logical_core == master_lcore())
            continue;

        join_thread(thread.logical_core);
    }
}

std::vector<uintmax_t> DDP::PosixThreadManager::slave_lcores() const
{
    std::vector<uintmax_t> slave_lcores;
    for(auto& thread: m_threads_map) {
        if(thread.logical_core == master_lcore())
            continue;

        slave_lcores.push_back(thread.logical_core);
    }
    return slave_lcores;
}
