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

#include <cstddef>
#include <utility>
#include <memory>
#include <functional>
#include <iterator>
#include <list>
#include <cstring>
#include <iostream>

#include "utils/Time.h"

namespace DDP {
    /**
     * Transaction table for matching DNS requests with responses. Table holds only references to items, for memory
     * management is responsible user.
     * @tparam EntryType Type of matched records.
     * @tparam burst_delete_limit Maximal deleted items from transaction table in one clean iteration.
     * @tparam bucket_size Size of buckets (extra space for collisions) for underlying hash table.
     */
    template<typename EntryType, std::size_t burst_delete_limit = 32, std::size_t bucket_size = 4>
    class TransactionTable
    {
    private:
        struct Entry;

        /**
         * Inner representation of one record inside DDP::TransactionTable.
         */
        struct Entry
        {
            EntryType* entry; //!< Pointer to entry itself.
            uint64_t timestamp; //!< Timestamp of last action with this entry.
            Entry* older_item; //!< Pointer to next older item in transaction table.
            Entry* newer_item; //!< Pointer to next newer item in transaction table.
        };

        /**
         * Proxy object allowing access entries from transaction table.
         */
        class GateTT
        {
            friend TransactionTable;
        public:
            /**
             * Creates new proxy for item from transaction table.
             * @param tt Reference to transaction table holding given entry.
             * @param entry Entry inside transaction which shoulb be covered by this object.
             */
            explicit GateTT(TransactionTable& tt, Entry& entry) : m_tt(tt), m_pos(&entry) {}

            /**
             * Informs if given entry is unused inside transaction table.
             * @return True if entry covered by this instance is not used otherwise false.
             */
            bool empty() { return m_pos->entry == nullptr; }

            /**
             * Update timestamp of associated entry in transaction table.
             */
            void update_timestamp() { m_pos->timestamp = Time(Time::Clock::MONOTONIC_COARSE).getMillis(); }

            /**
             * Associate new entry with this object.
             * @param new_entry New associated entry.
             */
            void set_entry(EntryType* new_entry) { m_pos->entry = new_entry; }

            /**
             * Provides access to stored entry.
             * @return Reference to stored entry.
             */
            EntryType& operator*() { return *(m_pos->entry); }

            /**
             * Provides access to stored entry.
             * @return Pointer to stored entry.
             */
            EntryType* operator->() { return m_pos->entry; }

            /**
             * Insert new entry on the place in transaction table associated with this object. If the spot is not empty
             * then it is replaced.
             * @param e New entry inserted into transaction table.
             * @return Reference to proxy of newly inserted item.
             */
            GateTT& operator=(EntryType& e)
            {
                m_tt.insert_hint(*this, e);
                return *this;
            }


        private:
            TransactionTable& m_tt; //!< Associated transaction table.
            Entry* m_pos; //!< Entry inside transaction table.
        };

    public:
        /**
         * Creates new transaction table.
         * @param size Number of rows for intern hash table (automatically multiplied by bucket size).
         * @param timeout Timeout in milliseconds for unmatched items in transaction table.
         * @param match_qname Enable matching by QNAMEs.
         */
        explicit TransactionTable(uint64_t size, uint64_t timeout, bool match_qname) :
                m_timeout(timeout), m_match_qname(match_qname), m_mask(size - 1),
                m_table(reinterpret_cast<Entry*>(Alloc::malloc(size * bucket_size * sizeof(Entry))), Alloc::free),
                m_records(0), m_oldest(nullptr), m_newest(nullptr)
        {
            if (!m_table)
                throw std::bad_alloc();

            if (!size || (size & (size - 1)))
                throw std::invalid_argument("Size has to be power of two!");

            std::memset(m_table.get(), 0, size * bucket_size * sizeof(Entry));
        }

        /**
         * Insert new entry into transaction table. Position is preselected by given proxy ::GateTT.
         * @param pos Specify postion where new entry will be placed.
         * @param entry Newly inserted item.
         */
        void insert_hint(GateTT& pos, EntryType& entry)
        {
            if (!pos.empty())
                erase(pos);

            pos.m_pos->entry = &entry;
            pos.m_pos->timestamp = Time(Time::Clock::MONOTONIC_COARSE).getMillis();
            pos.m_pos->older_item = m_newest;
            pos.m_pos->newer_item = nullptr;
            m_records++;

            if (m_newest) {
                m_newest->newer_item = pos.m_pos;
            }

            m_newest = pos.m_pos;

            if (!m_oldest)
                m_oldest = pos.m_pos;
        }

        /**
         * Insert new entry into transaction table. Position will be find automatically.
         * @param entry Newly inserted item.
         */
        void insert(EntryType& entry)
        {
            auto bucket = find_bucket(entry);
            auto free = find_free_item_bucket(bucket);
            if (free == nullptr)
                throw std::bad_alloc();

            GateTT gate(*this, *free);
            insert_hint(gate, entry);
        };

        /**
         * Remove entry from transaction table.
         * @param pos Position of removed item.
         */
        void erase(GateTT& pos)
        {
            if (pos.empty())
                return;

            pos.m_pos->entry = nullptr;

            if (pos.m_pos->older_item) {
                pos.m_pos->older_item->newer_item = pos.m_pos->newer_item;
            }

            if (pos.m_pos->newer_item) {
                pos.m_pos->newer_item->older_item = pos.m_pos->older_item;
            }

            if (pos.m_pos == m_newest) {
                m_newest = pos.m_pos->older_item;
            }

            if (pos.m_pos == m_oldest) {
                m_oldest = pos.m_pos->newer_item;
            }

            m_records--;
        }

        /**
         * Remove entry from transaction table.
         * @param pos Position of removed item.
         */
        void erase(GateTT&& pos) { erase(pos); }


        /**
         * Iterates through old items in transaction table, call upon them callback and then removes them.
         * @tparam CB Type of callback (will be deduced).
         * @param cb Callback called on removed items. It's called with one parameter which is reference to removed
         * entry.
         */
        template<typename CB>
        void timeout(CB cb)
        {
            auto next = m_oldest;
            auto timestamp = static_cast<uint64_t>(Time(Time::Clock::MONOTONIC_COARSE).getMillis());

            for (decltype(burst_delete_limit) i = 0; i < burst_delete_limit; i++) {
                if (next && next->timestamp + m_timeout <= timestamp) {
                    cb(*next->entry);
                    m_records--;
                    next->entry = nullptr;
                    next = next->newer_item;
                } else {
                    break;
                }
            }

            m_oldest = next;
            if (m_oldest)
                m_oldest->older_item = nullptr;

            if (m_records == 0)
                m_newest = nullptr;
        }

        /**
         * Iterates through all items in transaction table, call upon them callback and then removes them.
         * @tparam CB Type of callback (will be deduced).
         * @param cb Callback called on removed items. It's called with one parameter which is reference to removed
         * entry.
         */
        template<typename CB>
        void cleanup(CB cb)
        {
            auto next = m_oldest;
            while (next) {
                cb(*next->entry);
                next->entry = nullptr;
                next = next->newer_item;
            }

            m_oldest = nullptr;
            m_newest = nullptr;
            m_records = 0;
        }

        /**
         * Find record position in transaction table based on given entry.
         * @param entry Entry specifying position in transaction table.
         * @return Proxy object to entry in transaction table.
         */
        GateTT operator[](EntryType& entry)
        {
            auto bucket = find_bucket(entry);

            for (decltype(bucket_size) i = 0; i < bucket_size; i++) {
                if (bucket[i].entry && bucket[i].entry->match(entry, m_match_qname))
                    return GateTT(*this, bucket[i]);
            }

            if (auto free_item = find_free_item_bucket(bucket); free_item != nullptr) {
                return GateTT(*this, *free_item);
            }

            throw std::bad_alloc();
        }

        /**
         * Update timestmap of given record.
         * @param pos Record with updated timestamp.
         */
        void update_item(GateTT& pos)
        {
            pos.update_timestamp();

            if (pos.m_pos == m_newest)
                return;

            if (pos.m_pos->older_item) {
                pos.m_pos->older_item->newer_item = pos.m_pos->newer_item;
            }

            if (pos.m_pos->newer_item) {
                pos.m_pos->newer_item->older_item = pos.m_pos->older_item;
            }

            if (pos.m_pos == m_oldest) {
                m_oldest = pos.m_pos->newer_item;
            }

            pos.m_pos->older_item = m_newest;
            pos.m_pos->newer_item = nullptr;

            if (m_newest) {
                m_newest->newer_item = pos.m_pos;
            }

            m_newest = pos.m_pos;
        }

        /**
         * Set new timeout.
         * @param timeout New timeout in milliseconds.
         */
        void set_timeout(uint64_t timeout) { m_timeout = timeout; }

        /**
         * Return number of items in transaction table.
         * @return Number of items in transaction table.
         */
        uint64_t records() { return m_records; }

    protected:
        /**
         * Removes item from transaction table.
         * @param entry Entry specifying position in transaction table.
         */
        void erase(EntryType& entry) { erase(GateTT(*this, entry)); }

    private:
        /**
         * Find bucket for given entry in transaction table.
         * @param entry Entry for witch is made lookup for bucket.
         * @return Pointer to the first transaction table entry in the found bucket.
         */
        Entry* find_bucket(EntryType& entry) noexcept { return m_table.get() + bucket_size * (entry.hash() & m_mask); }

        /**
         * Finds the first empty entry in given bucket.
         * @param pos Pointer to first entry in bucket.
         * @return First empty item in bucekt otherwise nullptr.
         */
        Entry* find_free_item_bucket(Entry* pos) noexcept
        {
            for (decltype(bucket_size) i = 0; i < bucket_size; i++) {
                if (pos->entry == nullptr)
                    return pos;
                pos++;
            }

            return nullptr;
        }

        uint64_t m_timeout; //!< Timeout of unmatched in transaction table in milliseconds.
        bool m_match_qname; //!< Flag specifying matching qnames in record.
        const uint64_t m_mask; //!< Mask used for limiting calculated hash into size of transaction table.
        std::unique_ptr<Entry[], std::function<void(void*)>> m_table; //!< Pointer holding data structure for transaction table.
        uint64_t m_records; //!< Number of records in transaction table.
        Entry* m_oldest; //<! Oldest item in transaction table.
        Entry* m_newest; //!< Newest item in transaction table.
    };
}
