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

#include <utility>
#include <vector>
#include <cstdint>
#include <thread>
#include <optional>
#include <atomic>

#include "RingFwdDecl.h"

namespace DDP {

    namespace RING {
        constexpr static uint8_t SINGLE_PRODUCER = 0; //!< Flag for single producer.
        constexpr static uint8_t SINGLE_CONSUMER = 0; //!< Flag for single consumer.
        constexpr static uint8_t MULTI_PRODUCER = 1; //!< Flag for multiple producers.
        constexpr static uint8_t MULTI_CONSUMER = 2; //!< Flag for multiple consumers.
    }

    /**
     * One way thread safe queue with possible multiple producers and/or multiple consumers.
     * @tparam T Type of elements send through ring.
     * @tparam yield Enable switch process when cooperation of other thread is required. Can be helpful when there
     * is multiple producers/consumers and the are on the same core.
     */
    template<typename T, bool yield>
    class Ring
    {
        using size_type = uint32_t; //!< Inner limitation for maximal number of items.

        /**
         * Calculates the closets power of two of the given number.
         * @param n Lower bound for searched number of power of two.
         * @return Number of power of two the closets to given number.
         */
        constexpr static size_type next_pow_2(size_type n) noexcept
        {
            size_type count = 0;
            if (n && !(n & (n - 1)))
                return n;

            while (n != 0) {
                n >>= 1;
                count += 1;
            }
            return static_cast<size_type>(1) << count;
        }

        /**
         * Context for newly inserted item into ring. On construction seizes new item from ring and on destruction mark
         * the item as ready to be read.
         */
        class RingNewItemCtx
        {
        public:
            /**
             * Get new item from the ring.
             * @param ring Source ring.
             */
            explicit RingNewItemCtx(Ring& ring) :
                    m_ring(ring),
                    m_item_pos(ring.m_producer_head),
                    m_new_item_pos((m_item_pos + 1) & ring.size_mask()),
                    m_valid(false)
            {
                if (ring.full())
                    return;

                if (ring.is_multi_producer()) {
                    while (!ring.m_producer_head.compare_exchange_weak(m_item_pos, m_new_item_pos)) {
                        if constexpr (yield)
                            std::this_thread::yield();

                        m_new_item_pos = (m_item_pos + 1) & ring.size_mask();
                        if (ring.full())
                            return;
                    }
                } else {
                    ring.m_producer_head.store(m_new_item_pos);
                }

                m_valid = true;
            }

            /**
             * Return pointer to allocated space.
             * @return Pointer to allocated space.
             */
            void* item_space()
            {
                return m_ring.m_ring.data() + m_item_pos * sizeof(T);
            }

            /**
             * Return if the instance is valid and manage some space in the ring.
             * @return True if the instance is valid and manage some space in the ring otherwise false.
             */
            bool valid() { return m_valid; }

            /**
             * Mark allocated space as filled and ready to read by consumer.
             */
            ~RingNewItemCtx()
            {
                if (!m_valid)
                    return;

                if (m_ring.is_multi_producer()) {
                    while (m_ring.m_producer_tail.load() != m_item_pos) {
                        if constexpr (yield)
                            std::this_thread::yield();
                    }
                }
                m_ring.m_producer_tail.store(m_new_item_pos);
            }

        private:
            Ring& m_ring; //!< Associated ring.
            size_type m_item_pos; //!< Position of last item used in ring.
            size_type m_new_item_pos; //!< New seized position in ring.
            bool m_valid; //!< Flag if this object is valid.
        };

        /**
         * Context for currently read item from ring. On construction marks item as currently read and on destruction
         * will free item from ring.
         */
        class RingDiscardItemCtx
        {
        public:
            /**
            * Get firt readable item from ring.
            * @param ring Source ring.
            */
            explicit RingDiscardItemCtx(Ring& ring) :
                    m_ring(ring),
                    m_item_pos(ring.m_consumer_head),
                    m_new_item_pos((m_item_pos + 1) & ring.size_mask()),
                    m_valid(false)
            {
                if (ring.empty())
                    return;

                if (ring.is_multi_consumer()) {
                    while (!ring.m_consumer_head.compare_exchange_weak(m_item_pos, m_new_item_pos)) {
                        if constexpr (yield)
                            std::this_thread::yield();

                        m_new_item_pos = (m_item_pos + 1) & ring.size_mask();
                        if (ring.empty())
                            return;
                    }
                } else {
                    ring.m_consumer_head.store(m_new_item_pos);
                }

                m_valid = true;
            }

            /**
             * Provides access to currently read item by this object inside the ring.
             * @return Reference to item inside ring.
             */
            T& item()
            {
                return *reinterpret_cast<T*>(m_ring.m_ring.data() + m_item_pos * sizeof(T));
            }

            /**
             * Return if the instance is valid and manage some space in the ring.
             * @return True if the instance is valid and manage some space in the ring otherwise false.
             */
            bool valid() { return m_valid; }

            /**
             * Destroy managed item in the ring and release it for another use.
             */
            ~RingDiscardItemCtx()
            {
                if (!m_valid)
                    return;

                item().~T();
                if (m_ring.is_multi_consumer()) {
                    while (m_ring.m_consumer_tail.load() != m_item_pos) {
                        if constexpr (yield)
                            std::this_thread::yield();
                    }
                }

                m_ring.m_consumer_tail.store(m_new_item_pos);
            }

        private:
            Ring& m_ring; //!< Associated ring.
            size_type m_item_pos; //!< Position of last item used in ring.
            size_type m_new_item_pos; //!< New seized position in ring.
            bool m_valid; //!< Flag if this object is valid.
        };

    public:
        /**
         * Creates new ring.
         * @param size Maximal number of items in the ring.
         * @param flags Flags specifying if the ring is used by multiple producers and/or multiple consumers.
         */
        Ring(uint32_t size, uint8_t flags) : m_consumer_head(0), m_consumer_tail(0), m_producer_head(0),
                                             m_producer_tail(0), m_size(0), m_ring()
        {
            if (size < 1)
                throw std::range_error("Size of ring must be bigger than 1");

            if (!(flags < 0x4))
                throw std::range_error("Invalid flags");

            m_multi_producer = flags & RING::MULTI_PRODUCER;
            m_multi_consumer = flags & RING::MULTI_CONSUMER;
            m_size = next_pow_2(size + 1);
            m_ring.resize(sizeof(T) * m_size);
        }

        /**
         * Emplace new item into ring.
         * @tparam Args Type of arguments for emplaced item (will be deduced).
         * @param args Arguments for emplaced item.
         * @return Pointer to newly inserted item into ring.
         */
        template<typename... Args>
        T* emplace(Args&& ... args)
        {
            RingNewItemCtx ctx(*this);
            if (ctx.valid())
                return new(ctx.item_space()) T(std::forward<Args>(args)...);
            else
                return nullptr;
        }

        /**
         * Insert new item into ring.
         * @param item Inserted item.
         * @return Reference to inserted item.
         */
        T& push(T&& item)
        {
            RingNewItemCtx ctx(*this);
            if (ctx.valid())
                return *new(ctx.item_space()) T(std::forward<T>(item));
            else
                throw std::bad_alloc();
        }

        /**
         * Read item from ring.
         * @return Optional containing read item. If the ring was empty then optional is also empty.
         */
        std::optional<T> pop()
        {
            RingDiscardItemCtx ctx(*this);
            if (ctx.valid()) {
                if constexpr (std::is_move_constructible<T>::value)
                    return {std::move(ctx.item())};
                else
                    return {ctx.item()};
            } else {
                return {};
            }
        }

        /**
         * Informs if the ring is at full capacity.
         * @return True if the ring is full otherwise false.
         */
        bool full() { return ((m_producer_head + 1) & size_mask()) == m_consumer_tail; }

        /**
         * Informs if the ring is empty.
         * @return True if the ring is empty otherwise false.
         */
        bool empty() { return m_consumer_head == m_producer_tail; }

        /**
         * Number of elements able to get inside the ring.
         * @return
         */
        constexpr uint64_t size() const { return m_size; }

        /**
         * Mask used to limit size of position pointers inside the ring.
         * @return Mask used to limit size of position pointers inside the ring.
         */
        constexpr uint64_t size_mask() const { return m_size - 1; }

        /**
         * Informs if the ring can be used by multiple producers.
         * @return True if the ring can be used by multiple producers otherwise false.
         */
        constexpr bool is_multi_producer() const { return m_multi_producer; }

        /**
         * Informs if the ring can be used by multiple consumers.
         * @return True if the ring can be used by multiple consumers otherwise false.
         */
        constexpr bool is_multi_consumer() const { return m_multi_consumer; }

    private:
        std::atomic<size_type> m_consumer_head; //!< Consumers head for read items.
        std::atomic<size_type> m_consumer_tail; //!< Consumer tail of read items.
        std::atomic<size_type> m_producer_head; //!< Producers head for new items.
        std::atomic<size_type> m_producer_tail; //!< Producer tail inserted items.

        bool m_multi_producer; //!< Specify if the ring is multiple producers capable.
        bool m_multi_consumer; //!< Specify if the ring is multiple consumers capable.
        size_type m_size; //!< Size of the ring.
        std::vector<uint8_t> m_ring; //!< Data structure used for the ring.
    };
}