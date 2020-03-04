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

#include <exception>
#include <string>

namespace DDP {
    class MempoolException : public std::bad_alloc
    {
    public:
        /**
         * Constructor
         * @param errnum Error message.
         */
        explicit MempoolException(std::string error) : std::bad_alloc(), m_error(std::move(error)) {}

        /**
         * Constructor
         * @param error Error message
         */
        explicit MempoolException(const char* error) : std::bad_alloc(), m_error(error) {}

        /**
         * Access to description of the error
         * @return C string with error description.
         */
        const char* what() const noexcept override { return m_error.c_str(); }

    private:
        std::string m_error; //!< System error number.
    };

    template<typename T, typename E>
    class MempoolBase
    {
    public:
        constexpr static auto MEMPOOL_CACHE_SIZE = 256u;
        /**
         * Destructor.
         */
        virtual ~MempoolBase() noexcept = default;

        /**
             * Allocate and construct new object in the mempool.
             * @param args Arguments passed to constructor of the new object.
             * @return Reference to newly constructed object.
             */
        template<typename... Args>
        [[nodiscard]] E& get(Args&& ...args) { return static_cast<T*>(this)->get_impl(std::forward(args)...); }

        /**
         * Destroy and return it's space to the mempool.
         * @param obj Deallocated object.
         */
        void free(E& obj) noexcept { free(&obj); }

        /**
         * Destroy and return it's space to the mempool.
         * @param obj Deallocated object.
         */
        void free(E* obj) noexcept { static_cast<T*>(this)->free_impl(obj); }
    };
}