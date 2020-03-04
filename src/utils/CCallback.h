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
#include <functional>
#include <tuple>
#include <memory>
#include <type_traits>

namespace DDP {
    namespace CCallbackInternal {

        /**
         * Extract item from tuple and return moved/copyed value.
         * @tparam I Position in tuple for item extraction.
         * @tparam T Type stored in tuple.
         * @param tuple Source tuple for extraction item.
         * @return Requested item from tuple with correct type.
         */
        template<std::size_t I, typename T>
        decltype(auto) pass(T& tuple)
        {
            using type = std::tuple_element_t<I, T>;

            if constexpr (std::is_reference<type>::value) {
                return std::ref(std::get<I>(tuple));
            } else if constexpr (std::is_move_constructible_v<type>) {
                return std::move(std::get<I>(tuple));
            } else {
                return std::get<I>(tuple);
            }
        }

        /**
         * Invoke given C++ callback with parametr extracted from tuple with arguments.
         * @tparam F Type of C++ function.
         * @tparam T Type of tuple with arguments.
         * @tparam I0 Used for skip first item in tuple.
         * @tparam I Pack of sequence used for extraction items from tuple with arguments.
         * @param f Called C++ function.
         * @param t Tuple with parameters for C++ function.
         * @return Return value of called C++ function.
         */
        template<typename F, typename T, std::size_t I0, std::size_t... I>
        auto invoke(F&& f, T&& t, std::index_sequence<I0, I...>)
        {
            return std::invoke(std::forward<F>(f), pass<I>(t)...);
        }
    }

    /**
     * Allows call C callback with C++ lambdas or C++ functions and preserve type checking.
     * @warning C++ callback cannot throw exceptions!
     * @tparam CB Type of C function which will call our callback (will be deduced).
     * @tparam F Type of C++ callback called from C function (will be deduced).
     * @tparam Args Types of arguments passed to C++ callback (will be deduced).
     * @param cb C function calling C++ callback.
     *             Expected call definitions T(U (*)(void*), void*) where T and U are arbitrary types.
     * @param f C++ callback implementation. All its parameters have to be movable or copyable!
     * @param args Passed arguments to C++ callback.
     * @return Return value from called C function.
     */
    template<typename CB, typename F, typename... Args>
    auto CCallback(CB cb, F&& f, Args&& ... args) -> decltype(cb(nullptr, nullptr))
    {

        using params_t = decltype(std::make_tuple(std::forward<F>(f), std::forward<Args>(args)...));
        auto params = new params_t(std::forward<F>(f), std::forward<Args>(args)...);

        auto trampoline = [](void* data) {
            auto all_params = std::unique_ptr<params_t>(reinterpret_cast<params_t*>(data));
            auto func = std::get<0>(*all_params);

            return CCallbackInternal::invoke(func, *all_params,
                                             std::make_index_sequence<std::tuple_size_v<params_t>>{});
        };

        return cb(trampoline, params);
    }
}