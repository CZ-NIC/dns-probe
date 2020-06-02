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

namespace DDP {

    /**
     * RAII wrapper for custom callback. This callback will be called when
     * the instance of this object get out of scope.
     * @tparam F Type of the callback (will be deduced).
     */
    template<typename F>
    class FinallyImpl
    {
    public:
        /**
         * Constructor.
         * @param f Callback called when object get ou of a scope.
         */
        explicit FinallyImpl(F f) : m_clean(std::move(f)) {}

        /**
         * Destructor which call associated callback (if activated).
         */
        ~FinallyImpl() { clean(); }

        /**
         * Finally cannot be copied.
         */
        FinallyImpl(const FinallyImpl&) = delete;

        /**
         * Allows move finally to other scope.
         * @param other Source finally.
         */
        FinallyImpl(FinallyImpl&& other) noexcept : m_clean(std::move(other.m_clean)), m_enabled(other.m_enabled)
        {
            other.disable();
        }

        /**
         * Disable trigger for callback.
         */
        void disable() noexcept { m_enabled = false; };

        /**
         * Trigger callback.
         */
        void clean()
        {
            if (!m_enabled) {
                return;
            }

            disable();
            m_clean();
        }

    private:
        F m_clean; //!< Callback triggered on clean.
        bool m_enabled{true}; //!< Flag allowing disable Finally.
    };

    template<typename F>
    auto Finally(F&& f) { return FinallyImpl<std::decay_t<F>>(std::forward<F>(f)); }

}