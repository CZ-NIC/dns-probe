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

#include <functional>
#include <utility>
#include <unistd.h>

namespace DDP {
    /**
     * RAII wrapper around UNIX file descriptor
     */
    class FileDescriptor
    {
    public:
        /**
         * Creates FileDescriptor with invalid UNIX fd.
         */
        FileDescriptor() noexcept : fd(-1) {}

        /**
         * Creates FileDescriptor with given UNIX fd
         */
        explicit FileDescriptor(int fd) noexcept : fd(fd) {}

        /**
         * Copying of the FileDescriptor is forbidden.
         */
        FileDescriptor(const FileDescriptor&) = delete;

        /**
         * Move FileDescriptor into new object.
         * @param s Moved FileDescriptor.
         */
        FileDescriptor(FileDescriptor&& s) noexcept : fd(std::exchange(s.fd, -1)) {}

        /**
         * Move assignment operator.
         * @param s Moved object.
         * @return Reference to target object.
         */
        FileDescriptor& operator=(FileDescriptor&& s) noexcept
        {
            std::swap(fd, s.fd);
            return *this;
        }

        /**
         * Destroy the FileDescriptor and close associated UNIX fd.
         */
        ~FileDescriptor() { close(); }

        /**
         * Allows implicit cast to the int.
         * @return Associated UNIX file descriptor.
         */
        operator int() const { return fd; } // NOLINT(google-explicit-constructor)

        /**
         * Check if asociated UNIX fd is valid.
         * @return True if the fd is valid otherwise false.
         */
        bool is_valid() const { return fd >= 0; }

        /**
         * Assign new UNIX fd to FileDescriptor. If the FileDescriptor already contains another valid UNIX fd then
         * the old UNIX fd is closed and replaced with the new one.
         * @param fd UNIX file descriptor assigned to the FileDescriptor.
         * @return Reference to the FileDescriptor containing given UNIX fd.
         */
        FileDescriptor& operator=(const int& fd)
        {
            close();
            this->fd = fd;
            return *this;
        }


        /**
         * Close associated UNIX file descriptor.
         */
        void close()
        {
            if (fd >= 0) {
                ::close(fd);
                fd = -1;
            }
        }

    private:
        int fd; //!< Guarded file descriptor.
    };
}
