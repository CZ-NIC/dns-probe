/*
 *  Copyright (C) 2021 CZ.NIC, z. s. p. o.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "UnixSocket.h"

DDP::UnixSocket::UnixSocket(const char* sock_path)
    : Port(1), m_socket_path(sock_path), m_fd(-1)
{
    sockaddr_un sa;

    if (m_socket_path.empty() || (m_socket_path.length() + 1 > sizeof(sa.sun_path)))
        throw std::runtime_error("Invalid socket path " + std::string(sock_path));

    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, m_socket_path.c_str(), sizeof(sa.sun_path) - 1);

#if defined(SOCK_NONBLOCK)
    m_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (m_fd < 0 && errno == EINVAL)
        m_fd = socket(AF_UNIX, SOCK_STREAM, 0);
#else
    m_fd = socket(AF_UNIX, SOCK_STREAM, 0);
#endif

    if (m_fd < 0)
        throw std::runtime_error("Couldn't open dnstap socket!");

#if defined(SO_NOSIGPIPE)
    const int on = 1;
    if (setsockopt(m_fd, SOL_PACKET, SO_NOSIGPIPE, &on, sizeof(on)) != 0) {
        close(m_fd);
        throw std::runtime_error("Couldn't set NOSIGPIPE on dnstap socket!");
    }
#endif

    if (bind(m_fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0) {
        close(m_fd);
        throw std::runtime_error("Couldn't bind to dnstap socket!");
    }

    if (listen(m_fd, 10) < 0) {
        close(m_fd);
        throw std::runtime_error("Couldn't start listening on dnstap socket!");
    }
}

DDP::UnixSocket::~UnixSocket()
{
    if (m_fd >= 0)
        ::close(m_fd);
    unlink(m_socket_path.c_str());
}

uint16_t DDP::UnixSocket::read(Packet*, unsigned)
{
#if defined(SOCK_NONBLOCK)
    int conn = accept4(m_fd, NULL, NULL, SOCK_NONBLOCK);
#else
    int conn = accept(m_fd, NULL, NULL);
#endif
    if (conn < 0)
        return 0;
    else
        return conn;
}
