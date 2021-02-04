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

#include <stdexcept>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "DnstapUnixReader.h"
#include "core/Port.h"
#include "platform/Packet.h"
#include "utils/Logger.h"

static fstrm_res fstrm__unix_reader_op_destroy(void*)
{
    return fstrm_res_success;
}

static fstrm_res fstrm__unix_reader_op_open(void* obj)
{
    DDP::DnstapUnixReader::fstrm__unix_reader* r  = reinterpret_cast<DDP::DnstapUnixReader::fstrm__unix_reader*>(obj);
    if (r->connected)
        return fstrm_res_success;

    if (r->fd < 0)
        return fstrm_res_failure;

    r->connected = true;
    return fstrm_res_success;
}

static fstrm_res fstrm__unix_reader_op_close(void* obj)
{
    DDP::DnstapUnixReader::fstrm__unix_reader* r  = reinterpret_cast<DDP::DnstapUnixReader::fstrm__unix_reader*>(obj);
    if (r->connected) {
        r->connected = false;
        close(r->fd);
        return fstrm_res_success;
    }
    return fstrm_res_failure;
}

static fstrm_res fstrm__unix_reader_op_read(void* obj, void* buf, size_t nbytes)
{
    DDP::DnstapUnixReader::fstrm__unix_reader* r  = reinterpret_cast<DDP::DnstapUnixReader::fstrm__unix_reader*>(obj);
    if (r->connected) {
        uint8_t* data = reinterpret_cast<uint8_t*>(buf);
        while (nbytes > 0) {
            ssize_t bytes_read = read(r->fd, data, nbytes);
            if (bytes_read == -1 && errno == EINTR)
                continue;
            else if (bytes_read <= 0)
                return fstrm_res_failure;
            nbytes -= bytes_read;
            data += bytes_read;
        }
        return fstrm_res_success;
    }
    return fstrm_res_failure;
}

static fstrm_res fstrm__unix_reader_op_write(void* obj, const struct iovec* iov, int iovcnt)
{
    DDP::DnstapUnixReader::fstrm__unix_reader* r  = reinterpret_cast<DDP::DnstapUnixReader::fstrm__unix_reader*>(obj);

    if (!r->connected)
        return fstrm_res_failure;

    for (int i = 0; i < iovcnt; i++) {
        if (write(r->fd, iov[i].iov_base, iov[i].iov_len) != static_cast<ssize_t>(iov[i].iov_len)) {
            fstrm__unix_reader_op_close(r);
            return fstrm_res_failure;
        }
    }

    return fstrm_res_success;
}

DDP::DnstapUnixReader::DnstapUnixReader(int fd)
    : m_fd(fd), m_opts(), m_reader(nullptr)
{
    m_opts.fd = fd;
    fstrm_rdwr* rdwr = fstrm_rdwr_init(&m_opts);
    fstrm_rdwr_set_destroy(rdwr, fstrm__unix_reader_op_destroy);
    fstrm_rdwr_set_open(rdwr, fstrm__unix_reader_op_open);
    fstrm_rdwr_set_close(rdwr, fstrm__unix_reader_op_close);
    fstrm_rdwr_set_read(rdwr, fstrm__unix_reader_op_read);

    /* We have to define a write callback too because libfstrm's unix socket writer
     * uses bidirectional handshake to establish connection */
    fstrm_rdwr_set_write(rdwr, fstrm__unix_reader_op_write);

    m_reader = fstrm_reader_init(nullptr, &rdwr);
    auto ret = fstrm_reader_open(m_reader);
    if (ret != fstrm_res_success)
        throw std::runtime_error("Couldn't initialize dnstap reader!");
}

DDP::DnstapUnixReader::~DnstapUnixReader()
{
    if (m_reader)
        fstrm_reader_destroy(&m_reader);
    m_reader = nullptr;
    close(m_fd);
}

uint16_t DDP::DnstapUnixReader::read(Packet* pkt)
{
    const uint8_t* data = nullptr;
    size_t len = 0;
    auto ret = fstrm_reader_read(m_reader, &data, &len);
    if (ret == fstrm_res_success) {
        try {
            *pkt = Packet(data, len, false, PacketType::DNSTAP);
        }
        catch (std::exception& e) {
            Logger("Dnstap").warning() << "Unable to read dnstap message";
            return 0;
        }
        return 1;
    }
    else if (ret == fstrm_res_stop)
        throw PortEOF();
    else
        return 0;
}
