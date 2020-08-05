/*
 *  Copyright (C) 2020 Brno University of Technology
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

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cdns/cdns.h>

#include "BaseWriter.h"

namespace DDP {
    int TlsConnection::write(const void* data, int64_t n_bytes)
    {
        if (!m_ssl)
            return 0;

        int written = SSL_write(m_ssl, data, n_bytes);
        if (written < 0) {
            int err = SSL_get_error(m_ssl, written);
            throw std::runtime_error("Couldn't write to output! SSL error code: " + std::to_string(err));
        }

        return written;
    }

    void TlsConnection::open()
    {
        m_fd = socket(static_cast<int>(m_ipv), SOCK_STREAM, 0);
        if (m_fd < 0)
            throw std::runtime_error("Couldn't open socket for remote export");

        if (m_ipv == ExportIpVersion::IPV4) {
            sockaddr_in sa;
            std::memset(&sa, 0, sizeof(sa));
            sa.sin_family = static_cast<int>(m_ipv);
            inet_pton(static_cast<int>(m_ipv), m_ip.c_str(), &sa.sin_addr.s_addr);
            sa.sin_port = htons(m_port);
            if (connect(m_fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)))
                throw std::runtime_error("Error connecting to server for remote export!");
        }
        else {
            sockaddr_in6 sa;
            std::memset(&sa, 0, sizeof(sa));
            sa.sin6_family = static_cast<int>(m_ipv);
            inet_pton(static_cast<int>(m_ipv), m_ip.c_str(), &sa.sin6_addr);
            sa.sin6_port = htons(m_port);
            if (connect(m_fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)))
                throw std::runtime_error("Error connecting to server for remote export!");
        }

        SSL_library_init();
        SSL_load_error_strings();
        const SSL_METHOD* method = TLS_client_method();
        SSL_CTX* ctx = SSL_CTX_new(method);
        if (!ctx)
            throw std::runtime_error("Error creating TLS context!");

        if (!m_ca_cert.empty()) {
            if (!SSL_CTX_load_verify_locations(ctx, m_ca_cert.c_str(), NULL)) {
                SSL_CTX_free(ctx);
                throw std::runtime_error("Error loading CA certificate!");
            }
        }
        else {
            if (!SSL_CTX_set_default_verify_paths(ctx)) {
                SSL_CTX_free(ctx);
                throw std::runtime_error("Error loading default CA certificates!");
            }
        }

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

        SSL* ssl = SSL_new(ctx);
        if (!ssl) {
            SSL_CTX_free(ctx);
            throw std::runtime_error("Error creating TLS structure!");
        }

        SSL_set_fd(ssl, m_fd);
        int err = SSL_connect(ssl);
        if (err <= 0) {
            SSL_CTX_free(ctx);
            SSL_free(ssl);
            throw std::runtime_error("Error creating TLS connection to server for remote export!");
        }

        m_ssl = ssl;
        SSL_CTX_free(ctx);
    }
}
