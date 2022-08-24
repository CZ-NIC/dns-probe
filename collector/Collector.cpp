/*
 *  Copyright (C) 2020 CZ.NIC, z.s.p.o.
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

#include <cstring>
#include <iostream>
#include <fstream>
#include <atomic>
#include <algorithm>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <poll.h>

#include "Collector.h"

extern std::atomic<bool> run_flag;

DDP::ConnectionHandler::ConnectionHandler(int conn, SSL_CTX* ctx, std::string& filepath) : m_fd(conn),
    m_ctx(ctx), m_ssl(nullptr), m_state(ConnectionStates::FILE_LENGTH), m_file_length(0), m_file_name(),
    m_file_path(filepath), m_out()
{
    m_ssl = SSL_new(ctx);
    if (!m_ssl)
        throw std::runtime_error("Couldn't create TLS object!");

    int ret = SSL_set_fd(m_ssl, conn);
    if (ret != 1) {
        close_connection();
        throw std::runtime_error("Couldn't pair socket with TLS object");
    }

    ret = SSL_accept(m_ssl);
    if (ret != 1) {
        int err = SSL_get_error(m_ssl, ret);
        close_connection();
        throw std::runtime_error("Couldn't establish TLS connection! SSL error code: " + std::to_string(err));
    }
}

void DDP::ConnectionHandler::run()
{
    int ret;
    pollfd polls[1];
    polls[0].fd = m_fd;
    polls[0].events = POLLIN;

    while(run_flag.load()) {
        ret = poll(polls, 1, 2000);

        if (ret > 0) {
            if (polls[0].revents & POLLIN) {
                read_data();
                if (m_state == ConnectionStates::FINISHED) {
                    m_out.close();
                    chmod((m_file_name + ".part").c_str(), 0666);
                    if (std::rename((m_file_name + ".part").c_str(), m_file_name.c_str()))
                        throw std::runtime_error("Couldn't rename the output file!");
                    break;
                }
            }
            else {
                throw std::runtime_error("File descriptor read error!");
            }
        }
        else if (ret == 0) {}
        else
            throw std::runtime_error("File descriptor error: " + std::to_string(errno));
    }
}

void DDP::ConnectionHandler::read_data()
{
    uint8_t buf[4096];
    int ret;

    if (m_state == ConnectionStates::FILE_LENGTH) {
        ret = SSL_read(m_ssl, buf, 1);
        if (ret <= 0)
            throw std::runtime_error("Couldn't read beginning of file!");
        m_file_length = buf[0];
        m_state = ConnectionStates::FILE_NAME;
    }
    else if (m_state == ConnectionStates::FILE_NAME) {
        ret = SSL_read(m_ssl, buf, m_file_length);
        if (ret <= 0)
            throw std::runtime_error("Couldn't read filename!");
        m_file_name = m_file_path + "/" + std::string(reinterpret_cast<char*>(buf), m_file_length);
        m_out.open(m_file_name + ".part", std::ios::binary);
        if (m_out.fail())
            throw std::runtime_error("Couldn't open output file!");
        m_state = ConnectionStates::DATA;
    }
    else if (m_state == ConnectionStates::DATA) {
        ret = SSL_read(m_ssl, buf, sizeof(buf));
        if (ret <= 0) {
            int err = SSL_get_error(m_ssl, ret);
            if (err == SSL_ERROR_ZERO_RETURN)
                m_state = ConnectionStates::FINISHED;
            else
                throw std::runtime_error("Error reading data! SSL error: " + std::to_string(err));
        }
        else {
            m_out.write(reinterpret_cast<char*>(buf), ret);
        }
    }
}

void DDP::ConnectionHandler::close_connection()
{
    if (m_ssl) {
        SSL_shutdown(m_ssl);
        SSL_free(m_ssl);
    }

    if (m_fd >= 0)
        ::close(m_fd);

    struct stat buffer;
    if (stat((m_file_name + ".part").c_str(), &buffer) == 0) {
        std::remove((m_file_name + ".part").c_str());
    }
}

void DDP::connection_handler(int conn, SSL_CTX* ctx, std::string filepath)
{
    try {
        DDP::ConnectionHandler handler(conn, ctx, filepath);
        handler.run();
    }
    catch (const std::exception& e) {
        std::cerr << "Connection failed: " << e.what() << std::endl;
    }
}

DDP::Collector::Collector(CConfig& cfg) : m_cfg(cfg)
{
    bool is_ipv4 = false;
    sockaddr* sa;
    sockaddr_in sa4;
    sockaddr_in6 sa6;
    std::memset(&sa4, 0, sizeof(sa4));
    std::memset(&sa6, 0, sizeof(sa6));

    if (!m_cfg.ip.empty()) {
        in_addr ipv4;
        int ret = inet_pton(AF_INET, m_cfg.ip.c_str(), &ipv4);
        if (ret == 1) {
            m_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (m_fd < 0)
                throw std::runtime_error("Couldn't open socket!");

            sa4.sin_family = AF_INET;
            sa4.sin_addr = ipv4;
            sa4.sin_port = htons(m_cfg.port);
            sa = reinterpret_cast<sockaddr*>(&sa4);
            is_ipv4 = true;
        }
        else {
            in6_addr ipv6;
            ret = inet_pton(AF_INET6, m_cfg.ip.c_str(), &ipv6);
            if (ret != 1)
                throw std::runtime_error("Given IP address is invalid!");

            m_fd = socket(AF_INET6, SOCK_STREAM, 0);
            if (m_fd < 0)
                throw std::runtime_error("Couldn't open socket!");

            sa6.sin6_family = AF_INET6;
            sa6.sin6_addr = ipv6;
            sa6.sin6_port = htons(m_cfg.port);
            sa = reinterpret_cast<sockaddr*>(&sa6);
        }
    }
    else {
        m_fd = socket(AF_INET6, SOCK_STREAM, 0);
        if (m_fd < 0)
            throw std::runtime_error("Couldn't open socket!");

        sa6.sin6_family = AF_INET6;
        sa6.sin6_addr = in6addr_any;
        sa6.sin6_port = htons(m_cfg.port);
        sa = reinterpret_cast<sockaddr*>(&sa6);
    }

    int on = 1;
    if (setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char*>(&on), sizeof(on)) < 0)
        throw std::runtime_error("Couldn't set socket options!");

    if (bind(m_fd, sa, is_ipv4 ? sizeof(sa4) : sizeof(sa6)))
        throw std::runtime_error("Couldn't bind to socket!");

    if (listen(m_fd, 10))
        throw std::runtime_error("Couldn't listen on socket!");

    SSL_library_init();
    SSL_load_error_strings();

#ifndef PROBE_OPENSSL_LEGACY
    const SSL_METHOD* method = TLS_server_method();
#else
    const SSL_METHOD* method = TLSv1_2_server_method();
#endif

    m_ctx = SSL_CTX_new(method);
    if (!m_ctx)
        throw std::runtime_error("Error creating TLS context!");

    if (SSL_CTX_use_certificate_file(m_ctx, m_cfg.cert.c_str(), SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(m_ctx);
        throw std::runtime_error("Error loading collector's certificate!");
    }

    if (SSL_CTX_use_PrivateKey_file(m_ctx, m_cfg.key.c_str(), SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(m_ctx);
        throw std::runtime_error("Error loading collector's private key!");
    }

    if (!SSL_CTX_check_private_key(m_ctx)) {
        SSL_CTX_free(m_ctx);
        throw std::runtime_error("Collector's private key doesn't match the certificate public key!");
    }
}

void DDP::Collector::run()
{
    int i = 0;
    while (run_flag.load()) {
        if (i >= TIMEOUT_LIMIT) {
            if (!m_threads.empty()) {
                m_threads.erase(std::remove_if(m_threads.begin(), m_threads.end(),
                    [](auto& x) { return !x.valid() || x.wait_for(std::chrono::seconds(0)) == std::future_status::ready; }), m_threads.end());
            }
            i = 0;
        }
        int conn = accept(m_fd, NULL, NULL);
        if (conn == -1) {
            if (errno != EINTR)
                std::cerr << "Socket accept error: " << errno << std::endl;
            continue;
        }

        if (!run_flag.load())
            break;

        m_threads.emplace_back(std::async(std::launch::async, connection_handler, conn, m_ctx, m_cfg.filepath));
        i++;
    }

    for (auto&& th : m_threads) {
        th.wait();
    }
}
