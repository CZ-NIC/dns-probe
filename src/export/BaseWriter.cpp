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
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations including
 *  the two.
 */

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/ssl.h>

#include "BaseWriter.h"
#include "utils/Logger.h"

namespace DDP {
    std::string send_file(Config cfg, std::string filename, std::string sufix, uint8_t tries)
    {
        auto pos = filename.find_last_of('/');

        for (int i = 0; i < tries; i++) {
            try {
                TlsConnection tls(cfg);
                std::ifstream ifs(filename + sufix, std::ifstream::binary);
                if (ifs.fail())
                    throw std::runtime_error("Couldn't read file for transfer!");

                if (pos == std::string::npos) {
                    uint8_t length = filename.size();
                    tls.write(&length, 1);
                    tls.write(filename.data(), filename.size());
                }
                else {
                    uint8_t length = filename.size() - pos - 1;
                    tls.write(&length, 1);
                    tls.write(filename.data() + pos + 1, length);
                }

                unsigned char buffer[4096];
                while (!ifs.eof()) {
                    ifs.read(reinterpret_cast<char*>(buffer), 4096);
                    tls.write(buffer, ifs.gcount());
                }

                ifs.close();
                std::remove((filename + sufix).c_str());
                return "";
            }
            catch (std::exception& e) {}
        }

        Logger("Writer").warning() << "Couldn't send output file to remote server!";
        if (std::rename((filename + sufix).c_str(), filename.c_str()))
            Logger("Writer").warning() << "Couldn't rename the output file!";
        return filename;
    }

    std::unordered_set<std::string> send_files(Config cfg, std::unordered_set<std::string> flist)
    {
        for (auto it = flist.begin(); it != flist.end(); ) {
            auto ret = send_file(cfg, *it, "", 1);
            if (ret.empty())
                it = flist.erase(it);
            else
                ++it;
        }

        return flist;
    }

    void TlsCtx::init(std::string ca_cert)
    {
        if (m_ctx)
            return;

        SSL_library_init();
        SSL_load_error_strings();
#ifndef PROBE_OPENSSL_LEGACY
        const SSL_METHOD* method = TLS_client_method();
#else
        const SSL_METHOD* method = TLSv1_2_client_method();
#endif
        SSL_CTX* ctx = SSL_CTX_new(method);
        if (!ctx)
            throw std::runtime_error("Error creating TLS context!");

        if (!ca_cert.empty()) {
            if (!SSL_CTX_load_verify_locations(ctx, ca_cert.c_str(), NULL)) {
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
        m_ctx = ctx;
    }

    TlsCtx::~TlsCtx()
    {
        if (m_ctx)
            SSL_CTX_free(m_ctx);
    }

    void TlsConnection::close()
    {
        if (m_ssl) {
            SSL_shutdown(m_ssl);
            SSL_shutdown(m_ssl);
            SSL_free(m_ssl);
            ::close(m_fd);
            m_ssl = nullptr;
            m_fd = -1;
        }
    }

    int TlsConnection::write(const void* data, int64_t n_bytes)
    {
        if (n_bytes == 0)
            return 0;

        if (!m_ssl)
            return 0;

        int written = SSL_write(m_ssl, data, n_bytes);
        if (written <= 0) {
            int err = SSL_get_error(m_ssl, written);
            throw std::runtime_error("Couldn't write to output! SSL error code: " + std::to_string(err));
        }

        return written;
    }

    void TlsConnection::open()
    {
        sockaddr_in sa4;
        std::memset(&sa4, 0, sizeof(sa4));
        int ret = inet_pton(AF_INET, m_ip.c_str(), &sa4.sin_addr.s_addr);
        if (ret == 1) {
            sa4.sin_family = AF_INET;
            sa4.sin_port = htons(m_port);

            m_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (m_fd < 0)
                throw std::runtime_error("Couldn't open socket for remote export!");

            if (connect(m_fd, reinterpret_cast<sockaddr*>(&sa4), sizeof(sa4)))
                throw std::runtime_error("Error connecting to server for remote export!");
        }
        else {
            sockaddr_in6 sa6;
            std::memset(&sa6, 0, sizeof(sa6));
            ret = inet_pton(AF_INET6, m_ip.c_str(), &sa6.sin6_addr);
            if (ret != 1)
                throw std::runtime_error("Invalid IP address of remote server");

            sa6.sin6_family = AF_INET6;
            sa6.sin6_port = htons(m_port);

            m_fd = socket(AF_INET6, SOCK_STREAM, 0);
            if (m_fd < 0)
                throw std::runtime_error("Couldn't open socket for remote export!");

            if (connect(m_fd, reinterpret_cast<sockaddr*>(&sa6), sizeof(sa6)))
                throw std::runtime_error("Error connecting to server for remote export!");
        }

        m_ctx = TlsCtx::getInstance().get();
        SSL* ssl = SSL_new(m_ctx);
        if (!ssl)
            throw std::runtime_error("Error creating TLS structure!");

        SSL_set_fd(ssl, m_fd);
        int err = SSL_connect(ssl);
        if (err <= 0) {
            SSL_free(ssl);
            throw std::runtime_error("Error creating TLS connection to server for remote export!");
        }

        m_ssl = ssl;
    }

    std::string BaseWriter::filename(std::string sufix, bool invalid)
    {
        std::string inv;
        char time[20];
        timespec timestamp;
        tm tmp_tm;

        clock_gettime(CLOCK_REALTIME, &timestamp);
        gmtime_r(&timestamp.tv_sec, &tmp_tm);
        strftime(time, 20, "%Y%m%d-%H%M%S", &tmp_tm);

        if (invalid) {
            inv = "_inv";
        }
        std::string counter = "_" + std::to_string(m_filename_counter);
        std::string full_sufix = sufix.empty() ? "" : ("." + sufix);
        std::string filename = m_cfg.target_directory.value() + "/" + m_cfg.file_prefix.value() +
                                std::string(time) + m_id + inv + counter + full_sufix;

        struct stat buffer;
        if (stat((filename + m_sufix).c_str(), &buffer) == 0) {
            return m_cfg.target_directory.value() + "/" + m_cfg.file_prefix.value() + std::string(time) +
                m_id + inv + "_" + std::to_string(++m_filename_counter) + full_sufix;
        } else {
            if (m_filename_counter == 0) {
                return filename;
            }
            else {
                m_filename_counter = 0;
                return m_cfg.target_directory.value() + "/" + m_cfg.file_prefix.value() +
                    std::string(time) + m_id + inv + "_" + std::to_string(m_filename_counter) + full_sufix;
            }
        }
    }

    void BaseWriter::check_file_transfer()
    {
        if (!m_threads.empty()) {
            m_threads.erase(std::remove_if(m_threads.begin(), m_threads.end(),
                [this](auto& x) {
                bool ret = x.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
                if (ret) {
                    auto result = x.get();
                    if (!result.empty())
                        m_unsent_files.insert(result);
                }
                return ret;
            }));
        }

        if (m_files_thread.valid() &&
            (m_files_thread.wait_for(std::chrono::seconds(0)) == std::future_status::ready)) {
            auto failed = m_files_thread.get();
            for (auto&& file : failed) {
                m_unsent_files.insert(file);
            }

            if (!m_unsent_files.empty()) {
                m_files_thread = std::async(std::launch::async, send_files, m_cfg, m_unsent_files);
                m_unsent_files.clear();
            }
        }
        else if (!m_files_thread.valid()) {
            if (!m_unsent_files.empty()) {
                m_files_thread = std::async(std::launch::async, send_files, m_cfg, m_unsent_files);
                m_unsent_files.clear();
            }
        }
    }
}
