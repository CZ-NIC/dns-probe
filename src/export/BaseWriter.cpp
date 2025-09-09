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

#include <cstdio>
#include <fstream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <regex>
#include <time.h>

#ifdef PROBE_KAFKA
#include <librdkafka/rdkafkacpp.h>
#endif

#include "BaseWriter.h"
#include "utils/Logger.h"
#include "utils/Time.h"

namespace DDP {
#ifdef PROBE_KAFKA
    KafkaProducer::KafkaProducer(KafkaConfig& config)
        : m_config(config), m_sent(false), m_timestamp_regex(timestamp_regex_str)
    {
        m_conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);
        if (!m_conf)
            throw std::runtime_error("Couldn't create Kafka config!");

        std::string err;
        if  (m_conf->set("bootstrap.servers", m_config.brokers.value(), err) != RdKafka::Conf::CONF_OK) {
            delete m_conf;
            throw std::runtime_error("Couldn't set Kafka brokers: " + err);
        }

        if (!m_config.ca_location.value().empty()) {
            if (m_conf->set("ssl.ca.location", m_config.ca_location.value(), err) != RdKafka::Conf::CONF_OK) {
                delete m_conf;
                throw std::runtime_error("Couldn't set CA location for Kafka: " + err);
            }
        }

        if (m_conf->set("security.protocol", m_config.sec_protocol.string(), err) != RdKafka::Conf::CONF_OK) {
            delete m_conf;
            throw std::runtime_error("Couldn't set Kafka security protocol: " + err);
        }

        if (!m_config.cert_location.value().empty()) {
            if (m_conf->set("ssl.certificate.location", m_config.cert_location.value(), err) != RdKafka::Conf::CONF_OK) {
                delete m_conf;
                throw std::runtime_error("Couldn't set client's public key for Kafka: " + err);
            }
        }

        if (!m_config.key_location.value().empty()) {
            if (m_conf->set("ssl.key.location", m_config.key_location.value(), err) != RdKafka::Conf::CONF_OK) {
                delete m_conf;
                throw std::runtime_error("Couldn't set client's private key for Kafka: " + err);
            }
        }

        if (!m_config.key_passwd.value().empty()) {
            if (m_conf->set("ssl.key.password", "", err) != RdKafka::Conf::CONF_OK) {
                delete m_conf;
                throw std::runtime_error("Couldn't set client's private key password for Kafka: " + err);
            }
        }

        if (m_config.sec_protocol.value() == KafkaSecurityProtocol::SASL_PLAINTEXT ||
            m_config.sec_protocol.value() == KafkaSecurityProtocol::SASL_SSL) {
            if (m_conf->set("sasl.mechanisms", m_config.sasl_mechanism.string(), err) != RdKafka::Conf::CONF_OK) {
                delete m_conf;
                throw std::runtime_error("Couldn't set Kafka SASL mechanisms: " + err);
            }

            if (!m_config.sasl_username.value().empty()) {
                if (m_conf->set("sasl.username", m_config.sasl_username.value(), err) != RdKafka::Conf::CONF_OK) {
                    delete m_conf;
                    throw std::runtime_error("Couldn't set Kafka username: " + err);
                }
            }

            if (!m_config.sasl_password.value().empty()) {
                if (m_conf->set("sasl.password", m_config.sasl_password.value(), err) != RdKafka::Conf::CONF_OK) {
                    delete m_conf;
                    throw std::runtime_error("Couldn't set Kafka password: " + err);
                }
            }
        }

        if (m_conf->set("dr_cb", &m_delivery_cb, err) != RdKafka::Conf::CONF_OK) {
            delete m_conf;
            throw std::runtime_error("Couldn't set Kafka delivery callback: " + err);
        }

        m_producer = RdKafka::Producer::create(m_conf, err);
        if (!m_producer) {
            delete m_conf;
            throw std::runtime_error("Couldn't create Kafka producer: " + err);
        }
    }

    KafkaProducer::~KafkaProducer()
    {
        m_producer->flush(10 * 1000); // wait max 10 seconds
        delete m_producer;
        delete m_conf;
    }

    FileCtx KafkaProducer::write(std::string&& message, std::string& filename)
    {
        std::string key = m_config.partition.value();

        auto err = m_producer->produce(m_config.topic.value(), RdKafka::Topic::PARTITION_UA,
            RdKafka::Producer::RK_MSG_COPY, const_cast<char*>(message.c_str()), message.size(), key.c_str(),
            key.size(), get_timestamp_from_filename(filename), &m_sent);

        if (err != RdKafka::ERR_NO_ERROR)
            return FileCtx{filename, false};

        m_producer->poll(-1);

        if (m_sent) {
            m_sent = false;
            return FileCtx{filename, true};
        }
        else
            return FileCtx{filename, false};
    }

    void KafkaProducer::DeliveryReportCb::dr_cb(RdKafka::Message& message)
    {
        bool* sent = reinterpret_cast<bool*>(message.msg_opaque());

        if (message.err())
            *sent = false;
        else
            *sent = true;
    }

    int64_t KafkaProducer::get_timestamp_from_filename(std::string& filename)
    {
        std::smatch match;
        if (std::regex_match(filename, match, m_timestamp_regex)) {
            auto micros = std::stoul(match[3]);
            tm t;
            strptime(match[2].str().c_str(), "%Y%m%d.%H%M%S", &t);
            auto res = timegm(&t);
            return res * 1000 + micros / 1000;
        }
        else {
            auto timestamp = Time(DDP::Time::Clock::REALTIME);
            return timestamp.getMillis();
        }
    }

    FileCtx send_file_to_kafka(KafkaConfig config, std::string filename, std::string sufix, bool fail_rename)
    {
        struct stat buffer;
        if (stat((filename + sufix).c_str(), &buffer) != 0) {
            Logger("Writer").debug() << "Couldn't send output file! Filename doesn't exist: " << (filename + sufix);
            return FileCtx{filename, true};
        }

        FileCtx ret = FileCtx{filename, false};

        try {
            KafkaProducer producer = KafkaProducer(config);
            std::ifstream ifs(filename + sufix, std::ifstream::binary);
            if (ifs.fail())
                throw std::runtime_error("Couldn't read file for transfer!");

            std::ostringstream buff;
            buff << ifs.rdbuf();
            ret = producer.write(buff.str(), filename);
            ifs.close();

            if (!ret.sent)
                throw std::runtime_error("Kafka transfer failed!");
            else
                std::remove((filename + sufix).c_str());

            return ret;
        }
        catch (std::exception& e) {
            Logger("Writer").warning() << "Couldn't send output file to Kafka! " << e.what();
        }

        if (fail_rename) {
            if (std::rename((filename + sufix).c_str(), filename.c_str()))
                Logger("Writer").warning() << "Couldn't rename the output file!";
        }

        return ret;
    }

    std::unordered_set<FileCtx> send_files_to_kafka(KafkaConfig config, std::unordered_set<std::string> flist)
    {
        std::unordered_set<FileCtx> processed;

        for (auto& f : flist) {
            processed.insert(send_file_to_kafka(config, f, "", true));
        }

        return processed;
    }
#endif

    FileCtx send_file_attempt(TlsCtxIndex type, std::string ip, uint16_t port, std::string filename,
        std::string sufix, uint8_t tries, bool fail_rename)
    {
        struct stat buffer;
        if (stat((filename + sufix).c_str(), &buffer) != 0) {
            Logger("Writer").debug() << "Couldn't send output file! Filename doesn't exist: " << (filename + sufix);
            return FileCtx{filename, true};
        }

        auto pos = filename.find_last_of('/');

        for (int i = 0; i < tries; i++) {
            try {
                TlsConnection tls(type, ip, port);
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
                return FileCtx{filename, true};
            }
            catch (std::exception& e) {}
        }

        if (fail_rename) {
            if (std::rename((filename + sufix).c_str(), filename.c_str()))
                Logger("Writer").warning() << "Couldn't rename the output file!";
        }
        return FileCtx{filename, false};
    }

    FileCtx send_file(TlsCtxIndex type, std::string ip, uint16_t port, std::string bck_ip,
        uint16_t bck_port, std::string filename, std::string sufix, uint8_t tries)
    {
        auto ret = send_file_attempt(type, ip, port, filename, sufix, tries, bck_ip.empty());

        if (!ret.sent && !bck_ip.empty()) {
            ret = send_file_attempt(type, bck_ip, bck_port, filename, sufix, tries, true);
        }

        if (!ret.sent)
            Logger("Writer").warning() << "Couldn't send output file to remote server!";

        return ret;
    }

    std::unordered_set<FileCtx> send_files(TlsCtxIndex type, std::string ip, uint16_t port,
        std::string bck_ip, uint16_t bck_port, std::unordered_set<std::string> flist)
    {
        std::unordered_set<FileCtx> processed;

        for (auto& f : flist) {
            processed.insert(send_file(type, ip, port, bck_ip, bck_port, f, "", 1));
        }

        return processed;
    }

    void TlsCtx::init(TlsCtxIndex type, std::string ca_cert)
    {
        if (m_ctx[static_cast<uint8_t>(type)])
            return;

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
        m_ctx[static_cast<uint8_t>(type)] = ctx;
    }

    TlsCtx::~TlsCtx()
    {
        if (m_ctx[static_cast<uint8_t>(TlsCtxIndex::TRAFFIC)])
            SSL_CTX_free(m_ctx[static_cast<uint8_t>(TlsCtxIndex::TRAFFIC)]);

        if (m_ctx[static_cast<uint8_t>(TlsCtxIndex::STATISTICS)])
            SSL_CTX_free(m_ctx[static_cast<uint8_t>(TlsCtxIndex::STATISTICS)]);
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

        ERR_clear_error();
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

            if (connect(m_fd, reinterpret_cast<sockaddr*>(&sa4), sizeof(sa4))) {
                ::close(m_fd);
                throw std::runtime_error("Error connecting to server for remote export!");
            }
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

            if (connect(m_fd, reinterpret_cast<sockaddr*>(&sa6), sizeof(sa6))) {
                ::close(m_fd);
                throw std::runtime_error("Error connecting to server for remote export!");
            }
        }

        m_ctx = TlsCtx::getInstance().get(m_connection_type);
        SSL* ssl = SSL_new(m_ctx);
        if (!ssl) {
            ::close(m_fd);
            throw std::runtime_error("Error creating TLS structure!");
        }

        ERR_clear_error();
        SSL_set_fd(ssl, m_fd);
        int err = SSL_connect(ssl);
        if (err <= 0) {
            SSL_free(ssl);
            ::close(m_fd);
            throw std::runtime_error("Error creating TLS connection to server for remote export!");
        }

        m_ssl = ssl;
    }

    std::string BaseWriter::filename(std::string sufix, bool invalid)
    {
        std::string inv;
        char time[30];
        timespec timestamp;
        tm tmp_tm;

        clock_gettime(CLOCK_REALTIME, &timestamp);
        gmtime_r(&timestamp.tv_sec, &tmp_tm);
        auto pos = strftime(time, 20, "%Y%m%d.%H%M%S.", &tmp_tm);
        std::snprintf(time + pos, sizeof(time) - pos, "%06lu", timestamp.tv_nsec / 1000);

        if (invalid)
            inv = ".inv";

        std::string full_sufix = sufix.empty() ? "" : ("." + sufix);
        return m_cfg.target_directory.value() + "/" + m_cfg.file_prefix.value() + std::string(time)
               + m_id + inv + full_sufix;
    }

    void BaseWriter::check_file_transfer()
    {
        // check for finished sending threads
        // if thread finished unsuccessfully, add file to unsent files list that will be tried again later
        if (!m_threads.empty()) {
            m_threads.erase(std::remove_if(m_threads.begin(), m_threads.end(),
                [this](auto& x) {
                if (!x.valid())
                    return true;
                bool ret = x.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
                if (ret) {
                    auto result = x.get();
                    m_sending_files.erase(result.name);
                    if (!result.sent)
                        m_unsent_files.insert(result.name);
                }
                return ret;
            }), m_threads.end());
        }

        if (m_files_thread.valid() &&
            (m_files_thread.wait_for(std::chrono::seconds(0)) == std::future_status::ready)) {
            auto files = m_files_thread.get();
            for (auto&& file : files) {
                if (file.sent)
                    m_unsent_files.erase(file.name);
            }

            if (!m_unsent_files.empty())
                send_unsent_files_list();
        }
        else if (!m_files_thread.valid()) {
            if (!m_unsent_files.empty())
                send_unsent_files_list();
        }

        save_unsent_files_list();
    }

    void BaseWriter::load_unsent_files_list()
    {
        std::ifstream unsent_list(unsent_filename());
        if (unsent_list.fail())
            return;

        std::string line;
        while (std::getline(unsent_list, line)) {
            m_unsent_files.insert(line);
        }
        unsent_list.close();

        send_unsent_files_list();
    }

    void BaseWriter::save_unsent_files_list()
    {
        std::ofstream unsent_list(unsent_filename());

        for (auto& file : m_unsent_files) {
            unsent_list << file << std::endl;
        }

        for (auto& file : m_sending_files) {
            unsent_list << file << std::endl;
        }

        unsent_list.close();
    }

    void BaseWriter::send_unsent_files_list()
    {
        if (m_type == TlsCtxIndex::TRAFFIC) {
            if (m_cfg.export_location.value() == ExportLocation::REMOTE) {
                m_files_thread = std::async(std::launch::async, send_files, m_type, m_cfg.export_ip.value(),
                    m_cfg.export_port.value(), m_cfg.backup_export_ip.value(), m_cfg.backup_export_port.value(),
                    m_unsent_files);
            }
#ifdef PROBE_KAFKA
            else if (m_cfg.export_location.value() == ExportLocation::KAFKA) {
                m_files_thread = std::async(std::launch::async, send_files_to_kafka, m_cfg.kafka_export,
                m_unsent_files);
            }
#endif
        }
        else {
            if (m_cfg.stats_location.value() == ExportLocation::REMOTE) {
                m_files_thread = std::async(std::launch::async, send_files, m_type, m_cfg.stats_ip.value(),
                    m_cfg.stats_port.value(), m_cfg.backup_stats_ip.value(), m_cfg.backup_stats_port.value(),
                    m_unsent_files);
            }
#ifdef PROBE_KAFKA
            else if (m_cfg.stats_location.value() == ExportLocation::KAFKA) {
                m_files_thread = std::async(std::launch::async, send_files_to_kafka,
                    m_cfg.stats_kafka_export, m_unsent_files);
            }
#endif
        }
    }

    void BaseWriter::cleanup()
    {
        for (auto&& th : m_threads) {
            th.wait();
            auto ret = th.get();
            if (ret.sent)
                m_sending_files.erase(ret.name);
        }

        if (m_files_thread.valid()) {
            m_files_thread.wait();
            auto ret = m_files_thread.get();
            for (auto&& f : ret) {
                if (f.sent)
                    m_unsent_files.erase(f.name);
            }
        }

        save_unsent_files_list();

        struct stat buffer;
        std::string file = unsent_filename();
        if (stat(file.c_str(), &buffer) == 0 && buffer.st_size == 0)
            remove(file.c_str());
    }
}
