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

#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <future>
#include <unordered_set>
#include <array>

#ifdef PROBE_KAFKA
#include <librdkafka/rdkafkacpp.h>
#endif

#include "config/Config.h"

struct ssl_ctx_st;
typedef struct ssl_ctx_st SSL_CTX;
struct ssl_st;
typedef struct ssl_st SSL;

namespace DDP {
    constexpr static uint8_t DEFAULT_TRIES = 3; //!< Default number of attempts to transfer file

    /**
     * @brief Indexes to SSL_CTX* array in TlsCtx class to differentiate between export of
     * traffic data and run-time statistics.
     */
    enum class TlsCtxIndex : uint8_t {
        TRAFFIC = 0,
        STATISTICS
    };

    /**
     * @brief Context of exported files that were attempted to be sent to remote location.
     */
    struct FileCtx {
        bool operator==(const FileCtx& fctx) const {
            return name == fctx.name && sent == fctx.sent;
        }

        std::string name; //!< Name of the file.
        bool sent; //!< TRUE if file was successfully sent to remote location, FALSE otherwise.
    };
}

/**
 * Hash function for DDP::FileCtx.
 * Used for storing context of sent files in std::unordered_set.
 */
namespace std {
    template<>
    struct hash<DDP::FileCtx>
    {
        size_t operator()(const DDP::FileCtx& fctx) const
        {
            return hash<string>()(fctx.name) ^ hash<bool>()(fctx.sent);
        }
    };
}

namespace DDP {

#ifdef PROBE_KAFKA
    /**
     * @brief Send local file to Kafka cluster
     * @param config Kafka configuration
     * @param filename Name of the file to send WITHOUT the ".part" sufix
     * @param sufix Sufix of the file to send (usually ".part" sufix)
     * @param fail_rename Indicate whether to rename the file on failure to send
     * @return File context struct with info if file transfer was successful or not
     */
    FileCtx send_file_to_kafka(KafkaConfig config, std::string filename, std::string sufix, bool fail_rename);

    /**
     * @brief Send files given in flist to Kafka cluster
     * @param config Kafka configuration
     * @param flist List of files to send
     * @return List of file context structs with info if file transfers were successful or not
     */
    std::unordered_set<FileCtx> send_files_to_kafka(KafkaConfig config, std::unordered_set<std::string> flist);

    /**
     * @brief RAII wrapper around Kafka producer using RdKafka library
     */
    class KafkaProducer {
        public:
        /**
         * @brief Construct a new Kafka producer from given configuration
         * @param config Kafka configuration
         */
        KafkaProducer(KafkaConfig& config);

        /**
         * @brief Destructor. Closes the producer and frees resources
         */
        ~KafkaProducer();

        /**
         * @brief Writes message (file) to Kafka cluster
         * @param message Message (file) data
         * @param filename Name of the file to write
         * @return File context struct with info if file transfer was successful or not
         */
        FileCtx write(std::string&& message, std::string& filename);

        private:
        /**
         * @brief Callback class for message (file) delivery status
         */
        class DeliveryReportCb : public RdKafka::DeliveryReportCb {
            public:
            /**
             * @brief Callback for message (file) delivery status
             * @param message Message from Kafka whether transfer was successful
             */
            void dr_cb(RdKafka::Message& message);
        };

        KafkaConfig m_config;
        bool m_sent;
        RdKafka::Conf* m_conf;
        RdKafka::Producer* m_producer;
        RdKafka::Topic* m_topic;
        DeliveryReportCb m_delivery_cb;
    };
#endif

    /**
     * @brief Send local file to remote server via TLS connection
     * @param type Determines what data (traffic or statistics) will be transferred,
     * so correct TLS context is chosen.
     * @param ip IP address of remote server
     * @param port Transport protocol port of remote server
     * @param bck_ip IP address of backup remote server
     * @param bck_port Transport protocol port of backup remote server
     * @param filename Name of the file to send WITHOUT the ".part" sufix
     * @param sufix Sufix of the file to send (usually ".part" sufix)
     * @param tries How many times should the file transfer be attempted before giving up
     * @return File context struct with info if file transfer was successful or not
     */
    FileCtx send_file(TlsCtxIndex type, std::string ip, uint16_t port, std::string bck_ip,
        uint16_t bck_port, std::string filename, std::string sufix, uint8_t tries);

    /**
     * @brief Send files given in flist to remote server via TLS connection
     * @param type Determines what data (traffic or statistics) will be transferred,
     * so correct TLS context is chosen.
     * @param ip IP address of remote server
     * @param port Transport protocol port of remote server
     * @param bck_ip IP address of backup remote server
     * @param bck_port Transport protocol port of backup remote server
     * @param flist List of files to send
     * @return List of file context structs with info if file transfers were successful or not
     */
    std::unordered_set<FileCtx> send_files(TlsCtxIndex type, std::string ip, uint16_t port,
        std::string bck_ip, uint16_t bck_port, std::unordered_set<std::string> flist);

    /**
     * @brief Singleton RAII wrapper around SSL_CTX structure from OpenSSL library
     */
    class TlsCtx {
        public:

        TlsCtx(const TlsCtx&) = delete;
        TlsCtx& operator=(const TlsCtx&) = delete;

        /**
         * @brief Get the singleton intance of TlsCtx
         * @return Singleton instance
         */
        static TlsCtx& getInstance() {
            static TlsCtx instance;
            return instance;
        }

        /**
         * @brief Initialize SSL/TLS context. Needs to be called before using the context
         * @param type Purpose of TLS connection - traffic or statistics transfer
         * @param ca_cert CA certificate to verify server for TLS connection
         */
        void init(TlsCtxIndex type, std::string ca_cert = "");

        /**
         * @brief Get TLS context
         * @param index Which TLS context to get - for traffic or statistics transfer
         */
        SSL_CTX* get(TlsCtxIndex index) { return m_ctx[static_cast<uint8_t>(index)]; }

        private:
        TlsCtx() : m_ctx({nullptr, nullptr}) {}

        /**
         * @brief Free the SSL/TLX context
         */
        ~TlsCtx();

        std::array<SSL_CTX*, 2> m_ctx;
    };

    /**
     * @brief RAII wrapper around TLS connection using OpenSSL library
     */
    class TlsConnection {
        public:

        /**
         * @brief Construct a new TLS connection from given configuration
         * @param type Determines what data (traffic or statistics) will be transferred,
         * so correct TLS context is chosen.
         * @param ip IP address of remote server
         * @param port Transport protocol port of remote server
         */
        TlsConnection(TlsCtxIndex type, std::string ip, uint16_t port)
            : m_fd(-1), m_ssl(nullptr), m_ctx(nullptr), m_ip(ip), m_port(port),
              m_connection_type(type) { open(); }

        /**
         * @brief Destructor. Closes the TLS connection if it's still opened
         */
        ~TlsConnection() { close(); }

        /**
         * @brief Gracefully close the TLS connection
         */
        void close();

        /**
         * @brief Send given data through the TLS connection
         * @param data Buffer with data to send
         * @param n_bytes Length of the data buffer
         * @return Number of bytes successfully sent through the TLS connection
         */
        int write(const void* data, int64_t n_bytes);

        /**
         * @brief Check if the TLS connection is already closed
         * @return TRUE if the connection is closed, FALSE otherwise
         */
        bool closed() const { return m_ssl ? false : true; }

        private:
        /**
         * @brief Open new TLS connection
         */
        void open();

        int m_fd;
        SSL* m_ssl;
        SSL_CTX* m_ctx;
        std::string m_ip;
        uint16_t m_port;
        TlsCtxIndex m_connection_type;
    };

    /**
     * @brief Abstract class serving as interface for output writing classes
     */
    class BaseWriter {
        public:
        /**
         * @brief Construct a new BaseWriter object
         * @param cfg Configuration of the output
         * @param process_id Process ID used for generating names of the output files
         * @param type Type of data this writer will write (traffic or statistics)
         * @param sufix Sufix of the generated names for export files
         */
        explicit BaseWriter(Config& cfg, uint32_t process_id, TlsCtxIndex type, std::string sufix = "") :
            m_cfg(cfg),
            m_id(".p" + std::to_string(process_id)),
            m_sufix(sufix),
            m_type(type),
            m_filename(),
            m_threads(),
            m_sending_files(),
            m_unsent_files(),
            m_files_thread() {}

        virtual ~BaseWriter() {}

        /**
         * @brief Write given item with buffered DNS records to output
         * @param item Item with DNS records ready for export to output
         * @return Number of DNS records written to output
         */
        virtual int64_t write(boost::any item) = 0;

        /**
         * @brief Close current output and open a new one
         */
        virtual void rotate_output() = 0;

        /**
         * @brief Update configuration of the output
         * @param cfg New configuration of the output
         */
        void update_configuration(Config& cfg) {
            m_cfg = cfg;
        }

        /**
         * @brief Generate filename for given parameters
         * @param sufix Filename sufix after the last dot
         * @param invalid TRUE only for PCAP files with invalid packets
         * @return Newly generated filename
         */
        std::string filename(std::string sufix, bool invalid);

        protected:
        /**
         * @brief Collects all finished transfer threads a checks for transfer success.
         * Spawns thread to resend all files from failed transfers if such thread doesn't already exist.
         */
        void check_file_transfer();

        /**
         * @brief Try to load file with names of unsent files at the start of probe process
         * @param type Determine if files with run-time stats or traffic data should be loaded
         */
        void load_unsent_files_list();

        /**
         * @brief Save list of currently unsent files to a file on disk.
         */
        void save_unsent_files_list();

        /**
         * @brief Send all files from list of currently unsent files
         */
        void send_unsent_files_list();

        /**
         * @brief Clean up all sending threads and save unsent files list to a file if it's not empty
         */
        void cleanup();

        std::string unsent_filename() {
            std::string file_type = m_type == TlsCtxIndex::TRAFFIC ? ".traffic" : ".stats";
            return m_cfg.target_directory.value() + "/dns-probe-" + m_cfg.instance.value() + m_id + file_type
                + ".unsent";
        }

        Config m_cfg;
        std::string m_id;
        std::string m_sufix;
        TlsCtxIndex m_type;
        std::string m_filename;
        std::vector<std::future<FileCtx>> m_threads; //!< List of threads for initial transfer attempt of individual exported files
        std::unordered_set<std::string> m_sending_files; //!< List of files that are currently attempting to be sent for the first time
        std::unordered_set<std::string> m_unsent_files; //!< List of files that previously failed transfer to remote location
        std::future<std::unordered_set<FileCtx>> m_files_thread; //!< Thread for sending list of files that failed initial transfer
    };
}