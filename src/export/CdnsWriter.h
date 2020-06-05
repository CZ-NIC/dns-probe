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

#pragma once

#include <cdns/cdns.h>

#include "DnsWriter.h"

namespace CDNS {
    /**
     * @brief Writes given data to output TLS connection
     * @tparam std::shared_ptr<DDP::TlsConnection> Output TLS connection
     */
    template<>
    class Writer<std::shared_ptr<DDP::TlsConnection>> : public BaseCborOutputWriter {
        public:
        /**
         * @brief Construct a new Writer object for writing data to output TLS connection
         * @param value Outputs TLS connection
         * @param extension Extension for the output file's name
         * @throw CborOutputExtension if the output TLS connection isn't valid
         */
        Writer(const std::shared_ptr<DDP::TlsConnection>& value, const std::string extension = "")
            : BaseCborOutputWriter(), m_value(value), m_extension(extension) { open(); }

        /**
         * @brief Destroy the Writer object and close the current output TLS connection
         */
        ~Writer() override { close(); }

        /** Delete copy and move constructors */
        Writer(Writer& copy) = delete;
        Writer(Writer&& copy) = delete;

        /**
         * @brief Write data in buffer to output TLS connection
         * @param p Start of the buffer with data
         * @param size Size of the data in bytes
         * @throw CborOutputException if output TLS connection is closed
         * @throw std::runtime_error if writing to output TLS connection fails
         */
        void write(const char* p, std::size_t size) override {
            if (!m_value || m_value->closed())
                throw CborOutputException("No valid TLS connection established!");

            m_value->write(p, size);
        }

        /**
         * @brief Rotate the output TLS connection (currently opened connection is closed)
         * @param value New output TLS connection
         * @throw CborOutputException if the output TLS connection isn't valid
         */
        void rotate_output(const boost::any& value) override {
            if (value.type() != typeid(std::shared_ptr<DDP::TlsConnection>))
                return;

            close();
            m_value = boost::any_cast<std::shared_ptr<DDP::TlsConnection>>(value);
            open();
        }

        protected:
        /**
         * @brief Check if the given TLS connection is valid
         * @throw CborOutputException if output TLS connection isn't valid
         */
        void open() override {
            if (!m_value || m_value->closed())
                throw CborOutputException("Given SSL connection handle is invalid!");
        }

        /**
         * @brief Close the opened output TLS connection
         */
        void close() override {
            if (m_value) {
                m_value->close();
                m_value = nullptr;
            }
        }

        std::shared_ptr<DDP::TlsConnection> m_value;
        std::string m_extension;
    };
}

namespace DDP {
    /**
     * @brief Class for writing finished C-DNS Blocks to output
     */
    class CdnsWriter : public DnsWriter {
        public:
        /**
         * @brief Construct a new CdnsWriter object
         * @param cfg Configuration of the output
         * @param process_id Process ID used for generating names of the output files
         * @throw CdnsEncoderException
         */
        CdnsWriter(Config& cfg, uint32_t process_id);

        /**
         * @brief Delete C-DNS writer object and exported file if it's empty
         */
        ~CdnsWriter() {
            if (m_writer)
                delete m_writer;

            if (m_cfg.export_location.value() == ExportLocation::LOCAL) {
                struct stat buffer;
                if (m_bytes_written == 0 && stat(m_filename.c_str(), &buffer) == 0)
                    remove(m_filename.c_str());
                else
                    chmod(m_filename.c_str(), 0666);
            }
        }

        /**
         * @brief Wriite given item with buffered DNS records to output
         * @param item Item with DNS records ready for export to output
         * @return Number of DNS records written to output
         */
        int64_t write(boost::any item) override {
            if (item.type() != typeid(std::shared_ptr<CDNS::CdnsBlock>))
                return 0;

            return write(boost::any_cast<std::shared_ptr<CDNS::CdnsBlock>>(item));
        }

        /**
         * @brief Write C-DNS Block to output
         * @param item C-DNS Block ready for export to output
         * @return Number of DNS records written to output
         */
        int64_t write(std::shared_ptr<CDNS::CdnsBlock> item) {
            if (item == nullptr)
                return 0;

            m_bytes_written += m_writer->write_block(*item);
            m_blocks_written++;

            if (m_cfg.cdns_blocks_per_file.value() != 0 &&
                m_blocks_written >= m_cfg.cdns_blocks_per_file.value())
                rotate_output();

            return item->get_qr_count();
        }

        /**
         * @brief Close current output and open a new one.
         */
        void rotate_output() override;

        private:

        /**
         * @brief Write filename size and filename to TLS connection
         */
        void write_filename();

        CDNS::CdnsExporter* m_writer;
        uint64_t m_bytes_written;
        uint64_t m_blocks_written;
        std::shared_ptr<TlsConnection> m_tls;
    };
}