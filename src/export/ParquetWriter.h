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

#include <cstdio>
#include <arrow/api.h>
#include <arrow/io/api.h>
#include <parquet/arrow/reader.h>
#include <parquet/arrow/writer.h>
#include <parquet/exception.h>

#include "DnsWriter.h"

namespace arrow::io {
    /**
     * @brief Parquet output stream writing data to TLS connection
     */
    class TlsOutputStream : public OutputStream {
        public:
        /**
         * @brief Create new Parquet output stream
         * @param ssl TLS connection to bind to this output stream
         * @return New Parquet output stream bound to given TLS connection
         */
        static Result<std::shared_ptr<TlsOutputStream>> Open(std::shared_ptr<DDP::TlsConnection> ssl) {
            return Result<std::shared_ptr<TlsOutputStream>>(std::make_shared<TlsOutputStream>(ssl));
        }

        TlsOutputStream(std::shared_ptr<DDP::TlsConnection> ssl) : OutputStream(), m_out(ssl), m_pos(0) {}
        ~TlsOutputStream() override { Close(); }

        /**
         * @brief Close the Parquet output stream. Closes the internal TLS connection
         * @return Status message
         */
        Status Close() override {
            if (m_out) {
                m_out->close();
                m_out = nullptr;
            }
            m_pos = 0;
            return Status::OK();
        }

        /**
         * @brief Return the position in this stream
         * @return Current position in this stream
         */
        Result<int64_t> Tell() const override { return Result<int64_t>(m_pos); }

        /**
         * @brief Return whether the stream is closed
         * @return TRUE if the stream is closed, FALSE otherwise
         */
        bool closed() const override {
            if (!m_out)
                return true;
            else
                return m_out->closed();
        }

        /**
         * @brief Write given data to the output stream i.e. to the TLS connection
         * @param data Buffer with data to write
         * @param n_bytes Length of the data buffer
         * @return Status message
         */
        Status Write(const void* data, int64_t n_bytes) override {
            if (!m_out || m_out->closed())
                return Status::IOError("No valid TLS connection established!");

            m_pos += m_out->write(data, n_bytes);

            return Status::OK();
        }

        private:
        std::shared_ptr<DDP::TlsConnection> m_out;
        int m_pos;
    };
}


namespace DDP {
    /**
     * @brief Class for writing finished Arrow tables to output
     */
    class ParquetWriter : public DnsWriter {
        public:
        /**
         * @brief Construct a new ParquetWriter object
         * @param cfg Configuration of the output
         * @param process_id Process ID used for generating names of the output files
         */
        explicit ParquetWriter(Config& cfg, uint32_t process_id) : DnsWriter(cfg, process_id),
                                                                   m_compress(cfg.file_compression.value()) {}

        /**
         * @brief Write Arrow table to output
         * @param item Arrow table ready for export to output
         * @throw ::parquet::ParquetException
         * @return Number of DNS records written to output
         */
        int64_t write(boost::any item) override {
            if (item.type() != typeid(std::shared_ptr<arrow::Table>))
                return 0;

            return write(boost::any_cast<std::shared_ptr<arrow::Table>>(item));
        }

        /**
         * @brief Write Arrow table to output
         * @param item Arrow table ready for export to output
         * @throw ::parquet::ParquetException
         * @return Number of DNS records written to output
         */
        int64_t write(std::shared_ptr<arrow::Table> item);

        /**
         * @brief Close current output and open a new one.
         * Does nothing because Parquet creates a new output for each arrow Table anyway.
         */
        void rotate_output() override {}

        private:
        bool m_compress;
    };
}