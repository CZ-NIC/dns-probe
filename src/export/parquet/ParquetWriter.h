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

#include <cstdio>
#include <arrow/api.h>
#include <arrow/io/api.h>
#include <parquet/arrow/reader.h>
#include <parquet/arrow/writer.h>
#include <parquet/exception.h>

#include "export/BaseWriter.h"

namespace DDP {
    /**
     * @brief Class for writing finished Arrow tables to output
     */
    class ParquetWriter : public BaseWriter {
        public:
        /**
         * @brief Construct a new ParquetWriter object
         * @param cfg Configuration of the output
         * @param process_id Process ID used for generating names of the output files
         */
        explicit ParquetWriter(Config& cfg, uint32_t process_id) : BaseWriter(cfg, process_id, TlsCtxIndex::TRAFFIC),
                                                                   m_compress(cfg.file_compression.value()) {
            load_unsent_files_list();
        }

        ~ParquetWriter() { cleanup(); }

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
         * Checks if there are any unsent files and tries to resend them.
         */
        void rotate_output() override {
            if (m_cfg.export_location.value() == ExportLocation::REMOTE)
                check_file_transfer();
        }

        private:
        bool m_compress;
    };
}