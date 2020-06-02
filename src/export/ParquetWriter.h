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
        int64_t write(std::shared_ptr<arrow::Table> item) {
            if (item == nullptr)
                return 0;

            m_filename = filename("parquet", false);
            std::string full_name = m_filename + ".part";
            auto res = arrow::io::FileOutputStream::Open(full_name);
            PARQUET_THROW_NOT_OK(res);
            std::shared_ptr<arrow::io::FileOutputStream> outfile = res.ValueOrDie();

            parquet::WriterProperties::Builder propsBuilder;
            propsBuilder.compression(parquet::Compression::GZIP);
            auto props = propsBuilder.build();

            if (m_compress)
                PARQUET_THROW_NOT_OK(parquet::arrow::WriteTable(*item, arrow::default_memory_pool(), outfile, item->num_rows(), props));
            else
                PARQUET_THROW_NOT_OK(parquet::arrow::WriteTable(*item, arrow::default_memory_pool(), outfile, item->num_rows()));

            outfile->Close();
            if (std::rename(full_name.c_str(), m_filename.c_str()))
                throw std::runtime_error("Couldn't rename the output file!");

            chmod(m_filename.c_str(), 0666);

            return item->num_rows();
        }

        /**
         * @brief Close current output and open a new one.
         * Does nothing because Parquet creates a new output for each arrow Table anyway.
         */
        void rotate_output() override {}

        private:
        bool m_compress;
    };
}