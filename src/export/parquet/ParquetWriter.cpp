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

#include <sys/stat.h>
#include <sys/types.h>

#include "ParquetWriter.h"

int64_t DDP::ParquetWriter::write(std::shared_ptr<arrow::Table> item)
{
    if (item == nullptr)
        return 0;

    m_filename = filename("parquet", false);
    std::string full_name;
    std::shared_ptr<arrow::io::OutputStream> outfile;

    full_name = m_filename + ".part";
    auto res = arrow::io::FileOutputStream::Open(full_name);
    PARQUET_THROW_NOT_OK(res);
    outfile = res.ValueOrDie();

    if (m_compress) {
        parquet::WriterProperties::Builder propsBuilder;
        propsBuilder.compression(parquet::Compression::GZIP);
        auto props = propsBuilder.build();
        PARQUET_THROW_NOT_OK(parquet::arrow::WriteTable(*item, arrow::default_memory_pool(), outfile, item->num_rows(), props));
    }
    else
        PARQUET_THROW_NOT_OK(parquet::arrow::WriteTable(*item, arrow::default_memory_pool(), outfile, item->num_rows()));

    auto ret = outfile->Close();
    if (!ret.ok())
        throw std::runtime_error("Arrow: " + ret.ToString());

    chmod(full_name.c_str(), 0666);
    if (m_cfg.export_location.value() == ExportLocation::LOCAL) {
        if (std::rename(full_name.c_str(), m_filename.c_str()))
            throw std::runtime_error("Couldn't rename the output file!");
    }
    else {
        check_file_transfer();
        m_threads.emplace_back(std::async(std::launch::async, send_file, m_type,
            m_cfg.export_ip.value(), m_cfg.export_port.value(), m_filename, ".part", DEFAULT_TRIES));
        m_unsent_files.insert(m_filename);
    }

    return item->num_rows();
}