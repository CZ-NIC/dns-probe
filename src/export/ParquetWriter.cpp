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

#include "ParquetWriter.h"

int64_t DDP::ParquetWriter::write(std::shared_ptr<arrow::Table> item)
{
    if (item == nullptr)
        return 0;

    m_filename = filename("parquet", false);
    std::string full_name;
    std::shared_ptr<arrow::io::OutputStream> outfile;

    if (m_cfg.export_location.value() == ExportLocation::LOCAL) {
        full_name = m_filename + ".part";
        auto res = arrow::io::FileOutputStream::Open(full_name);
        PARQUET_THROW_NOT_OK(res);
        outfile = res.ValueOrDie();
    }
    else {
        auto tls = std::make_shared<TlsConnection>(m_cfg);
        auto res = arrow::io::TlsOutputStream::Open(tls);
        PARQUET_THROW_NOT_OK(res);
        outfile = res.ValueOrDie();

        // Have to write filename size and filename directly to TLS connection instead of
        // Parquet output because parquet::arrow::WriteTable() doesn't support appending to output
        auto pos = m_filename.find_last_of('/');
        if (pos == std::string::npos) {
            uint8_t length = m_filename.size();
            tls->write(&length, 1);
            tls->write(m_filename.data(), m_filename.size());
        }
        else {
            uint8_t length = m_filename.size() - pos - 1;
            tls->write(&length, 1);
            tls->write(m_filename.data() + pos + 1, length);
        }
    }

    if (m_compress) {
        parquet::WriterProperties::Builder propsBuilder;
        propsBuilder.compression(parquet::Compression::GZIP);
        auto props = propsBuilder.build();
        PARQUET_THROW_NOT_OK(parquet::arrow::WriteTable(*item, arrow::default_memory_pool(), outfile, item->num_rows(), props));
    }
    else
        PARQUET_THROW_NOT_OK(parquet::arrow::WriteTable(*item, arrow::default_memory_pool(), outfile, item->num_rows()));

    outfile->Close();

    if (m_cfg.export_location.value() == ExportLocation::LOCAL) {
        chmod(full_name.c_str(), 0666);
        if (std::rename(full_name.c_str(), m_filename.c_str()))
            throw std::runtime_error("Couldn't rename the output file!");

    }

    return item->num_rows();
}