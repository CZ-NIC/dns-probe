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

#include "CdnsWriter.h"

DDP::CdnsWriter::CdnsWriter(Config& cfg, uint32_t process_id) : DnsWriter(cfg, process_id,
                                                                cfg.file_compression.value() ? ".gz" : ""),
                                                                m_writer(nullptr), m_bytes_written(0),
                                                                m_blocks_written(0),
                                                                m_tls(nullptr)
{
    CDNS::FilePreamble fp;

    fp.m_block_parameters[0].storage_parameters.max_block_items = m_cfg.cdns_records_per_block.value();
    set_cdns_hints(fp.m_block_parameters[0].storage_parameters.storage_hints.query_response_hints,
                   fp.m_block_parameters[0].storage_parameters.storage_hints.query_response_signature_hints,
                   cfg.cdns_fields.value());

    m_filename = filename("cdns", false);
    if (m_cfg.file_compression.value()) {
        if (m_cfg.export_location.value() == ExportLocation::LOCAL)
            m_writer = new CDNS::CdnsExporter(fp, m_filename, CDNS::CborOutputCompression::GZIP);
        else {
            m_tls = std::make_shared<TlsConnection>(m_cfg);
            m_writer = new CDNS::CdnsExporter(fp, m_tls, CDNS::CborOutputCompression::GZIP);
        }
    }
    else {
        if (m_cfg.export_location.value() == ExportLocation::LOCAL)
            m_writer = new CDNS::CdnsExporter(fp, m_filename, CDNS::CborOutputCompression::NO_COMPRESSION);
        else {
            m_tls = std::make_shared<TlsConnection>(m_cfg);
            m_writer = new CDNS::CdnsExporter(fp, m_tls, CDNS::CborOutputCompression::NO_COMPRESSION);
        }
    }

    m_filename += m_sufix;

    // Have to write filename length and filename directly to TLS connection
    if (m_cfg.export_location.value() == ExportLocation::REMOTE) {
        write_filename();
    }
}

void DDP::CdnsWriter::rotate_output()
{
    std::string rotated = m_filename;
    m_filename = filename("cdns", false);
    if (m_cfg.export_location.value() == ExportLocation::LOCAL) {
        m_bytes_written += m_writer->rotate_output(m_filename, false);
        m_filename += m_sufix;

        struct stat buffer;
        if (m_bytes_written == 0 && stat(rotated.c_str(), &buffer) == 0)
            remove(rotated.c_str());
        else
            chmod(rotated.c_str(), 0666);
    }
    else {
        m_tls = std::make_shared<TlsConnection>(m_cfg);
        m_bytes_written += m_writer->rotate_output(m_tls, false);
        m_filename += m_sufix;

        write_filename();
    }

    m_blocks_written = 0;
    m_bytes_written = 0;
}

void DDP::CdnsWriter::write_filename()
{
    auto pos = m_filename.find_last_of('/');
    if (pos == std::string::npos) {
        uint8_t length = m_filename.size();
        m_tls->write(&length, 1);
        m_tls->write(m_filename.data(), m_filename.size());
    }
    else {
        uint8_t length = m_filename.size() - pos - 1;
        m_tls->write(&length, 1);
        m_tls->write(m_filename.data() + pos + 1, length);
    }
}
