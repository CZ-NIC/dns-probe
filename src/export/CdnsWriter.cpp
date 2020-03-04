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

DDP::CdnsWriter::CdnsWriter(Config& cfg, uint32_t process_id) : DnsWriter(cfg, process_id), m_writer(nullptr),
                                                                m_bytes_written(0), m_blocks_written(0)
{
    CDNS::FilePreamble fp;

    fp.m_block_parameters[0].storage_parameters.max_block_items = m_cfg.cdns_records_per_block.value();
    set_cdns_hints(fp.m_block_parameters[0].storage_parameters.storage_hints.query_response_hints,
                   fp.m_block_parameters[0].storage_parameters.storage_hints.query_response_signature_hints,
                   cfg.cdns_fields.value());

    m_filename = filename("cdns", false);
    m_writer = new CDNS::CdnsExporter(fp, m_filename, CDNS::CborOutputCompression::NO_COMPRESSION);
    m_filename += m_sufix;
}

void DDP::CdnsWriter::rotate_output()
{
    std::string rotated = m_filename;
    m_filename = filename("cdns", false);
    m_bytes_written += m_writer->rotate_output(m_filename, false);
    m_filename += m_sufix;

    struct stat buffer;
    if (m_bytes_written == 0 && stat(rotated.c_str(), &buffer) == 0)
        remove(rotated.c_str());
    else
        chmod(rotated.c_str(), 0666);

    m_blocks_written = 0;
    m_bytes_written = 0;
}
