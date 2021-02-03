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

#include "CdnsWriter.h"

void DDP::set_cdns_hints(uint32_t& qr_hints, uint32_t& qr_sig_hints, std::bitset<CdnsBits> fields)
{
    qr_hints = 0;
    qr_sig_hints = 0;

    if (fields[static_cast<uint32_t>(CDNSField::TRANSACTION_ID)])
        qr_hints |= CDNS::QueryResponseHintsMask::transaction_id;

    if (fields[static_cast<uint32_t>(CDNSField::TIME_OFFSET)])
        qr_hints |= CDNS::QueryResponseHintsMask::time_offset;

    if (fields[static_cast<uint32_t>(CDNSField::QUERY_NAME)])
        qr_hints |= CDNS::QueryResponseHintsMask::query_name_index;

    if (fields[static_cast<uint32_t>(CDNSField::CLIENT_HOPLIMIT)])
        qr_hints |= CDNS::QueryResponseHintsMask::client_hoplimit;

    if (fields[static_cast<uint32_t>(CDNSField::QR_TRANSPORT_FLAGS)])
        qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::qr_transport_flags;

    if (fields[static_cast<uint32_t>(CDNSField::CLIENT_ADDRESS)])
        qr_hints |= CDNS::QueryResponseHintsMask::client_address_index;

    if (fields[static_cast<uint32_t>(CDNSField::CLIENT_PORT)])
        qr_hints |= CDNS::QueryResponseHintsMask::client_port;

    if (fields[static_cast<uint32_t>(CDNSField::SERVER_ADDRESS)])
        qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::server_address_index;

    if (fields[static_cast<uint32_t>(CDNSField::SERVER_PORT)])
        qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::server_port;

    if (fields[static_cast<uint32_t>(CDNSField::QUERY_SIZE)])
        qr_hints |= CDNS::QueryResponseHintsMask::query_size;

    if (fields[static_cast<uint32_t>(CDNSField::QR_DNS_FLAGS)])
        qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::qr_dns_flags;

    if (fields[static_cast<uint32_t>(CDNSField::QUERY_ANCOUNT)])
        qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::query_ancount;

    if (fields[static_cast<uint32_t>(CDNSField::QUERY_ARCOUNT)])
        qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::query_arcount;

    if (fields[static_cast<uint32_t>(CDNSField::QUERY_NSCOUNT)])
        qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::query_nscount;

    if (fields[static_cast<uint32_t>(CDNSField::QUERY_QDCOUNT)])
        qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::query_qdcount;

    if (fields[static_cast<uint32_t>(CDNSField::QUERY_OPCODE)])
        qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::query_opcode;

    if (fields[static_cast<uint32_t>(CDNSField::RESPONSE_RCODE)])
        qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::response_rcode;

    if (fields[static_cast<uint32_t>(CDNSField::QUERY_CLASSTYPE)])
        qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::query_classtype_index;

    if (fields[static_cast<uint32_t>(CDNSField::QUERY_EDNS_VERSION)])
        qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::query_edns_version;

    if (fields[static_cast<uint32_t>(CDNSField::QUERY_EDNS_UDP_SIZE)])
        qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::query_udp_size;

    if (fields[static_cast<uint32_t>(CDNSField::QUERY_OPT_RDATA)])
        qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::query_opt_rdata_index;

    if (fields[static_cast<uint32_t>(CDNSField::RESPONSE_ADDITIONAL_SECTIONS)])
        qr_hints |= CDNS::QueryResponseHintsMask::response_additional_sections;

    if (fields[static_cast<uint32_t>(CDNSField::RESPONSE_SIZE)])
        qr_hints |= CDNS::QueryResponseHintsMask::response_size;
}

DDP::CdnsWriter::CdnsWriter(Config& cfg, uint32_t process_id) : BaseWriter(cfg, process_id,
                                                                cfg.file_compression.value() ? ".gz" : ""),
                                                                m_writer(nullptr), m_bytes_written(0),
                                                                m_blocks_written(0)
{
    CDNS::FilePreamble fp;

    fp.m_block_parameters[0].storage_parameters.max_block_items = m_cfg.cdns_records_per_block.value();
    set_cdns_hints(fp.m_block_parameters[0].storage_parameters.storage_hints.query_response_hints,
                   fp.m_block_parameters[0].storage_parameters.storage_hints.query_response_signature_hints,
                   cfg.cdns_fields.value());

    m_filename = filename("cdns", false);

    if (m_cfg.file_compression.value())
        m_writer = std::make_unique<CDNS::CdnsExporter>(fp, m_filename, CDNS::CborOutputCompression::GZIP);
    else
        m_writer = std::make_unique<CDNS::CdnsExporter>(fp, m_filename, CDNS::CborOutputCompression::NO_COMPRESSION);

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
    else {
        chmod(rotated.c_str(), 0666);
        if (m_cfg.export_location.value() == ExportLocation::REMOTE) {
            if (std::rename(rotated.c_str(), (rotated + ".part").c_str()))
                throw std::runtime_error("Couldn't rename the output file!");

            check_file_transfer();
            m_threads.emplace_back(std::async(std::launch::async, send_file, m_cfg, rotated, ".part", DEFAULT_TRIES));
        }
    }

    m_blocks_written = 0;
    m_bytes_written = 0;
}
