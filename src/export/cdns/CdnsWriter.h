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

#include <cdns/cdns.h>

#include "export/BaseWriter.h"
#include "utils/Logger.h"

namespace DDP {

    /**
     * @brief Set the C-DNS QueryResponse and QueryResponseSignature hints according to given C-DNS fields
     * @param qr_hints QueryResponse hints to set
     * @param qr_sig_hints QueryResponseSignature hints to set
     * @param fields C-DNS fields according to which the hints will be set
     */
    void set_cdns_hints(uint32_t& qr_hints, uint32_t& qr_sig_hints, std::bitset<CdnsBits> fields);

    /**
     * @brief Class for writing finished C-DNS Blocks to output
     */
    class CdnsWriter : public BaseWriter {
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
            m_writer = nullptr;

            try {
                struct stat buffer;
                if (m_bytes_written == 0 && stat(m_filename.c_str(), &buffer) == 0)
                    remove(m_filename.c_str());
                else {
                    chmod(m_filename.c_str(), 0666);
                    if (m_cfg.export_location.value() == ExportLocation::REMOTE) {
                        if (!std::rename(m_filename.c_str(), (m_filename + ".part").c_str()))
                            m_threads.emplace_back(std::async(std::launch::async, send_file,
                                                              TlsCtxIndex::TRAFFIC, m_cfg.export_ip.value(),
                                                              m_cfg.export_port.value(), m_filename,
                                                              ".part", DEFAULT_TRIES));
                    }
                }
            }
            catch (std::exception& e) {
                Logger("Writer").warning() << "Destructor error: " << e.what();
            }

            for (auto&& th : m_threads) {
                th.wait();
            }
        }

        /**
         * @brief Write given item with buffered DNS records to output
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

        std::unique_ptr<CDNS::CdnsExporter> m_writer;
        uint64_t m_bytes_written;
        uint64_t m_blocks_written;
    };
}
