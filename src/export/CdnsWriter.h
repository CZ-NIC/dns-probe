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

            struct stat buffer;
            if (m_bytes_written == 0 && stat(m_filename.c_str(), &buffer) == 0)
                remove(m_filename.c_str());
            else
                chmod(m_filename.c_str(), 0666);
        }

        /**
         * @brief Wriite given item with buffered DNS records to output
         * @param item Item with DNS records ready for export to output
         * @return Number of DNS records written to output
         */
        int64_t write(std::any item) override {
            if (item.type() != typeid(std::shared_ptr<CDNS::CdnsBlock>))
                return 0;

            return write(std::any_cast<std::shared_ptr<CDNS::CdnsBlock>>(item));
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
        CDNS::CdnsExporter* m_writer;
        uint64_t m_bytes_written;
        uint64_t m_blocks_written;
    };
}