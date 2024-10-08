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

#include <bitset>
#include <cdns/cdns.h>

#include "export/BaseExport.h"
#include "CdnsWriter.h"

namespace DDP {
    /**
     * @brief Class for buffering DNS records to C-DNS block
     */
    class CdnsExport : public BaseExport {
        public:
        /**
         * @brief Constructor creates new C-DNS block configured for given C-DNS fields
         * @param cfg Object witch configuration options
         */
        CdnsExport(Config& cfg, MMDB_s& country_db, MMDB_s& asn_db);

        /**
         * @brief Store DNS record into C-DNS block
         * @param record DNS record to store
         * @return Shared pointer with C-DNS Block to export or nullptr if there's nothing to export
         */
        boost::any buffer_record(DnsRecord& record) override;

        /**
         * @brief Rotate current C-DNS block (export current one and start a new one)
         * @return boost::any Current C-DNS block to export
         */
        boost::any rotate_export() override {
            if (m_block->get_item_count() == 0)
                return nullptr;

            std::shared_ptr<CDNS::CdnsBlock> ret = m_block;
            m_block = std::make_shared<CDNS::CdnsBlock>(CDNS::CdnsBlock(m_parameters, 0));
            return ret;
        }

        /**
         * @brief Write currently buffered records into file on application exit
         * @param writer CdnsWriter!!! object that handles writing C-DNS Block to output
         * @param stats Statistics for update
         */
        void write_leftovers(BaseWriter* writer, Statistics& stats) override {
            if (writer)
                write_leftovers(*dynamic_cast<CdnsWriter*>(writer), stats);
        };

        /**
         * @brief Write currently buffered records into file on application exit
         * @param writer Object that handles writing C-DNS Blocks to output
         * @param stats Statistics for update
         */
        void write_leftovers(CdnsWriter& writer, Statistics& stats);

        /**
         * @brief Update export configuration (nothing is done here)
         * @param cfg New configuration
         */
        void update_configuration(Config&) override {}

        private:
        std::shared_ptr<CDNS::CdnsBlock> m_block;
        std::bitset<CdnsBits> m_fields;
        CDNS::BlockParameters m_parameters;
        bool m_export_resp_rr;
    };
}