/*
 *  Copyright (C) 2025 CZ.NIC, z. s. p. o.
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

 #include <vector>
 #include <rapidjson/stringbuffer.h>
 #include <rapidjson/writer.h>

 #include "export/BaseExport.h"
 #include "JsonWriter.h"

 namespace DDP {
    /**
     * @brief Class for buffering DNS records to JSON string
     */
    class JsonExport : public BaseExport {
        public:
        /**
         * @brief Constructor creates new vector of JSON objects representing DNS records
         * @param cfg Object with configuration options
         * @param country_db GeoIP country database
         * @param asn_db GeoIP ASN database
         */
        JsonExport(Config& cfg, MMDB_s& country_db, MMDB_s& asn_db);

        /**
         * @brief Store DNS record into JSON object
         * @param record DNS record to store
         * @return Shared pointer with vector of JSON objects to export or nullptr if there's nothing to export
         */
        boost::any buffer_record(DnsRecord& record) override;

        /**
         * @brief Rotate current vector of JSON objects (export current one and start a new one)
         * @return boost::any Current vector of JSON objects to export
         */
        boost::any rotate_export() override {
            if (m_chunk->size() == 0)
                return nullptr;

            std::shared_ptr<std::vector<rapidjson::StringBuffer>> ret = m_chunk;
            m_chunk = std::make_shared<std::vector<rapidjson::StringBuffer>>(m_max_records);
            return ret;
        }

        /**
         * @brief Write currently buffered records into file on application exit
         * @param writer JsonWriter!!! object that handles writing JSON objects to output
         * @param stats Statistics for update
         */
        void write_leftovers(BaseWriter* writer, Statistics& stats) override {
            if (writer)
                write_leftovers(*dynamic_cast<JsonWriter*>(writer), stats);
        }

        /**
         * @brief Write currently buffered records into file on application exit
         * @param writer Object that handles writing JSON objects to output
         * @param stats Statistics for update
         */
        void write_leftovers(JsonWriter& writer, Statistics& stats);

        /**
         * @brief Update export configuration (nothing is done here)
         */
        void update_configuration(Config&) override {}

        private:
        /**
         * @brief Write array of DNS resource records to internal JSON buffer
         * @param rrs Array of DNS resource records to buffer
         */
        void write_rr_array(std::vector<DnsRR*>& rrs);

        rapidjson::StringBuffer m_buffer;
        rapidjson::Writer<rapidjson::StringBuffer> m_writer;
        std::shared_ptr<std::vector<rapidjson::StringBuffer>> m_chunk;
        bool m_export_resp_rr;
        uint64_t m_max_records;
        char m_rdata_buffer[UINT16_MAX];
    };
 }