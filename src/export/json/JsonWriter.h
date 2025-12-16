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

 #include <rapidjson/stringbuffer.h>

 #include "export/BaseWriter.h"

 namespace DDP {
    /**
     * @brief Class for writing finished JSON objects to output
     */
    class JsonWriter : public BaseWriter {
        public:
        /**
         * @brief Construct a new JsonWriter object
         * @param cfg Configuration of the output
         * @param process_id Process ID used for generating names of the output files
         */
        JsonWriter(Config& cfg, uint32_t process_id);

        /**
         * @brief Delete JSON writer object and exported file if it's empty
         */
        ~JsonWriter();

        /**
         * @brief Write given item with buffered DNS records to output
         * @param item Item with DNS records ready for export to output
         * @return Number of DNS records written to output
         */
        int64_t write(boost::any item) override {
            if (item.type() != typeid(std::shared_ptr<std::vector<rapidjson::StringBuffer>>))
                return 0;

            return write(boost::any_cast<std::shared_ptr<std::vector<rapidjson::StringBuffer>>>(item));
        }

        /**
         * @brief Write vector of JSON objects to output
         * @param item Vector of JSON objects for export to output
         * @return Number of DNS records written to output
         */
        int64_t write(std::shared_ptr<std::vector<rapidjson::StringBuffer>> item);

        /**
         * @brief Close current output and open a new one
         */
        void rotate_output() override;

        class BaseSink;

        private:
        std::unique_ptr<BaseSink> m_sink;
        uint64_t m_bytes_written;
        uint64_t m_records_exported;
    };
 }