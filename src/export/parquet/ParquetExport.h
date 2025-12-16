/*
 *  Copyright (C) 2018 Brno University of Technology
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

#include <exception>
#include <cstring>
#include <functional>
#include <unordered_map>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <arrow/api.h>
#include <arrow/io/api.h>
#include <parquet/arrow/reader.h>
#include <parquet/arrow/writer.h>
#include <parquet/exception.h>

#include "core/DnsRecord.h"
#include "export/BaseExport.h"
#include "core/Statistics.h"
#include "ParquetWriter.h"

namespace DDP {
    class ParquetExport : public BaseExport
    {
    public:
        static constexpr int COLUMNS = 55;

        /**
         * @brief Constructor creates Parquet file schema
         * @param cfg Object with configuration options
         */
        explicit ParquetExport(Config& cfg, MMDB_s& country_db, MMDB_s& asn_db);

        /**
         * @brief Store DNS record into arrow columns.
         * @param record DNS record to store
         * @throw ::parquet::ParquetException
         * @throw EdnsParseException when parsing of EDNS options fails
         * @return Shared pointer with Table in Arrow format or nullptr if there's nothing to export
         */
        boost::any buffer_record(DnsRecord& record) override;

        /**
         * @brief Rotate current Arrow table (export current one and start a new one)
         * @return boost::any Current Arrow table to export
         */
        boost::any rotate_export() override {
            return write_table();
        }

        /**
         * @brief Write currently buffered records into file on application exit
         * @param writer ParquetWriter!!! object thaht handles writing Arrow table to output
         * @param stats Statistics for update
         */
        void write_leftovers(BaseWriter* writer, Statistics& stats) override {
            if (writer)
                write_leftovers(*dynamic_cast<ParquetWriter*>(writer), stats);
        };

        /**
         * @brief Write currently buffered records into file on application exit
         * @param writer Object that handles writing Arrow table to output
         * @param stats Statistics for update
         * @throw ::parquet::ParquetException From calling write_table() and write_to_file()
         */
        void write_leftovers(ParquetWriter& writer, Statistics& stats);

        /**
         * @brief Update export configuration
         * @param cfg New configuration
         */
        void update_configuration(Config& cfg) override {
            m_records_limit = cfg.parquet_records.value();
        }

    private:
        /**
         * @brief Create new arrow table and send it to fileWriter ring
         * @return Shared pointer to table in Arrow format
         */
        std::shared_ptr<arrow::Table> write_table();

        arrow::Int32Builder ID;
        arrow::Int64Builder Time;
        arrow::Int64Builder UnixTime;
        arrow::StringBuilder Qname;
        arrow::StringBuilder Domainname;
        arrow::Int32Builder Len;
        arrow::Int32Builder Frag;
        arrow::Int32Builder TTL;
        arrow::Int32Builder IPv;
        arrow::Int32Builder Prot;
        arrow::StringBuilder Src;
        arrow::Int32Builder SrcPort;
        arrow::StringBuilder Dst;
        arrow::Int32Builder DstPort;
        arrow::Int32Builder UDPSum;
        arrow::Int32Builder DNSLen;

        arrow::BooleanBuilder AA;
        arrow::BooleanBuilder TC;
        arrow::BooleanBuilder RD;
        arrow::BooleanBuilder RA;
        arrow::BooleanBuilder Z;
        arrow::BooleanBuilder AD;
        arrow::BooleanBuilder CD;

        arrow::Int32Builder AnCount;
        arrow::Int32Builder ArCount;
        arrow::Int32Builder NsCount;
        arrow::Int32Builder QdCount;
        arrow::Int32Builder OpCode;
        arrow::Int32Builder RCode;
        arrow::Int32Builder QType;
        arrow::Int32Builder QClass;
        arrow::StringBuilder Country;
        arrow::StringBuilder ASN;

        arrow::Int32Builder EdnsUDP;
        arrow::Int32Builder EdnsVersion;
        arrow::BooleanBuilder EdnsDO;
        arrow::BooleanBuilder EdnsPing;
        arrow::StringBuilder EdnsNSID;
        arrow::StringBuilder EdnsDnssecDau;
        arrow::StringBuilder EdnsDnssecDhu;
        arrow::StringBuilder EdnsDnssecN3u;
        arrow::StringBuilder EdnsClientSubnet;
        arrow::StringBuilder EdnsOther;
        arrow::StringBuilder EdnsClientSubnetAsn;
        arrow::StringBuilder EdnsClientSubnetCountry;

        arrow::Int32Builder Labels;
        arrow::Int32Builder ResLen;
        arrow::Int64Builder TimeMicro;
        arrow::Int32Builder RespFrag;
        arrow::Int32Builder ProcTime;

        arrow::BooleanBuilder IsGoogle;
        arrow::BooleanBuilder IsOpenDNS;

        arrow::Int32Builder DNSResLen;
        arrow::StringBuilder ServerLocation;
        arrow::DoubleBuilder TcpHsRtt;

        std::shared_ptr<arrow::Schema> m_DnsSchema;
        uint64_t m_records_limit;
    };
}
