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
#include <arpa/inet.h>
#include <sys/socket.h>
#include <maxminddb.h>

#ifdef PROBE_CRYPTOPANT
#include <cryptopANT.h>
#endif

#include "core/DnsRecord.h"
#include "core/Statistics.h"
#include "config/Config.h"
#include "BaseWriter.h"

namespace DDP {

    class DnsExportException : public std::exception {};

    /**
     * @brief Abstract class serving as interface for classes buffering
     * DNS records to export structures
     */
    class BaseExport
    {
    public:
        explicit BaseExport(bool anonymize_ip, MMDB_s& country_db, MMDB_s& asn_db)
        : m_anonymize_ip(anonymize_ip), m_country(country_db), m_asn(asn_db) {}

        virtual ~BaseExport() {};

        /**
         * @brief Store DNS record into export structure
         * @param record DNS record to store
         * @return Structure to export or nullptr if there's nothing to export
         */
        virtual boost::any buffer_record(DnsRecord& record) = 0;

        /**
         * @brief Rotate current export structure (export current one and start a new one)
         * @return boost::any Current structure to export
         */
        virtual boost::any rotate_export() = 0;

        /**
         * @brief Write currently buffered records into file on application exit
         * @param writer Object that handles writing to output
         * @param stats Statistics for update
         */
        virtual void write_leftovers(BaseWriter* writer, Statistics& stats) = 0;

        /**
         * @brief Update export configuration
         * @param cfg New configuration
         */
        virtual void update_configuration(Config& cfg) = 0;

    protected:

        /**
         * @brief Fill given ASN and Country Code strings from Maxmind databases based on given IP address
         * @param addr IP address to lookup in Maxmind databases
         * @param ipv Version of given IP address
         * @param asn ASN string to fill with IP's ASN
         * @param country Country Code string to fill with IP's ISO 3166-1 country code
         */
        void fill_asn_country(const in6_addr* addr, int ipv, std::string& asn, std::string& country);

        bool m_anonymize_ip;
        MMDB_s& m_country;
        MMDB_s& m_asn;
    };
}
