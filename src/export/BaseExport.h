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
#include <cstdint>
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

    /**
     * @brief Generic exception thrown when DNS record export fails
     */
    class DnsExportException : public std::runtime_error
    {
    public:
        explicit DnsExportException( const std::string& what_arg ) : std::runtime_error(what_arg) {}
        explicit DnsExportException( const char* what_arg ) : std::runtime_error(what_arg) {}
    };

    /**
     * @brief Exception thrown if parsing of EDNS record's data fails
     */
    class EdnsParseException : public std::runtime_error
    {
    public:
        explicit EdnsParseException( const std::string& what_arg ) : std::runtime_error(what_arg) {}
        explicit EdnsParseException( const char* what_arg ) : std::runtime_error(what_arg) {}
    };

    /**
     * @brief Abstract class serving as interface for classes buffering
     * DNS records to export structures
     */
    class BaseExport
    {
    public:
        static constexpr char DIGITS[] = "0001020304050607080910111213141516171819"
                                         "2021222324252627282930313233343536373839"
                                         "4041424344454647484950515253545556575859"
                                         "6061626364656667686970717273747576777879"
                                         "8081828384858687888990919293949596979899";
        static constexpr uint8_t DNS_MIN_EDNS_OPTION_SIZE = 4;

        /**
         * @brief Enumeration of EDNS options' codes
         */
        enum class EDNSOptions : uint16_t {
            NSID = 3,
            DNSSEC_DAU = 5,
            DNSSEC_DHU = 6,
            DNSSEC_N3U = 7,
            ClientSubnet = 8,

            Other = UINT16_MAX
        };

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

        /**
         * @brief Parse all EDNS options in OPT RR data section
         * @param ptr Pointer to start of options data
         * @param size Size of the options data to parse
         * @throw EdnsParseException
         * @return Map containing all found and parsed EDNS options
         */
        std::unordered_map<uint16_t, boost::any> parse_edns_options(const uint8_t* ptr, uint16_t size);

        /**
         * @brief Parse DNSSEC algorithm's list into comma separated values
         * @param ptr Pointer to start of the list
         * @param opt_len Length of algorithm list in bytes
         * @return List of comma separated values indicating supported DNSSEC algorithms
         */
        std::string parse_dnssec_list(const uint8_t* ptr, uint16_t opt_len);

        /**
         * @brief Add EDNS option code to a string list of option codes
         * @param option_string String option list to add to
         * @param option_code EDNS option code to add to the string list
         */
        void add_edns_option_code_to_string(std::string& option_string, uint16_t option_code);

        /**
        * @brief Convert number to C string
        * @param value Number to convert
        * @param buffer Buffer to store the string
        * @return Pointer to the start of the string in buffer
        */
        static char* format_int(uint8_t value, char* buffer);

        bool m_anonymize_ip;
        MMDB_s& m_country;
        MMDB_s& m_asn;
    };
}
