/*
 *  Copyright (C) 2021 CZ.NIC, z. s. p. o.
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

#include "BaseExport.h"

constexpr char DDP::BaseExport::DIGITS[];

void DDP::BaseExport::fill_asn_country(const in6_addr* addr, int ipv, std::string& asn, std::string& country)
{
    if (m_country.filename != nullptr || m_asn.filename != nullptr) {
        sockaddr_in sa4;
        sockaddr_in6 sa6;
        sockaddr* sa = nullptr;

        if (ipv == AF_INET) {
            sa4.sin_family = AF_INET;
            sa = reinterpret_cast<sockaddr*>(&sa4);
            sa4.sin_addr = *reinterpret_cast<const in_addr*>(addr);
        }
        else {
            sa6.sin6_family = AF_INET6;
            sa6.sin6_addr = *addr;
            sa = reinterpret_cast<sockaddr*>(&sa6);
        }

        if (m_country.filename != nullptr) {
            int err;
            auto result = MMDB_lookup_sockaddr(&m_country, sa, &err);
            if (err == MMDB_SUCCESS && result.found_entry) {
                MMDB_entry_data_s data;
                int status = MMDB_get_value(&result.entry, &data, "country", "iso_code", NULL);
                if (status == MMDB_SUCCESS && data.has_data && data.type == MMDB_DATA_TYPE_UTF8_STRING)
                    country = std::string(data.utf8_string, data.data_size);
            }
        }

        if (m_asn.filename != nullptr) {
            int err;
            auto result = MMDB_lookup_sockaddr(&m_asn, sa, &err);
            if (err == MMDB_SUCCESS && result.found_entry) {
                MMDB_entry_data_s data;
                int status = MMDB_get_value(&result.entry, &data, "autonomous_system_number", NULL);
                if (status == MMDB_SUCCESS && data.has_data && data.type == MMDB_DATA_TYPE_UINT32)
                    asn = std::to_string(data.uint32);
            }
        }
    }
}

std::unordered_map<uint16_t, boost::any> DDP::BaseExport::parse_edns_options(const uint8_t* ptr, uint16_t size)
{
    std::unordered_map<uint16_t, boost::any> ret;
    uint16_t parsed = 0;
    std::string other_options = "";

    while (parsed < size) {
        if (size - parsed < DNS_MIN_EDNS_OPTION_SIZE) {
            throw EdnsParseException("Invalid EDNS option size");
        }
        uint16_t option = ntohs(*reinterpret_cast<const uint16_t*>(ptr));
        ptr += 2;
        parsed += 2;
        int16_t opt_len = ntohs(*reinterpret_cast<const uint16_t*>(ptr));
        if (opt_len > (size - parsed - 2)) {
            throw EdnsParseException("Invalid RR record");
        }
        ptr += 2;
        parsed += 2;

        if (opt_len > 0) {
            switch (option) {
                // parse NSID
                case static_cast<uint16_t>(EDNSOptions::NSID):
                    ret[static_cast<uint16_t>(EDNSOptions::NSID)] = std::string(reinterpret_cast<const char*>(ptr), opt_len);
                    break;

                // parse DNSSEC DAU algorithms list
                case static_cast<uint16_t>(EDNSOptions::DNSSEC_DAU):
                    ret[static_cast<uint16_t>(EDNSOptions::DNSSEC_DAU)] = parse_dnssec_list(ptr, opt_len);
                    break;

                // parse DNSSEC DHU algorithms list
                case static_cast<uint16_t>(EDNSOptions::DNSSEC_DHU):
                    ret[static_cast<uint16_t>(EDNSOptions::DNSSEC_DHU)] = parse_dnssec_list(ptr, opt_len);
                    break;

                // parse DNSSEC N3U algorithms list
                case static_cast<uint16_t>(EDNSOptions::DNSSEC_N3U):
                    ret[static_cast<uint16_t>(EDNSOptions::DNSSEC_N3U)] = parse_dnssec_list(ptr, opt_len);
                    break;

                // TODO parse Client Subnet option
                case static_cast<uint16_t>(EDNSOptions::ClientSubnet):
                    add_edns_option_code_to_string(other_options, option);
                    break;

                default:
                    add_edns_option_code_to_string(other_options, option);
                    break;
            }
        }

        parsed += opt_len;
        ptr += opt_len;
    }

    ret[static_cast<uint16_t>(EDNSOptions::Other)] = std::move(other_options);

    return ret;
}

std::string DDP::BaseExport::parse_dnssec_list(const uint8_t* ptr, uint16_t opt_len)
{
    uint16_t str_len = 0;
    char str_buffer[4];
    char* str_ptr = str_buffer;
    uint8_t str_size = 0;
    bool not_first = false;
    std::string ret;

    // Traverse the list of algorithm codes and write them to buffer
    for (int i = 0; i < opt_len; i++) {
        // Write comma to buffer to separate algorithm codes
        if (not_first) {
            ret += ",";
        }
        else {
            not_first = true;
        }

        // Write algorithm code to buffer
        str_ptr = format_int(*(ptr + i), str_buffer);
        str_size = 4 - (str_ptr - str_buffer) - 1;

        ret += std::string(str_ptr, str_size);

        str_len += str_size;
    }

    return ret;
}

void DDP::BaseExport::add_edns_option_code_to_string(std::string& option_string, uint16_t option_code)
{
    if (!option_string.empty())
        option_string.append(",");

    option_string.append(std::to_string(option_code));
}

char* DDP::BaseExport::format_int(uint8_t value, char* buffer)
{
    char* ptr = buffer + 3;

    while(value >= 100) {
        auto index = static_cast<unsigned>((value % 100) * 2);
        value /= 100;
        *--ptr = DIGITS[index + 1];
        *--ptr = DIGITS[index];
    }

    if (value < 10) {
        *--ptr = static_cast<char>('0' + value);
        return ptr;
    }

    auto index = static_cast<unsigned>(value * 2);
    *--ptr = DIGITS[index + 1];
    *--ptr = DIGITS[index];
    return ptr;
}
