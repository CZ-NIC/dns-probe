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
