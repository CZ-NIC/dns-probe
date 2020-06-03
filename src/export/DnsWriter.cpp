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

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cdns/cdns.h>

#include "DnsWriter.h"

namespace DDP {
    void set_cdns_hints(uint32_t& qr_hints, uint32_t& qr_sig_hints, std::bitset<23> fields)
    {
        qr_hints = 0;
        qr_sig_hints = 0;

        if (fields[static_cast<uint32_t>(CDNSField::TRANSACTION_ID)])
            qr_hints |= CDNS::QueryResponseHintsMask::transaction_id;

        if (fields[static_cast<uint32_t>(CDNSField::TIME_OFFSET)])
            qr_hints |= CDNS::QueryResponseHintsMask::time_offset;

        if (fields[static_cast<uint32_t>(CDNSField::QUERY_NAME)])
            qr_hints |= CDNS::QueryResponseHintsMask::query_name_index;

        if (fields[static_cast<uint32_t>(CDNSField::CLIENT_HOPLIMIT)])
            qr_hints |= CDNS::QueryResponseHintsMask::client_hoplimit;

        if (fields[static_cast<uint32_t>(CDNSField::QR_TRANSPORT_FLAGS)])
            qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::qr_transport_flags;

        if (fields[static_cast<uint32_t>(CDNSField::CLIENT_ADDRESS)])
            qr_hints |= CDNS::QueryResponseHintsMask::client_address_index;

        if (fields[static_cast<uint32_t>(CDNSField::CLIENT_PORT)])
            qr_hints |= CDNS::QueryResponseHintsMask::client_port;

        if (fields[static_cast<uint32_t>(CDNSField::SERVER_ADDRESS)])
            qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::server_address_index;

        if (fields[static_cast<uint32_t>(CDNSField::SERVER_PORT)])
            qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::server_port;

        if (fields[static_cast<uint32_t>(CDNSField::QUERY_SIZE)])
            qr_hints |= CDNS::QueryResponseHintsMask::query_size;

        if (fields[static_cast<uint32_t>(CDNSField::QR_DNS_FLAGS)])
            qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::qr_dns_flags;

        if (fields[static_cast<uint32_t>(CDNSField::QUERY_ANCOUNT)])
            qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::query_ancount;

        if (fields[static_cast<uint32_t>(CDNSField::QUERY_ARCOUNT)])
            qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::query_arcount;

        if (fields[static_cast<uint32_t>(CDNSField::QUERY_NSCOUNT)])
            qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::query_nscount;

        if (fields[static_cast<uint32_t>(CDNSField::QUERY_QDCOUNT)])
            qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::query_qdcount;

        if (fields[static_cast<uint32_t>(CDNSField::QUERY_OPCODE)])
            qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::query_opcode;

        if (fields[static_cast<uint32_t>(CDNSField::RESPONSE_RCODE)])
            qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::response_rcode;

        if (fields[static_cast<uint32_t>(CDNSField::QUERY_CLASSTYPE)])
            qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::query_classtype_index;

        if (fields[static_cast<uint32_t>(CDNSField::QUERY_EDNS_VERSION)])
            qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::query_edns_version;

        if (fields[static_cast<uint32_t>(CDNSField::QUERY_EDNS_UDP_SIZE)])
            qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::query_udp_size;

        if (fields[static_cast<uint32_t>(CDNSField::QUERY_OPT_RDATA)])
            qr_sig_hints |= CDNS::QueryResponseSignatureHintsMask::query_opt_rdata_index;

        if (fields[static_cast<uint32_t>(CDNSField::RESPONSE_ADDITIONAL_SECTIONS)])
            qr_hints |= CDNS::QueryResponseHintsMask::response_additional_sections;

        if (fields[static_cast<uint32_t>(CDNSField::RESPONSE_SIZE)])
            qr_hints |= CDNS::QueryResponseHintsMask::response_size;
    }

    int TlsConnection::write(const void* data, int64_t n_bytes)
    {
        if (!m_ssl)
            return 0;

        int written = SSL_write(m_ssl, data, n_bytes);
        if (written < 0) {
            int err = SSL_get_error(m_ssl, written);
            throw std::runtime_error("Couldn't write to output! SSL error code: " + std::to_string(err));
        }

        return written;
    }

    void TlsConnection::open()
    {
        m_fd = socket(static_cast<int>(m_ipv), SOCK_STREAM, 0);
        if (m_fd < 0)
            throw std::runtime_error("Couldn't open socket for remote export");

        if (m_ipv == ExportIpVersion::IPV4) {
            sockaddr_in sa;
            std::memset(&sa, 0, sizeof(sa));
            sa.sin_family = static_cast<int>(m_ipv);
            inet_pton(static_cast<int>(m_ipv), m_ip.c_str(), &sa.sin_addr.s_addr);
            sa.sin_port = htons(m_port);
            if (connect(m_fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)))
                throw std::runtime_error("Error connecting to server for remote export!");
        }
        else {
            sockaddr_in6 sa;
            std::memset(&sa, 0, sizeof(sa));
            sa.sin6_family = static_cast<int>(m_ipv);
            inet_pton(static_cast<int>(m_ipv), m_ip.c_str(), &sa.sin6_addr);
            sa.sin6_port = htons(m_port);
            if (connect(m_fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)))
                throw std::runtime_error("Error connecting to server for remote export!");
        }

        SSL_library_init();
        SSL_load_error_strings();
        const SSL_METHOD* method = TLS_client_method();
        SSL_CTX* ctx = SSL_CTX_new(method);
        SSL* ssl = SSL_new(ctx);
        if (!ssl)
            throw std::runtime_error("Error creating TLS context!");

        SSL_set_fd(ssl, m_fd);
        int err = SSL_connect(ssl);
        if (err <= 0)
            throw std::runtime_error("Error creating TLS connection to server for remote export!");

        m_ssl = ssl;
    }
}
