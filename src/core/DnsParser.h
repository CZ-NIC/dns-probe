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
 */

#pragma once

#include <exception>
#include <vector>

#include <cstdint>
#include <arpa/inet.h> // in6_addr
#include <sys/socket.h> // AF_INET and AF_INET6

#include "utils/Time.h"
#include "DnsRecord.h"
#include "config/Config.h"
#include "TransactionTable.h"
#include "DnsTcpConnection.h"
#include "utils/MemView.h"
#include "export/PcapWriter.h"
#include "utils/Logger.h"
#include "utils/DynamicMempool.h"
#include "platform/Mempool.h"

namespace DDP {

    /**
     * @brief Exception thrown if DNS message buffer cannot be allocated in DNS Parser constructor
     */
    class DnsParserConstuctor : public std::runtime_error
    {
    public:
        explicit DnsParserConstuctor( const std::string& what_arg ) : std::runtime_error(what_arg) {}
        explicit DnsParserConstuctor( const char* what_arg ) : std::runtime_error(what_arg) {}
    };

    /**
     * @brief Exception thrown if packet parsing fails when constructing DnsRecord
     */
    class DnsParseException : public std::runtime_error
    {
    public:
        explicit DnsParseException( const std::string& what_arg ) : std::runtime_error(what_arg) {}
        explicit DnsParseException( const char* what_arg ) : std::runtime_error(what_arg) {}
    };

    /**
     * @brief Exception thrown if non-DNS packet is encountered in DNS Parser
     */
    class NonDnsException : public std::runtime_error
    {
    public:
        explicit NonDnsException( const std::string& what_arg ) : std::runtime_error(what_arg) {}
        explicit NonDnsException( const char* what_arg ) : std::runtime_error(what_arg) {}
    };

    /**
     * @brief This class performs parsing of incoming packets
     */

    class DnsParser
    {
    public:
        static constexpr uint16_t ETHER_TYPE_IPV4 = 0x0800;
        static constexpr uint16_t ETHER_TYPE_IPV6 = 0x86DD;
        static constexpr uint8_t IP_VERSION_4 = 0x04;
        static constexpr uint8_t IP_VERSION_6 = 0x06;
        static constexpr uint8_t IPV4_ADDRLEN = 0x04;
        static constexpr uint8_t IPV6_ADDRLEN = 0x10;
        static constexpr uint16_t DNS_PORT = 0x35;

        static constexpr uint8_t DNS_HEADER_SIZE = 12;
        static constexpr uint8_t DNS_MIN_QUESTION_SIZE = 5;
        static constexpr uint8_t DNS_MAX_QNAME_SIZE = 255;
        static constexpr uint8_t DNS_MAX_LABEL_SIZE = 63;
        static constexpr uint8_t DNS_QTYPE_QCLASS_SIZE = 4;
        static constexpr uint8_t DNS_MIN_RR_SIZE = 11;
        static constexpr uint8_t DNS_RR_FIELDS_SKIP = 8;
        static constexpr uint8_t DNS_LABEL_PTR = 0xC0;

        static constexpr uint8_t DNS_EDNS_DO = 0x80;
        static constexpr uint8_t DNS_QTYPE_AXFR = 252;
        static constexpr uint8_t DNS_RCODE_OK0 = 0;
        static constexpr uint8_t DNS_RCODE_OK9 = 9;
        static constexpr uint8_t DNS_TYPE_SOA = 6;

        static constexpr uint8_t DNS_HEADER_QR = 0x80;
        static constexpr uint8_t DNS_HEADER_OPCODE = 0x78;
        static constexpr uint8_t DNS_HEADER_OPCODE_SHIFT = 3;
        static constexpr uint8_t DNS_HEADER_AA = 0x04;
        static constexpr uint8_t DNS_HEADER_TC = 0x02;
        static constexpr uint8_t DNS_HEADER_RD = 0x01;

        static constexpr uint8_t DNS_HEADER_RA = 0x80;
        static constexpr uint8_t DNS_HEADER_Z = 0x40;
        static constexpr uint8_t DNS_HEADER_AD = 0x20;
        static constexpr uint8_t DNS_HEADER_CD = 0x10;
        static constexpr uint8_t DNS_HEADER_RCODE = 0x0F;

        static constexpr uint8_t DNS_EDNS_RR_TYPE = 41;

        static constexpr uint16_t DNS_MSG_BUFFER_SIZE = UINT16_MAX;
        static constexpr uint16_t EDNS_MEMPOOL_ITEM_SIZE = 32;

        // DNS payload section types
        enum class DNSSectionType : uint8_t
        {
            QUESTION,
            ANSWER,
            AR,
            OTHER,
        };

        /**
         * @throw DnsParserConstructor
         * @throw std::bad_alloc
         * @throw std::invalid_argument
         */
        explicit DnsParser(Config& cfg, unsigned process_id, Mempool<DnsRecord>& record_mempool,
                           Mempool<DnsTcpConnection>& tcp_mempool, Statistics& stats);

        ~DnsParser() = default;

        /**
         * @brief Get empty DnsRecord from mempool
         * @return Empty DnsRecord from mempool
         */
        DnsRecord& get_empty();

        /**
         * @brief Fill DnsRecord structure from given packet
         * @param packet Packet to parse
         * @throw DnsParseException From calling DNS parsing methods
         * @return DnsRecord structure filled with information from parsed packet
         */
        std::vector<DnsRecord*> parse_packet(const Packet& packet);

        /**
         * @brief Free given DnsRecord structure back to mempool
         * @param record DnsRecord to free
         */
        void put_back_record(DnsRecord& record);

        /**
         * @brief Free given DnsRecord structures back to mempool
         * @param records Vector of DnsRecords to free
         */
        void put_back_records(std::vector<DnsRecord*>& records);

        /**
         * @brief Merge information from 2 DnsRecord structures containing request and response into 1
         * @param request Structure to merge into
         * @param response Structure to merge from
         * @return Merged DnsRecord structure
         */
        DnsRecord& merge_records(DnsRecord& request, DnsRecord& response);

        /**
         * @brief Merge information concerning AXFR question from 2 DnsRecord structures into 1
         * @param request Structure to merge into
         * @param response Structure to merge from
         */
        void merge_AXFR_record(DnsRecord& request, DnsRecord& response);

        /**
         * @brief Copy part of DNS message into buffer
         * @param msg Pointer to start of part of DNS message
         * @param size Size of this part of DNS message
         * @param offset Where to copy this part of DNS message in buffer
         * @throw DnsParseException
         * @return Pointer to start of buffer containing given DNS message
         */
        uint8_t* copy_to_buffer(const uint8_t* msg, uint16_t size, std::size_t offset);

        /**
         * @brief Parse packet's L2 header
         * @param pkt Pointer to the start of unparsed part of packet
         * @param record DnsRecord to fill with packet's information
         * @throw DnsParseException
         * @return Pointer to the next unparsed part of packet
         */
        MemView<uint8_t> parse_l2(const MemView<uint8_t>& pkt, DnsRecord& record);

        /**
         * @brief Parse packet's L3 header
         * @param pkt Pointer to the start of unparsed part of packet
         * @param record DnsRecord to fill with packet's information
         * @throw DnsParseException
         * @return Pointer to the next unparsed part of packet
         */
        MemView<uint8_t> parse_l3(const MemView<uint8_t>& pkt, DnsRecord& record);

        /**
         * @brief Parse packet's IPv4 header
         * @param pkt Pointer to the start of unparsed part of packet
         * @param record DnsRecord to fill with packet's information
         * @throw DnsParseException
         * @return Pointer to the next unparsed part of packet
         */
        MemView<uint8_t> parse_ipv4(const MemView<uint8_t>& pkt, DnsRecord& record);

        /**
         * @brief Parse packet's IPv6 header
         * @param pkt Pointer to the start of unparsed part of packet
         * @param record DnsRecord to fill with packet's information
         * @throw DnsParseException
         * @return Pointer to the next unparsed part of packet
         */
        MemView<uint8_t> parse_ipv6(const MemView<uint8_t>& pkt, DnsRecord& record);

        /**
         * @brief Parse packet's UDP header
         * @param pkt Pointer to the start of unparsed part of packet
         * @param record DnsRecord to fill with packet's information
         * @throw DnsParseException
         * @return Pointer to the next unparsed part of packet
         */
        MemView<uint8_t> parse_l4_udp(const MemView<uint8_t>& pkt, DnsRecord& record);

        /**
         * @brief Parse packet's TCP header
         * @param pkt Pointer to the start of unparsed part of packet
         * @param record DnsRecord to fill with packet's information
         * @param records Vector of DnsRecords with filled packet information (TCP can export multiple
         * packets from reorder buffer at once)
         * @throw DnsParseException
         * @return TRUE if there are new records to export, FALSE otherwise
         */
        bool parse_l4_tcp(const MemView<uint8_t>& pkt, DnsRecord& record, std::vector<DnsRecord*>& records);

        /**
         * @brief Parse packet's DNS header and DNS data
         * @param pkt Pointer to the start of unparsed part of packet
         * @param record DnsRecord to fill with packet's information
         * @throw DnsParseException
         * @return Pointer to the next unparsed part of packet
         */
        void parse_dns(MemView<uint8_t> pkt, DnsRecord& record);

        /**
         * @brief Perform timeout of old connections from the table of active TCP connections
         */
        void tcp_table_timetout() {
            m_tcp_table.timeout([this](DnsTcpConnection& conn) {
                conn.clear_buffers();
                this->m_tcp_mempool.free(conn);
            });
        }

        /**
         * @brief Update dynamic configuration
         * @param cfg New dynamic configuration
         */
        void update_configuration(Config& cfg) {
            m_export_invalid = cfg.pcap_export.value() == PcapExportCfg::INVALID;
            m_dns_port = cfg.dns_port;
            m_pcap_inv.update_configuration(cfg);
            m_tcp_table.set_timeout(cfg.tcp_ct_timeout);
        }

        /**
         * @brief If exporting invalid packets to PCAP is set try to write given packet to PCAP
         * @param pkt Invalid packet to write to PCAP
         */
        void export_invalid(const Packet& pkt) {
            try {
                if (m_export_invalid)
                    m_stats.exported_to_pcap += m_pcap_inv.write(&pkt);
            }
            catch (std::exception& e) {
                Logger("PCAP").debug() << "Couldn't write invalid packet to PCAP file";
            }
        }

        /**
         * @brief Rotate output PCAP for invalid packets if its enabled
         */
        void rotate_invalid() {
            if (m_export_invalid)
                m_pcap_inv.rotate_output();
        }

        /**
         * @brief Check if exporting invalid packets is enabled
         */
        bool is_export_invalid() { return m_export_invalid; }

    private:
        Mempool<DnsRecord>& m_record_mempool;
        Mempool<DnsTcpConnection>& m_tcp_mempool;
        DynamicMempool m_edns_mempool;
        TransactionTable<DnsTcpConnection> m_tcp_table;
        std::unique_ptr<uint8_t, std::function<void(void*)>> m_msg_buffer;
        bool m_raw_pcap;
        bool m_export_invalid;
        PcapWriter m_pcap_inv;
        const Packet* m_processed_packet;
        uint16_t m_dns_port;
        Statistics& m_stats;

        /**
         * @brief Parse DNS header and fill DNS record fields
         * @param pkt Pointer to start of DNS header
         * @param record DNS record to fill
         * @throw DnsParseException
         */
        void parse_dns_header(const MemView<uint8_t>& pkt, DnsRecord& record);

        /**
         * @brief Parse first question in DNS payload question section
         * @param question Pointer to start of question
         * @param record DNS record to fill
         * @throw DnsParseException
         * @return Pointer to the next unparsed part of packet
         */
        MemView<uint8_t> parse_dns_question(const MemView<uint8_t>& question, DnsRecord& record);

        /**
         * @brief Try to find OPT RR in DNS payload with EDNS information and parse it
         * @param pkt Pointer into DNS payload where to start to search
         * @param record DNS record to fill
         * @throw DnsParseException
         */
        void parse_edns(const MemView<uint8_t>& pkt, DnsRecord& record);

        /**
         * @brief Parse one Resource Record and if it's OPT RR with EDNS information fill DNS record
         * @param ptr Pointer into DNS payload where to start parsing
         * @param pkt_end Pointer to the firt byte after the end of packet data
         * @param record DNS record to fill
         * @param section Type of the DNS payload section being parsed
         * @throw DnsParseException From calling parse_edns_options()
         * @return Pointer to the end of the parsed section, nullptr on failure
         */
        const uint8_t* parse_rr(const uint8_t* ptr, const uint8_t* pkt_end, DnsRecord& record, DNSSectionType section);
    };
}


