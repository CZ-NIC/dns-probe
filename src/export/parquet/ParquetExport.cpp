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

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arrow/api.h>
#include <arrow/io/api.h>
#include <parquet/arrow/reader.h>
#include <parquet/arrow/writer.h>
#include <parquet/exception.h>

#include "ParquetExport.h"

constexpr char DDP::ParquetExport::DIGITS[];

DDP::ParquetExport::ParquetExport(Config& cfg)
                                  : BaseExport(cfg.anonymize_ip.value()), m_records_limit(cfg.parquet_records.value())
{
    m_DnsSchema = arrow::schema({arrow::field("id", arrow::int32()),
                                arrow::field("unixtime", arrow::int64()),
                                arrow::field("time", arrow::int64()),
                                arrow::field("qname", arrow::utf8()),
                                arrow::field("domainname", arrow::utf8()),
                                arrow::field("len", arrow::int32()),
                                arrow::field("frag", arrow::int32()),
                                arrow::field("ttl", arrow::int32()),
                                arrow::field("ipv", arrow::int32()),
                                arrow::field("prot", arrow::int32()),
                                arrow::field("src", arrow::utf8()),
                                arrow::field("srcp", arrow::int32()),
                                arrow::field("dst", arrow::utf8()),
                                arrow::field("dstp", arrow::int32()),
                                arrow::field("udp_sum", arrow::int32()),
                                arrow::field("dns_len", arrow::int32()),

                                arrow::field("aa", arrow::boolean()),
                                arrow::field("tc", arrow::boolean()),
                                arrow::field("rd", arrow::boolean()),
                                arrow::field("ra", arrow::boolean()),
                                arrow::field("z", arrow::boolean()),
                                arrow::field("ad", arrow::boolean()),
                                arrow::field("cd", arrow::boolean()),

                                arrow::field("ancount", arrow::int32()),
                                arrow::field("arcount", arrow::int32()),
                                arrow::field("nscount", arrow::int32()),
                                arrow::field("qdcount", arrow::int32()),
                                arrow::field("opcode", arrow::int32()),
                                arrow::field("rcode", arrow::int32()),
                                arrow::field("qtype", arrow::int32()),
                                arrow::field("qclass", arrow::int32()),
                                arrow::field("country", arrow::utf8()),
                                arrow::field("asn", arrow::utf8()),

                                arrow::field("edns_udp", arrow::int32()),
                                arrow::field("edns_version", arrow::int32()),
                                arrow::field("edns_do", arrow::boolean()),
                                arrow::field("edns_ping", arrow::boolean()),
                                arrow::field("edns_nsid", arrow::utf8()),
                                arrow::field("edns_dnssec_dau", arrow::utf8()),
                                arrow::field("edns_dnssec_dhu", arrow::utf8()),
                                arrow::field("edns_dnssec_n3u", arrow::utf8()),
                                arrow::field("edns_client_subnet", arrow::utf8()),
                                arrow::field("edns_other", arrow::utf8()),
                                arrow::field("edns_client_subnet_asn", arrow::utf8()),
                                arrow::field("edns_client_subnet_country", arrow::utf8()),

                                arrow::field("labels", arrow::int32()),
                                arrow::field("res_len", arrow::int32()),
                                arrow::field("time_micro", arrow::int64()),
                                arrow::field("resp_frag", arrow::int32()),
                                arrow::field("proc_time", arrow::int32()),

                                arrow::field("is_google", arrow::boolean()),
                                arrow::field("is_opendns", arrow::boolean()),

                                arrow::field("dns_res_len", arrow::int32()),
                                arrow::field("server_location", arrow::utf8()),
                                arrow::field("tcp_hs_rtt", arrow::int64())
    });
}

boost::any DDP::ParquetExport::buffer_record(DDP::DnsRecord& record)
{
    // Parse EDNS record first to drop the DNS record if EDNS record is invalid
    std::unordered_map<uint16_t, boost::any> req_edns_map, resp_edns_map;
    if (record.m_req_ednsRdata != nullptr)
        req_edns_map = parse_edns_options(record.m_req_ednsRdata, record.m_req_ednsRdata_size);

    if (record.m_resp_ednsRdata != nullptr)
        resp_edns_map = parse_edns_options(record.m_resp_ednsRdata, record.m_resp_ednsRdata_size);

    // DNS ID
    PARQUET_THROW_NOT_OK(ID.Append(record.m_id));

    // Seconds part of timestamp
    PARQUET_THROW_NOT_OK(UnixTime.Append(record.m_timestamp.getSeconds()));

    // Timestamp (microseconds precision)
    PARQUET_THROW_NOT_OK(Time.Append(record.m_timestamp.getMicros()));

    // Qname and Domain Name (part of Qname)
    char* domain_name = nullptr;
    uint8_t labels = 0;
    int size = record.domain_name(&domain_name, &labels);
    if (labels > 0)
        PARQUET_THROW_NOT_OK(Qname.Append(record.m_qname + 1, strlen(record.m_qname) - 1));
    else
        PARQUET_THROW_NOT_OK(Qname.Append(record.m_qname, strlen(record.m_qname)));

    PARQUET_THROW_NOT_OK(Domainname.Append(domain_name, size));

    // Request packet length
    PARQUET_THROW_NOT_OK(Len.Append(record.m_len));

    // Fragmentation (Always empty)
    PARQUET_THROW_NOT_OK(Frag.Append(0));

    // TTL
    PARQUET_THROW_NOT_OK(TTL.Append(record.m_ttl));

    // IP version
    if (record.m_addr_family == DDP::DnsRecord::AddrFamily::IP4) {
        PARQUET_THROW_NOT_OK(IPv.Append(4));
    }
    else {
        PARQUET_THROW_NOT_OK(IPv.Append(6));
    }

    // Transport layer protocol
    PARQUET_THROW_NOT_OK(Prot.Append(static_cast<int32_t>(record.m_proto)));

    // Source IP address
    int buf_len = record.m_addr_family == DDP::DnsRecord::AddrFamily::IP4 ? INET_ADDRSTRLEN + 4 : INET6_ADDRSTRLEN + 4;
    char addrBuf[buf_len];
    in6_addr* addr = record.client_address();
    int ipv = record.m_addr_family == DDP::DnsRecord::AddrFamily::IP4 ? AF_INET : AF_INET6;

#ifdef PROBE_CRYPTOPANT
    if (m_anonymize_ip) {
        if (ipv == AF_INET)
            *reinterpret_cast<uint32_t*>(addr) = scramble_ip4(*reinterpret_cast<uint32_t*>(addr), 0);
        else
            scramble_ip6(addr, 0);
    }
#endif

    inet_ntop(ipv, addr, addrBuf, sizeof(addrBuf));
    PARQUET_THROW_NOT_OK(Src.Append(addrBuf, strlen(addrBuf)));

    // Source port
    PARQUET_THROW_NOT_OK(SrcPort.Append(record.client_port()));

    // Destination IP address
    in6_addr* srv_addr = record.server_address();
    inet_ntop(ipv, srv_addr, addrBuf, sizeof(addrBuf));
    PARQUET_THROW_NOT_OK(Dst.Append(addrBuf, strlen(addrBuf)));

    // Destination port
    PARQUET_THROW_NOT_OK(DstPort.Append(record.server_port()));

    // UDP checksum
    PARQUET_THROW_NOT_OK(UDPSum.Append(record.m_udp_sum));

    // Request DNS payload length
    PARQUET_THROW_NOT_OK(DNSLen.Append(record.m_dns_len));

    // DNS header AA bit
    PARQUET_THROW_NOT_OK(AA.Append(record.m_aa));

    // DNS header TC bit
    PARQUET_THROW_NOT_OK(TC.Append(record.m_tc));

    // DNS header RD bit
    PARQUET_THROW_NOT_OK(RD.Append(record.m_rd));

    // DNS header RA bit
    PARQUET_THROW_NOT_OK(RA.Append(record.m_ra));

    // DNS header Z bit
    PARQUET_THROW_NOT_OK(Z.Append(record.m_z));

    // EDNS AD bit
    PARQUET_THROW_NOT_OK(AD.Append(record.m_ad));

    // EDNS CD bit
    PARQUET_THROW_NOT_OK(CD.Append(record.m_cd));

    // DNS header AnCount
    PARQUET_THROW_NOT_OK(AnCount.Append(record.m_ancount));

    // DNS header ArCount
    PARQUET_THROW_NOT_OK(ArCount.Append(record.m_arcount));

    // DNS header NsCount
    PARQUET_THROW_NOT_OK(NsCount.Append(record.m_nscount));

    // DNS header QdCount
    PARQUET_THROW_NOT_OK(QdCount.Append(record.m_qdcount));

    // DNS header OpCode
    PARQUET_THROW_NOT_OK(OpCode.Append(record.m_opcode));

    // DNS header RCode
    PARQUET_THROW_NOT_OK(RCode.Append(record.m_rcode));

    // DNS QType
    PARQUET_THROW_NOT_OK(QType.Append(record.m_qtype));

    // DNS QClass
    PARQUET_THROW_NOT_OK(QClass.Append(record.m_qclass));

    // Country
    PARQUET_THROW_NOT_OK(Country.Append(""));

    // ASN
    PARQUET_THROW_NOT_OK(ASN.Append(""));

    // EDNS UDP payload
    PARQUET_THROW_NOT_OK(EdnsUDP.Append(record.m_ednsUDP));

    // EDNS Version
    PARQUET_THROW_NOT_OK(EdnsVersion.Append(record.m_ednsVersion));

    // EDNS DO bit
    PARQUET_THROW_NOT_OK(EdnsDO.Append(record.m_ednsDO));

    // EDNS Ping bit
    PARQUET_THROW_NOT_OK(EdnsPing.Append(false));

    // EDNS options
    if (record.m_req_ednsRdata != nullptr) {
        // EDNS DNSSEC DAU
        auto find_dau = req_edns_map.find(static_cast<uint16_t>(EDNSOptions::DNSSEC_DAU));
        if (find_dau != req_edns_map.end()) {
            PARQUET_THROW_NOT_OK(EdnsDnssecDau.Append(boost::any_cast<std::string>(req_edns_map[static_cast<uint16_t>(EDNSOptions::DNSSEC_DAU)])));
        }
        else {
            PARQUET_THROW_NOT_OK(EdnsDnssecDau.Append(""));
        }

        // EDNS DNSSEC DHU
        auto find_dhu = req_edns_map.find(static_cast<uint16_t>(EDNSOptions::DNSSEC_DHU));
        if (find_dhu != req_edns_map.end()) {
            PARQUET_THROW_NOT_OK(EdnsDnssecDhu.Append(boost::any_cast<std::string>(req_edns_map[static_cast<uint16_t>(EDNSOptions::DNSSEC_DHU)])));
        }
        else {
            PARQUET_THROW_NOT_OK(EdnsDnssecDhu.Append(""));
        }

        // EDNS DNSSEC N3U
        auto find_n3u = req_edns_map.find(static_cast<uint16_t>(EDNSOptions::DNSSEC_N3U));
        if (find_n3u != req_edns_map.end()) {
            PARQUET_THROW_NOT_OK(EdnsDnssecN3u.Append(boost::any_cast<std::string>(req_edns_map[static_cast<uint16_t>(EDNSOptions::DNSSEC_N3U)])));
        }
        else {
            PARQUET_THROW_NOT_OK(EdnsDnssecN3u.Append(""));
        }
    }
    else {
        // EDNS DNSSEC DAU
        PARQUET_THROW_NOT_OK(EdnsDnssecDau.Append(""));

        // EDNS DNSSEC DHU
        PARQUET_THROW_NOT_OK(EdnsDnssecDhu.Append(""));

        // EDNS DNSSEC N3U
        PARQUET_THROW_NOT_OK(EdnsDnssecN3u.Append(""));
    }

    if (record.m_resp_ednsRdata != nullptr) {
        // EDNS NSID
        auto find = resp_edns_map.find(static_cast<uint16_t>(EDNSOptions::NSID));
        if (find != resp_edns_map.end()) {
            PARQUET_THROW_NOT_OK(EdnsNSID.Append(boost::any_cast<std::string>(resp_edns_map[static_cast<uint16_t>(EDNSOptions::NSID)])));
        }
        else {
            PARQUET_THROW_NOT_OK(EdnsNSID.Append(""));
        }
    }
    else {
        // EDNS NSID
        PARQUET_THROW_NOT_OK(EdnsNSID.Append(""));
    }

    // EDNS client subnet
    PARQUET_THROW_NOT_OK(EdnsClientSubnet.Append(""));

    // EDNS other
    PARQUET_THROW_NOT_OK(EdnsOther.Append(""));

    // EDNS client subnet ASN
    PARQUET_THROW_NOT_OK(EdnsClientSubnetAsn.Append(""));

    // EDNS client subnet country
    PARQUET_THROW_NOT_OK(EdnsClientSubnetCountry.Append(""));

    // Labels
    PARQUET_THROW_NOT_OK(Labels.Append(labels));

    // Response packet length
    PARQUET_THROW_NOT_OK(ResLen.Append(record.m_res_len));

    // Microseconds part of timestamp
    PARQUET_THROW_NOT_OK(TimeMicro.Append(record.m_timestamp.getMicroseconds()));

    // Response fragmentation (always empty)
    PARQUET_THROW_NOT_OK(RespFrag.Append(0));

    // Processor time spent to process this DNS record?
    PARQUET_THROW_NOT_OK(ProcTime.Append(0));

    // Is query to Google DNS servers
    PARQUET_THROW_NOT_OK(IsGoogle.Append(false));

    // Is query to OpenDNS servers
    PARQUET_THROW_NOT_OK(IsOpenDNS.Append(false));

    // Response DNS payload length
    PARQUET_THROW_NOT_OK(DNSResLen.Append(record.m_res_dns_len));

    // Server location
    PARQUET_THROW_NOT_OK(ServerLocation.Append(""));

    // TCP RTT (microseconds precision)
    PARQUET_THROW_NOT_OK(TcpHsRtt.Append(record.m_tcp_rtt));

    if (ID.length() >= static_cast<int64_t>(m_records_limit)) {
        return write_table();
    }

    return nullptr;
}

std::shared_ptr<arrow::Table> DDP::ParquetExport::write_table()
{
    if (ID.length() == 0)
        return nullptr;

    std::vector<std::shared_ptr<arrow::Array>> arrays(COLUMNS);
    int i = 0;

    // DNS ID
    PARQUET_THROW_NOT_OK(ID.Finish(&arrays[i++]));

    // Seconds part of timestamp
    PARQUET_THROW_NOT_OK(UnixTime.Finish(&arrays[i++]));

    // Timestamp (microseconds precision)
    PARQUET_THROW_NOT_OK(Time.Finish(&arrays[i++]));

    // Qname
    PARQUET_THROW_NOT_OK(Qname.Finish(&arrays[i++]));

    // Domain Name (part of Qname)
    PARQUET_THROW_NOT_OK(Domainname.Finish(&arrays[i++]));

    // Request packet length
    PARQUET_THROW_NOT_OK(Len.Finish(&arrays[i++]));

    // Fragmentation
    PARQUET_THROW_NOT_OK(Frag.Finish(&arrays[i++]));

    // TTL
    PARQUET_THROW_NOT_OK(TTL.Finish(&arrays[i++]));

    // IP version
    PARQUET_THROW_NOT_OK(IPv.Finish(&arrays[i++]));

    // Transport layer protocol
    PARQUET_THROW_NOT_OK(Prot.Finish(&arrays[i++]));

    // Source IP address
    PARQUET_THROW_NOT_OK(Src.Finish(&arrays[i++]));

    // Source port
    PARQUET_THROW_NOT_OK(SrcPort.Finish(&arrays[i++]));

    // Destination IP address
    PARQUET_THROW_NOT_OK(Dst.Finish(&arrays[i++]));

    // Destination port
    PARQUET_THROW_NOT_OK(DstPort.Finish(&arrays[i++]));

    // UDP checksum
    PARQUET_THROW_NOT_OK(UDPSum.Finish(&arrays[i++]));

    // Request DNS payload length
    PARQUET_THROW_NOT_OK(DNSLen.Finish(&arrays[i++]));

    // DNS header AA bit
    PARQUET_THROW_NOT_OK(AA.Finish(&arrays[i++]));

    // DNS header TC bit
    PARQUET_THROW_NOT_OK(TC.Finish(&arrays[i++]));

    // DNS header RD bit
    PARQUET_THROW_NOT_OK(RD.Finish(&arrays[i++]));

    // DNS header RA bit
    PARQUET_THROW_NOT_OK(RA.Finish(&arrays[i++]));

    // DNS header Z bit
    PARQUET_THROW_NOT_OK(Z.Finish(&arrays[i++]));

    // EDNS AD bit
    PARQUET_THROW_NOT_OK(AD.Finish(&arrays[i++]));

    // EDNS CD bit
    PARQUET_THROW_NOT_OK(CD.Finish(&arrays[i++]));

    // DNS header AnCount
    PARQUET_THROW_NOT_OK(AnCount.Finish(&arrays[i++]));

    // DNS header ArCount
    PARQUET_THROW_NOT_OK(ArCount.Finish(&arrays[i++]));

    // DNS header NsCount
    PARQUET_THROW_NOT_OK(NsCount.Finish(&arrays[i++]));

    // DNS header QdCount
    PARQUET_THROW_NOT_OK(QdCount.Finish(&arrays[i++]));

    // DNS header OpCode
    PARQUET_THROW_NOT_OK(OpCode.Finish(&arrays[i++]));

    // DNS header RCode
    PARQUET_THROW_NOT_OK(RCode.Finish(&arrays[i++]));

    // DNS QType
    PARQUET_THROW_NOT_OK(QType.Finish(&arrays[i++]));

    // DNS QClass
    PARQUET_THROW_NOT_OK(QClass.Finish(&arrays[i++]));

    // Country
    PARQUET_THROW_NOT_OK(Country.Finish(&arrays[i++]));

    // ASN
    PARQUET_THROW_NOT_OK(ASN.Finish(&arrays[i++]));

    // EDNS UDP payload
    PARQUET_THROW_NOT_OK(EdnsUDP.Finish(&arrays[i++]));

    // EDNS Version
    PARQUET_THROW_NOT_OK(EdnsVersion.Finish(&arrays[i++]));

    // EDNS DO bit
    PARQUET_THROW_NOT_OK(EdnsDO.Finish(&arrays[i++]));

    // EDNS Ping bit
    PARQUET_THROW_NOT_OK(EdnsPing.Finish(&arrays[i++]));

    // EDNS NSID
    PARQUET_THROW_NOT_OK(EdnsNSID.Finish(&arrays[i++]));

    // EDNS DNSSEC DAU
    PARQUET_THROW_NOT_OK(EdnsDnssecDau.Finish(&arrays[i++]));

    // EDNS DNSSEC DHU
    PARQUET_THROW_NOT_OK(EdnsDnssecDhu.Finish(&arrays[i++]));

    // EDNS DNSSEC N3U
    PARQUET_THROW_NOT_OK(EdnsDnssecN3u.Finish(&arrays[i++]));

    // EDNS client subnet
    PARQUET_THROW_NOT_OK(EdnsClientSubnet.Finish(&arrays[i++]));

    // EDNS other
    PARQUET_THROW_NOT_OK(EdnsOther.Finish(&arrays[i++]));

    // EDNS client subnet ASN
    PARQUET_THROW_NOT_OK(EdnsClientSubnetAsn.Finish(&arrays[i++]));

    // EDNS client subnet country
    PARQUET_THROW_NOT_OK(EdnsClientSubnetCountry.Finish(&arrays[i++]));

    // Labels
    PARQUET_THROW_NOT_OK(Labels.Finish(&arrays[i++]));

    // Response packet length
    PARQUET_THROW_NOT_OK(ResLen.Finish(&arrays[i++]));

    // Microseconds part of timestamp
    PARQUET_THROW_NOT_OK(TimeMicro.Finish(&arrays[i++]));

    // Response fragmentation
    PARQUET_THROW_NOT_OK(RespFrag.Finish(&arrays[i++]));

    // Processor time spent to process this DNS record?
    PARQUET_THROW_NOT_OK(ProcTime.Finish(&arrays[i++]));

    // Is query to Google DNS servers
    PARQUET_THROW_NOT_OK(IsGoogle.Finish(&arrays[i++]));

    // Is query to OpenDNS servers
    PARQUET_THROW_NOT_OK(IsOpenDNS.Finish(&arrays[i++]));

    // Response DNS payload length
    PARQUET_THROW_NOT_OK(DNSResLen.Finish(&arrays[i++]));

    // Server location
    PARQUET_THROW_NOT_OK(ServerLocation.Finish(&arrays[i++]));

    // TCP RTT (microseconds precision)
    PARQUET_THROW_NOT_OK(TcpHsRtt.Finish(&arrays[i++]));

    // Create Arrow table
    std::shared_ptr<arrow::Table> table = arrow::Table::Make(m_DnsSchema, arrays);

    return table;
}

void DDP::ParquetExport::write_leftovers(ParquetWriter& writer, Statistics& stats)
{
    if (ID.length() == 0)
        return;

    std::shared_ptr<arrow::Table> table = write_table();
    writer.write(table);
    stats.exported_records += table->num_rows();
}

std::unordered_map<uint16_t, boost::any> DDP::ParquetExport::parse_edns_options(const uint8_t* ptr, uint16_t size)
{
    std::unordered_map<uint16_t, boost::any> ret;
    uint16_t parsed = 0;

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
                    break;

                default:
                    break;
            }
        }

        parsed += opt_len;
        ptr += opt_len;
    }

    return ret;
}

std::string DDP::ParquetExport::parse_dnssec_list(const uint8_t* ptr, uint16_t opt_len)
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

char* DDP::ParquetExport::format_int(uint8_t value, char* buffer)
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
