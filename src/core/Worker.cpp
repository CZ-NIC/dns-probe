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

#include "Worker.h"
#include "utils/Poll.h"

int DDP::Worker::run()
{
    try {
        for(unsigned i = 0; i < m_ports.size(); i++) {
            m_poll.emplace<PortPollAble>(*this, i);
        }

        for (unsigned j = 0; j < m_sockets.size(); j++) {
            m_poll.emplace<SocketPollAble>(*this, j);
        }

        for (unsigned k = 0; k < m_knots.size(); k++) {
            m_poll.emplace<KnotPollAble>(*this, k);
        }

        m_poll.loop();
    }
    catch (std::exception& e) {
        Logger("Worker").error() << "Worker on core " << m_process_id << " crashed. Cause: " << e.what();
        m_comm_link.send(Message(Message::Type::STOP));
        return -1;
    }

    return 0;
}

DDP::WorkerRetCode DDP::Worker::process_packet(const Packet& pkt)
{
    DDP::WorkerRetCode ret = DDP::WorkerRetCode::WORKER_OK;

    // Export expired records in transaction table after TT_TIMEOUT_COUNT processed packets
    m_tt_timeout_count++;
    if (m_tt_timeout_count >= TT_TIMEOUT_COUNT) {
        try {
            m_transaction_table.timeout([this](DnsRecord& rec){this->m_parser.put_back_record(rec);});
            m_parser.tcp_table_timetout();
        }
        catch (std::exception& e) {
            Logger("TT").debug() << "Timeout failed: " << e.what();
        }
        m_tt_timeout_count = 0;
    }

    // If enabled in configuration, export packet to PCAP
    try {
        if (m_cfg.pcap_export.value() == PcapExportCfg::ALL && pkt.type() == PacketType::WIRE)
            m_stats.exported_to_pcap += m_pcap_all.write(&pkt);
    }
    catch (std::exception& e) {
        Logger("PCAP").warning() << "Couldn't write packet to PCAP file: " << e.what();
    }

    // Parse packet into DNS record.
    // If unable to parse packet and if enabled in configuration,
    // export packet to invalid packets PCAP file
    std::vector<DnsRecord*> records;
    try {
        records = m_parser.parse_packet(pkt);
    }
    catch (std::exception& e) {
        Logger("Parse error").debug() << e.what();
        if (!records.empty())
            m_parser.put_back_records(records);

        m_parser.export_invalid(pkt);

        return DDP::WorkerRetCode::WORKER_PARSE_ERROR;
    }

    // Match DNS record in transaction table
    // If successful, merge query-response into one DNS record and try to export it
    for (auto& record: records) {
        try {
            if(record->m_request) {
                update_stats(record);
            }

            auto gate = m_transaction_table[*record];

            if (gate.empty()) {
                m_transaction_table.insert_hint(gate, *record);
            }
            else {
                if (record->m_request == (*gate).m_request || (record->m_response == (*gate).m_response &&
                    !(record->m_qtype == DNS_QTYPE_AXFR && (*gate).m_qtype == DNS_QTYPE_AXFR))) {
                    m_transaction_table.insert(*record);
                    continue;
                }
                // gate == REQ && gate != RESP -> merge
                // gate == REQ && gate == RESP -> cumulate
                // gate != REQ && gate == RESP ->
                                        // new == REQ -> merge
                                        // new == RESP -> cumulate
                DnsRecord* to_export = nullptr;
                if ((*gate).m_qtype == DnsParser::DNS_QTYPE_AXFR ||
                        record->m_qtype == DnsParser::DNS_QTYPE_AXFR ||
                        ((*gate).m_response && record->m_response)) {
                    if ((*gate).m_request) {
                        if ((*gate).m_response) {
                            m_parser.merge_AXFR_record(*gate, *record);
                            to_export = gate.operator->();
                        }
                        else {
                            to_export = &m_parser.merge_records(*gate, *record);
                        }

                        if (!record->m_last_soa) {
                            m_parser.put_back_record(*record);
                            m_transaction_table.update_item(gate);
                            continue;
                        }
                    }
                    else {
                        if (record->m_request) {
                            to_export = &m_parser.merge_records(*record, *gate);

                            if (!record->m_last_soa) {
                                m_parser.put_back_record(*gate);
                                gate.set_entry(record);
                                m_transaction_table.update_item(gate);
                                continue;
                            }
                        }
                        else if (record->m_response) {
                            m_parser.merge_AXFR_record(*gate, *record);
                            m_parser.put_back_record(*record);
                            m_transaction_table.update_item(gate);
                            continue;
                        }
                    }
                }
                else {
                    if (gate->m_response) {
                        to_export = &m_parser.merge_records(*record, *gate);
                    }
                    else {
                        to_export = &m_parser.merge_records(*gate, *record);
                    }
                }

                try {
                    auto block = m_exporter->buffer_record(*to_export);
                    if (!block.empty()) {
#ifdef PROBE_PARQUET
                        if (block.type() == typeid(std::shared_ptr<arrow::Table>) &&
                            boost::any_cast<std::shared_ptr<arrow::Table>>(block) != nullptr) {
                            enqueue(block);
                        }
#endif
#ifdef PROBE_CDNS
                        if (block.type() == typeid(std::shared_ptr<CDNS::CdnsBlock>) &&
                                 boost::any_cast<std::shared_ptr<CDNS::CdnsBlock>>(block) != nullptr) {
                            enqueue(block);
                        }
#endif
                    }
                }
#ifdef PROBE_PARQUET
                catch(EdnsParseException& e) {
                    Logger("Parse error").debug() << e.what();
                    m_parser.export_invalid(pkt);
                }
#endif
                catch(std::exception& e) {
                    Logger("Export").warning() << "Buffering new DNS record failed: " << e.what();
                }

                DnsRecord* tmp = gate.operator->();
                m_transaction_table.erase(gate);
                m_parser.put_back_record(*tmp);
                m_parser.put_back_record(*record);
                m_stats.transactions++;
            }
        }
        catch (std::exception& e) {
            Logger("Match").debug() << "Record matching or export failed: " << e.what();
            m_parser.put_back_record(*record);
            ret = DDP::WorkerRetCode::WORKER_EXPORT_ERROR;
        }
    }

    return ret;
}

DDP::WorkerRetCode DDP::Worker::process_knot_datagram(const Packet& dgram)
{
    DDP::WorkerRetCode ret = DDP::WorkerRetCode::WORKER_OK;

    // Parse datagram into DNS record.
    std::vector<DnsRecord*> records;
    try {
        records = m_parser.parse_packet(dgram);
    }
    catch (std::exception& e) {
        Logger("Parse error").debug() << e.what();
        if (!records.empty())
            m_parser.put_back_records(records);

        return DDP::WorkerRetCode::WORKER_PARSE_ERROR;
    }

    for (auto& record: records) {
        if(record->m_request) {
            update_stats(record);
        }

        try {
            auto block = m_exporter->buffer_record(*record);
            if (!block.empty()) {
#ifdef PROBE_PARQUET
                if (block.type() == typeid(std::shared_ptr<arrow::Table>) &&
                    boost::any_cast<std::shared_ptr<arrow::Table>>(block) != nullptr) {
                    enqueue(block);
                }
#endif
#ifdef PROBE_CDNS
                if (block.type() == typeid(std::shared_ptr<CDNS::CdnsBlock>) &&
                            boost::any_cast<std::shared_ptr<CDNS::CdnsBlock>>(block) != nullptr) {
                    enqueue(block);
                }
#endif
            }
        }
#ifdef PROBE_PARQUET
        catch(EdnsParseException& e) {
            Logger("Parse error").debug() << e.what();
        }
#endif
        catch (std::exception& e) {
            Logger("Export").warning() << "Buffering new DNS record failed: " << e.what();
        }

        m_parser.put_back_record(*record);
        m_stats.transactions++;
    }

    return ret;
}

void DDP::Worker::new_config(Config& cfg)
{
    m_cfg = cfg;
    m_transaction_table.set_timeout(cfg.tt_timeout);
    m_parser.update_configuration(cfg);
    m_exporter->update_configuration(cfg);
    m_writer->update_configuration(cfg);
    m_pcap_all.update_configuration(cfg);
}

void DDP::Worker::rotate_output()
{
    try {
        // Send currently buffered DNS records to exporter core
        auto block = m_exporter->rotate_export();
        if (!block.empty()) {
#ifdef PROBE_PARQUET
            if (block.type() == typeid(std::shared_ptr<arrow::Table>) &&
                boost::any_cast<std::shared_ptr<arrow::Table>>(block) != nullptr) {
                enqueue(block);
            }
#endif
#ifdef PROBE_CDNS
            if (block.type() == typeid(std::shared_ptr<CDNS::CdnsBlock>) &&
                     boost::any_cast<std::shared_ptr<CDNS::CdnsBlock>>(block) != nullptr) {
                enqueue(block);
            }
#endif
        }

        // Send mark to exporter core
        enqueue(m_output_rotation_counter++);

        // Rotate PCAPs with all or invalid packets if enabled
        if (m_cfg.pcap_export.value() == PcapExportCfg::ALL)
            m_pcap_all.rotate_output();

        m_parser.rotate_invalid();

        // Rotate leftovers writer in case there are unsent files from previous probe process
        m_writer->rotate_output();
    }
    catch(std::exception& e) {
        Logger("Export").warning() << "Output rotation on worker " << m_process_id << "failed: " << e.what();
    }
}

void DDP::Worker::stop()
{
    tt_cleanup();
    Process::stop();
}

void DDP::Worker::close_port(int pos)
{
    m_ports.erase(m_ports.begin() + pos);
    if(m_ports.empty() && m_sockets.empty() && m_knots.empty()) {
        m_comm_link.send(MessageWorkerStopped(ThreadManager::current_lcore()));
        tt_cleanup();
        m_poll.disable();
    }
}

void DDP::Worker::update_stats(DnsRecord* record)
{
    bool detailed = false;
    IPv4_prefix_t ipv4 = {reinterpret_cast<const uint32_t*>(record->server_address())[0], UINT32_MAX};
    IPv6_prefix_t ipv6 = {*record->server_address(), {{ .__u6_addr32 = {UINT32_MAX,UINT32_MAX,UINT32_MAX,UINT32_MAX}}}};

    if(record->m_addr_family == DnsRecord::AddrFamily::IP4) {
        if (is_detailed_stats_ipv4()) {
            detailed = true;
            m_stats.queries_ipv4[ipv4][Statistics::Q_IPV4]++;
        }
        m_stats.queries[Statistics::Q_IPV4]++;

        // Retrieved client address is in network byte order so we can mask by 0xFF
        // to get highest byte of IPv4 address.
        auto first_byte = reinterpret_cast<const uint32_t*>(record->client_address())[0] & 0xFF;
        m_stats.ipv4_src_entropy_cnts[first_byte]++;
    }
    else if(record->m_addr_family == DnsRecord::AddrFamily::IP6) {
        if (is_detailed_stats_ipv6()) {
            detailed = true;
            m_stats.queries_ipv6[ipv6][Statistics::Q_IPV6]++;
        }
        m_stats.queries[Statistics::Q_IPV6]++;
    }

    auto type = 0u;

    if(record->m_proto == DnsRecord::Proto::TCP) {
        if (record->server_port() == DnsParser::DOT_PORT) {
            type = Statistics::Q_DOT;
        }
        else if (record->server_port() == DnsParser::DOH_PORT) {
            type = Statistics::Q_DOH;
        }
        else {
            type = Statistics::Q_TCP;
        }
    }
    else if(record->m_proto == DnsRecord::Proto::UDP) {
        type = Statistics::Q_UDP;
    }
    else {
        return;
    }

    if (detailed) {
        if (record->m_addr_family == DnsRecord::AddrFamily::IP4)
            m_stats.queries_ipv4[ipv4][type]++;
        else if (record->m_addr_family == DnsRecord::AddrFamily::IP6)
            m_stats.queries_ipv6[ipv6][type]++;
    }
    m_stats.queries[type]++;
}

void DDP::Worker::PortPollAble::ready_read() {
    uint16_t rx_count = 0;
    std::array<Packet, Port::BATCH_SIZE> pkts;
    // Read batch of packets from port
    try {
        rx_count = m_port.read(pkts.data(), m_queue);
    } catch(PortEOF& e) {
        m_worker.close_port(m_port_pos);
        poll()->unregister(*this);
        return;
    }

    if (rx_count == 0)
        return;

    // Process batch of packets
    for (size_t k = 0; k < rx_count; k++) {
        m_worker.process_packet(pkts[k]);
    }

    m_worker.m_stats.packets += rx_count;
    m_worker.m_stats.active_tt_records = m_worker.m_transaction_table.records();
    m_port.free_packets(m_queue);
}

void DDP::Worker::SocketPollAble::ready_read()
{
    auto conn = m_port.read(nullptr, m_queue);
    if (conn == 0)
        return;

#ifdef PROBE_DNSTAP
    try {
        m_worker.m_poll.emplace<DnstapPollAble>(m_worker, conn);
    }
    catch (std::exception& e) {
        Logger("Socket").warning() << e.what();
    }
#endif
}

#ifdef PROBE_DNSTAP
void DDP::Worker::DnstapPollAble::ready_read()
{
    uint16_t rx_count = 0;
    Packet pkt;
    try {
        rx_count = m_reader.read(&pkt);
    }
    catch (PortEOF& e) {
        poll()->unregister(*this);
        return;
    }

    if (rx_count == 0)
        return;

    m_worker.process_packet(pkt);
    m_worker.m_stats.packets += rx_count;
    m_worker.m_stats.active_tt_records = m_worker.m_transaction_table.records();
}
#endif

void DDP::Worker::KnotPollAble::ready_read() {
    uint16_t rx_count = 0;
    std::array<Packet, Port::BATCH_SIZE> pkts;
    // Read batch of packets from port
    try {
        rx_count = m_port.read(pkts.data(), 0);
    } catch(PortEOF& e) {
        m_worker.close_port(m_port_pos);
        poll()->unregister(*this);
        return;
    }

    if (rx_count == 0)
        return;

    // Process batch of packets
    for (size_t k = 0; k < rx_count; k++) {
        m_worker.process_knot_datagram(pkts[k]);
    }

    m_worker.m_stats.packets += rx_count;
    m_worker.m_stats.active_tt_records = m_worker.m_transaction_table.records();
}