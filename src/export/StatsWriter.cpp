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

#include <iostream>
#include <fstream>
#include <sys/stat.h>

#include "core/Statistics.h"
#include "utils/Time.h"
#include "StatsWriter.h"

int64_t DDP::StatsWriter::write(AggregatedStatistics item)
{
    m_filename = filename();
    auto fields = m_cfg.stats_fields.value();
    Time timestamp = Time(Time::Clock::REALTIME);
    std::ofstream output(m_filename + ".part");
    bool comma = false;

    output << "{";

    if (fields[static_cast<uint32_t>(StatsField::PROCESSED_PACKETS)]) {
        if (comma) { output << ","; } else { comma = true; }
        output << "\"processed-packets\":" << std::to_string(item.packets);
    }

    if (fields[static_cast<uint32_t>(StatsField::PROCESSED_TRANSACTIONS)]) {
        if (comma) { output << ","; } else { comma = true; }
        output << "\"processed-transactions\":" << std::to_string(item.transactions);
    }

    if (fields[static_cast<uint32_t>(StatsField::EXPORTED_RECORDS)]) {
        if (comma) { output << ","; } else { comma = true; }
        output << "\"exported-records\":" << std::to_string(item.exported_records);
    }

    if (fields[static_cast<uint32_t>(StatsField::PENDING_TRANSACTIONS)]) {
        if (comma) { output << ","; } else { comma = true; }
        output << "\"pending-transactions\":" << std::to_string(item.active_tt_records);
    }

    if (fields[static_cast<uint32_t>(StatsField::EXPORTED_PCAP_PACKETS)]) {
        if (comma) { output << ","; } else { comma = true; }
        output << "\"exported-pcap-packets\":" << std::to_string(item.exported_to_pcap);
    }

    if (m_cfg.export_stats.value() == ExportStats::DETAILED &&
        (m_cfg.ipv4_indices.size() > 0 || m_cfg.ipv6_indices.size() > 0)) {
        for (auto& i: m_cfg.ipv4_indices) {
            char buff[INET_ADDRSTRLEN + 4];
            auto* ret = inet_ntop(AF_INET, &i.first, buff, INET_ADDRSTRLEN + 4);
            if (!ret)
                continue;
            auto cb = [&output, buff](){ output << "\"[" << buff << "]"; };
            write_queries_stats(output, comma, cb, item.queries[i.second], item.qps[i.second]);
        }

        for (auto& i: m_cfg.ipv6_indices) {
            char buff[INET6_ADDRSTRLEN + 4];
            auto* ret = inet_ntop(AF_INET6, &i.first, buff, INET6_ADDRSTRLEN + 4);
            if (!ret)
                continue;
            auto cb = [&output, buff](){ output << "\"[" << buff << "]"; };
            write_queries_stats(output, comma, cb, item.queries[i.second], item.qps[i.second]);
        }
    }

    auto cb = [&output](){ output << "\""; };
    write_queries_stats(output, comma, cb, item.queries[0], item.qps[0]);

    if (fields[static_cast<uint32_t>(StatsField::UNIX_TIMESTAMP)]) {
        if (comma) { output << ","; } else { comma = true; }
        output << "\"unix-timestamp\":" << std::to_string(timestamp.getMicros());
    }

    output << "}";

    int64_t res = output.tellp();
    output.close();

    chmod((m_filename + ".part").c_str(), 0666);
    if (m_cfg.stats_location.value() == ExportLocation::LOCAL) {
        if (std::rename((m_filename + ".part").c_str(), m_filename.c_str()))
            throw std::runtime_error("Couldn't rename the output statistics file!");
    }
    else {
        check_file_transfer(TlsCtxIndex::STATISTICS);
        m_threads.emplace_back(std::async(std::launch::async, send_file, TlsCtxIndex::STATISTICS,
            m_cfg.stats_ip.value(), m_cfg.stats_port.value(), m_filename, ".part", DEFAULT_TRIES));
    }

    return res < 0 ? 0 : res;
}

std::string DDP::StatsWriter::filename()
{
    char time[30];
    timespec timestamp;
    tm tmp_tm;

    clock_gettime(CLOCK_REALTIME, &timestamp);
    gmtime_r(&timestamp.tv_sec, &tmp_tm);
    auto pos = strftime(time, 20, "%Y%m%d.%H%M%S.", &tmp_tm);
    std::snprintf(time + pos, sizeof(time) - pos, "%06lu", timestamp.tv_nsec / 1000);

    return m_cfg.stats_directory.value() + "/" + m_cfg.file_prefix.value() + std::string(time)
        + ".stats.json";
}

void DDP::StatsWriter::write_queries_stats(std::ofstream& output, bool& comma, std::function<void()> cb,
    Statistics::QueryStatsArray& queries, Statistics::QueryStatsArray& qps)
{
    auto fields = m_cfg.stats_fields.value();

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_IPV4)]) {
        if (comma) { output << ","; } else { comma = true; }
        cb();
        output << "queries-ipv4\":" << std::to_string(queries[Statistics::Q_IPV4]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_IPV6)]) {
        if (comma) { output << ","; } else { comma = true; }
        cb();
        output << "queries-ipv6\":" << std::to_string(queries[Statistics::Q_IPV6]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_TCP)]) {
        if (comma) { output << ","; } else { comma = true; }
        cb();
        output << "queries-tcp\":" << std::to_string(queries[Statistics::Q_TCP]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_UDP)]) {
        if (comma) { output << ","; } else { comma = true; }
        cb();
        output << "queries-udp\":" << std::to_string(queries[Statistics::Q_UDP]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_DOT)]) {
        if (comma) { output << ","; } else { comma = true; }
        cb();
        output << "queries-dot\":" << std::to_string(queries[Statistics::Q_DOT]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_DOH)]) {
        if (comma) { output << ","; } else { comma = true; }
        cb();
        output << "queries-doh\":" << std::to_string(queries[Statistics::Q_DOH]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES)]) {
        if (comma) { output << ","; } else { comma = true; }
        cb();
        output << "queries\":" << std::to_string(queries[Statistics::Q_IPV4] + queries[Statistics::Q_IPV6]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_PER_SECOND_IPV4)]) {
        if (comma) { output << ","; } else { comma = true; }
        cb();
        output << "queries-per-second-ipv4\":" << std::to_string(qps[Statistics::Q_IPV4]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_PER_SECOND_IPV6)]) {
        if (comma) { output << ","; } else { comma = true; }
        cb();
        output << "queries-per-second-ipv6\":" << std::to_string(qps[Statistics::Q_IPV6]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_PER_SECOND_TCP)]) {
        if (comma) { output << ","; } else { comma = true; }
        cb();
        output << "queries-per-second-tcp\":" << std::to_string(qps[Statistics::Q_TCP]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_PER_SECOND_UDP)]) {
        if (comma) { output << ","; } else { comma = true; }
        cb();
        output << "queries-per-second-udp\":" << std::to_string(qps[Statistics::Q_UDP]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_PER_SECOND_DOT)]) {
        if (comma) { output << ","; } else { comma = true; }
        cb();
        output << "queries-per-second-dot\":" << std::to_string(qps[Statistics::Q_DOT]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_PER_SECOND_DOH)]) {
        if (comma) { output << ","; } else { comma = true; }
        cb();
        output << "queries-per-second-doh\":" << std::to_string(qps[Statistics::Q_DOH]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_PER_SECOND)]) {
        if (comma) { output << ","; } else { comma = true; }
        cb();
        output << "queries-per-second\":" << std::to_string(qps[Statistics::Q_IPV4] + qps[Statistics::Q_IPV6]);
    }
}
