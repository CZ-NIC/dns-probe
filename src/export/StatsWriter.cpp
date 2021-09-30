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

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_IPV4)]) {
        if (comma) { output << ","; } else { comma = true; }
        output << "\"queries-ipv4\":" << std::to_string(item.queries[Statistics::Q_IPV4]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_IPV6)]) {
        if (comma) { output << ","; } else { comma = true; }
        output << "\"queries-ipv6\":" << std::to_string(item.queries[Statistics::Q_IPV6]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_TCP)]) {
        if (comma) { output << ","; } else { comma = true; }
        output << "\"queries-tcp\":" << std::to_string(item.queries[Statistics::Q_TCP]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_UDP)]) {
        if (comma) { output << ","; } else { comma = true; }
        output << "\"queries-udp\":" << std::to_string(item.queries[Statistics::Q_UDP]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES)]) {
        if (comma) { output << ","; } else { comma = true; }
        output << "\"queries\":" << std::to_string(item.queries[Statistics::Q_IPV4] + item.queries[Statistics::Q_IPV6]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_PER_SECOND_IPV4)]) {
        if (comma) { output << ","; } else { comma = true; }
        output << "\"queries-per-second-ipv4\":" << std::to_string(item.qps[Statistics::Q_IPV4]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_PER_SECOND_IPV6)]) {
        if (comma) { output << ","; } else { comma = true; }
        output << "\"queries-per-second-ipv6\":" << std::to_string(item.qps[Statistics::Q_IPV6]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_PER_SECOND_TCP)]) {
        if (comma) { output << ","; } else { comma = true; }
        output << "\"queries-per-second-tcp\":" << std::to_string(item.qps[Statistics::Q_TCP]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_PER_SECOND_UDP)]) {
        if (comma) { output << ","; } else { comma = true; }
        output << "\"queries-per-second-udp\":" << std::to_string(item.qps[Statistics::Q_UDP]);
    }

    if (fields[static_cast<uint32_t>(StatsField::QUERIES_PER_SECOND)]) {
        if (comma) { output << ","; } else { comma = true; }
        output << "\"queries-per-second\":" << std::to_string(item.qps[Statistics::Q_IPV4] + item.qps[Statistics::Q_IPV6]);
    }

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
