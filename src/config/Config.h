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


#include <string>
#include <unordered_map>
#include <forward_list>
#include <functional>

#include "ConfigTypes.h"
#include "ConfigItem.h"

namespace DDP {
    /**
     * Structure containing configuration of the application
     */
    struct Config
    {
        ConfigItem<ThreadManager::MaskType> coremask; //!< Coremask used fo selecting cores where application will be running.
        ConfigItem<uint16_t> dns_port; //!< TCP/UDP port used for identifying DNS traffic

        ConfigItem<uint32_t> tt_size; //!< Number of items in the transaction table
        ConfigItem<uint64_t> tt_timeout; //!< Timeout for orphaned items transaction table in milliseconds
        ConfigItem<bool> match_qname; //!< Enable matching qnames in transaction table

        ConfigItem<uint32_t> tcp_ct_size; //!< Maximal concurrent tracking TCP connections
        ConfigItem<uint64_t> tcp_ct_timeout; //!< Timeout of TCP connection

        ConfigItem<std::string> file_prefix; //!< Exported file prefix name
        ConfigItem<uint32_t> file_rot_timeout; //!< Exported file rotation timeout in seconds
        ConfigItem<uint64_t> file_rot_size; //!< Exported file size limit in MB
        ConfigItem<PcapExportCfg> pcap_export; //!< Define what will be in exported PCAPs
        ConfigItem<bool> raw_pcap; //!< Defines if input PCAP file is without ethernet headers

        ConfigItem<ExportFormat> export_format; //!< Specify export format
        ConfigItem<uint64_t> parquet_records; //!< Number of records in parquet file
        ConfigBitfield<23> cdns_fields; //!< Fields which will be part of CDNS file
        ConfigItem<uint64_t> cdns_records_per_block; //!< Number of records in one block in CDNS file
        ConfigItem<uint64_t> cdns_blocks_per_file; //!< Number of blocks in CDNS file
    };
}
