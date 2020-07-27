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
#include <pcap.h>

#include "BaseWriter.h"
#include "platform/Packet.h"

namespace DDP {

    /**
     * @brief Class for writing packets to output PCAPs
     */
    class PcapWriter : public BaseWriter {
        constexpr static int PCAP_PACKET_HEADER_LENGTH = 16;
    public:
        /**
         * @brief Constructor
         * @param cfg Configuration of the output
         * @param invalid Indicates if incoming packets for export are invalid
         * @param process_id Process identifier, used in generation of PCAP file's name
         */
        explicit PcapWriter(Config& cfg, bool invalid, uint32_t process_id) :
                BaseWriter(cfg, process_id),
                m_invalid(invalid),
                m_out(nullptr),
                m_exported_bytes(0) {}

        ~PcapWriter() { close_file(); };

        /**
         * @brief Write given packet to RAW PCAP file
         * @param item Structure with packet to export
         * @throw std::exception From calling create_file() during file rotation
         * @return Number of packets written to file
         */
        int64_t write(boost::any item) override {
            if (item.type() != typeid(const Packet*))
                return 0;

            return write(boost::any_cast<const Packet*>(item));
        }

        /**
         * @brief Write given packet to RAW PCAP file
         * @param item Structure with packet to export
         * @throw std::exception From calling create_file() during file rotation
         * @return Number of packets written to file
         */
        int64_t write(const Packet* item);

        /**
         * @brief Close current output and open a new one
         */
        void rotate_output() override {
            if (m_out) {
                close_file();
                create_file();
            }
        }

    private:
        /**
         * @brief Create new PCAP file for RAW packet export
         * @throw std::exception When new file couldn't be created
         */
        void create_file();

        /**
         * @brief Close current PCAP export file
         */
        void close_file();

        bool m_invalid;
        pcap_dumper_t* m_out;
        uint64_t m_exported_bytes;
    };
}
