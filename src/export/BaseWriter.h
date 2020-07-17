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

#pragma once

#include <string>
#include <cstdint>
#include <sys/stat.h>
#include <sys/types.h>

#include "config/Config.h"

namespace DDP {
    /**
     * @brief Abstract class serving as interface for output writing classes
     */
    class BaseWriter {
        public:
        /**
         * @brief Construct a new BaseWriter object
         * @param cfg Configuration of the output
         * @param process_id Process ID used for generating names of the output files
         * @param sufix Sufix of the generated names for export files
         */
        explicit BaseWriter(Config& cfg, uint32_t process_id, std::string sufix = "") :
            m_cfg(cfg),
            m_id("_p" + std::to_string(process_id)),
            m_sufix(sufix),
            m_filename_counter(0),
            m_filename() {}

        virtual ~BaseWriter() {};

        /**
         * @brief Write given item with buffered DNS records to output
         * @param item Item with DNS records ready for export to output
         * @return Number of DNS records written to output
         */
        virtual int64_t write(boost::any item) = 0;

        /**
         * @brief Close current output and open a new one
         */
        virtual void rotate_output() = 0;

        /**
         * @brief Update configuration of the output
         * @param cfg New configuration of the output
         */
        void update_configuration(Config& cfg) {
            m_cfg = cfg;
        }

        /**
         * @brief Generate filename for given parameters
         * @param sufix Filename sufix after the last dot
         * @param invalid TRUE only for PCAP files with invalid packets
         * @return Newly generated filename
         */
        std::string filename(std::string sufix, bool invalid) {
            std::string inv;
            char time[20];
            timespec timestamp;
            tm tmp_tm;

            clock_gettime(CLOCK_REALTIME, &timestamp);
            gmtime_r(&timestamp.tv_sec, &tmp_tm);
            strftime(time, 20, "%Y%m%d-%H%M%S", &tmp_tm);

            if (invalid) {
                inv = "_inv";
            }
            std::string counter = "_" + std::to_string(m_filename_counter);
            std::string full_sufix = sufix.empty() ? "" : ("." + sufix);
            std::string filename = m_cfg.target_directory.value() + "/" + m_cfg.file_prefix.value() +
                                   std::string(time) + m_id + inv + counter + full_sufix;

            struct stat buffer;
            if (stat((filename + m_sufix).c_str(), &buffer) == 0) {
                return m_cfg.target_directory.value() + "/" + m_cfg.file_prefix.value() + std::string(time) +
                    m_id + inv + "_" + std::to_string(++m_filename_counter) + full_sufix;
            } else {
                if (m_filename_counter == 0) {
                    return filename;
                }
                else {
                    m_filename_counter = 0;
                    return m_cfg.target_directory.value() + "/" + m_cfg.file_prefix.value() +
                        std::string(time) + m_id + inv + "_" + std::to_string(m_filename_counter) + full_sufix;
                }
            }
        }

        protected:
        Config m_cfg;
        std::string m_id;
        std::string m_sufix;
        uint8_t m_filename_counter;
        std::string m_filename;
    };
}