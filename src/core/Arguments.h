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
#include <list>

namespace DDP {
    /**
     * @brief Structure for unified program arguments
     */
    struct Arguments
    {
        bool exit; //!< Signals that application should exit
        const char* app = "app"; //<! Contains name of currently running application (usually argv[0])
        std::list<std::string> interfaces; //<! List of interfaces used for listening for incoming DNS data
        std::list<std::string> pcaps; //<! List of PCAPs with data for processing
        bool raw_pcap;
    };
}