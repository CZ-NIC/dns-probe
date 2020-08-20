/*
 *  Copyright (C) 2020 CZ.NIC, z.s.p.o.
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

#ifndef PROBE_COLLECTOR_CONFIG
#define PROBE_COLLECTOR_CONFIG ""
#endif

#include <iostream>
#include <fstream>
#include <algorithm>
#include <string>
#include <csignal>
#include <atomic>
#include <getopt.h>

#include "Collector.h"

std::atomic<bool> run_flag(true); //!< Flag for stopping collector's and all connections' processing loops

/**
 * @brief Signal handler sets flag to stop all processing loops on all running threads
 * @param signum
 */
static void signal_handler(int signum)
{
    std::cout << "Exiting on signal " << std::to_string(signum) << std::endl;
    run_flag.store(false);
}

static void print_help()
{
    std::cout << "dp-collector [-s SERVER_CERTIFICATE -k SERVER_PRIVATE_KEY] [-a IP_ADDRESS] [-p PORT] [-c CONFIG_FILE] [-h]" << std::endl;
    std::cout << std::endl << "Options:" << std::endl;
    std::cout << "\t-s SERVER_CERTIFICATE   : Collector's certificate for establishing TLS connection." << std::endl;
    std::cout << "\t-k SERVER_PRIVATE_KEY   : Collector's private key for TLS connection encryption." << std::endl;
    std::cout << "\t-a IP_ADDRESS           : Bind collector to specific IP address." << std::endl;
    std::cout << "\t-p PORT                 : Collector's transport protocol port (default 6378)." << std::endl;
    std::cout << "\t-c CONFIG_FILE          : Configuration file with all the parameters specified." << std::endl;
}

static DDP::CConfig parse_config_file(const char* file)
{
    DDP::CConfig cfg;

    std::ifstream ifs(file, std::ifstream::binary);
    if (ifs.fail())
        return cfg;

    for (std::string line; std::getline(ifs, line); ) {
        if (line[0] == '#')
            continue;

        auto pos = line.find("=");
        std::string item = line.substr(0, pos);
        std::string value = line.substr(pos + 1, line.size() - pos - 1);

        item.erase(std::remove_if(item.begin(), item.end(), ::isspace), item.end());
        std::transform(item.begin(), item.end(), item.begin(), toupper);

        value.erase(std::remove_if(value.begin(), value.end(), ::isspace), value.end());

        if (item == "SERVER_CERTIFICATE")
            cfg.cert = value;
        else if (item == "SERVER_PRIVATE_KEY")
            cfg.key = value;
        else if (item == "IP_ADDRESS")
            cfg.ip = value;
        else if (item == "PORT")
            cfg.port = std::atoi(value.c_str());
    }

    return cfg;
}

int main(int argc, char** argv)
{
    // Set up signal handlers
    struct sigaction sig = {};
    sig.sa_handler = &signal_handler;
    sigfillset(&sig.sa_mask);
    sigaction(SIGINT, &sig, nullptr);
    sigaction(SIGTERM, &sig, nullptr);
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    DDP::CConfig cfg = parse_config_file(PROBE_COLLECTOR_CONFIG);
    int opt;

    while ((opt = getopt(argc, argv, "hs:k:a:p:c:")) != EOF) {

        switch (opt) {
            case 'h':
                print_help();
                exit(EXIT_SUCCESS);
                break;

            case 's':
                cfg.cert = std::string(optarg);
                break;

            case 'k':
                cfg.key = std::string(optarg);
                break;

            case 'a':
                cfg.ip = std::string(optarg);
                break;

            case 'p':
                cfg.port = std::atoi(optarg);
                break;

            case 'c':
                cfg = parse_config_file(optarg);
                break;

            default:
                std::cerr << "Invalid arguments!" << std::endl;
                print_help();
                exit(EXIT_FAILURE);
        }
    }

    if (cfg.cert.empty()) {
        std::cerr << "Missing collector's certificate!" << std::endl;
        print_help();
        exit(EXIT_FAILURE);
    }

    if (cfg.key.empty()) {
        std::cerr << "Missing collector's private key!" << std::endl;
        print_help();
        exit(EXIT_FAILURE);
    }

    try {
        DDP::Collector collector(cfg);
        collector.run();
    }
    catch (const std::exception& e) {
        std::cerr << "Server failed: " << e.what() << std::endl;
    }

    return 0;
}
