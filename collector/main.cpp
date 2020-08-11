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

#include <iostream>
#include <string>
#include <csignal>
#include <atomic>
#include <getopt.h>

#include "collector.h"

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
    std::cout << "dp-collector -s SERVER_CERTIFICATE -k SERVER_PRIVATE_KEY [-a IP_ADDRESS] [-p PORT] [-h]" << std::endl;
    std::cout << std::endl << "Options:" << std::endl;
    std::cout << "\t-s SERVER_CERTIFICATE   : Collector's certificate for establishing TLS connection." << std::endl;
    std::cout << "\t-k SERVER_PRIVATE_KEY   : Collector's private key for TLS connection encryption." << std::endl;
    std::cout << "\t-a IP_ADDRESS           : Bind collector to specific IP address." << std::endl;
    std::cout << "\t-p PORT                 : Collector's transport protocol port (default 6378)." << std::endl;
}

int main(int argc, char** argv)
{
    // Set up signal handlers
    struct sigaction sig = {};
    sig.sa_handler = &signal_handler;
    sigfillset(&sig.sa_mask);
    sigaction(SIGINT, &sig, nullptr);
    sigaction(SIGTERM, &sig, nullptr);

    std::string srv_cert;
    std::string srv_key;
    std::string ip;
    uint16_t port = 6378;

    bool is_cert, is_key;
    int opt;

    while ((opt = getopt(argc, argv, "hs:k:a:p:")) != EOF) {

        switch (opt) {
            case 'h':
                print_help();
                exit(EXIT_SUCCESS);
                break;

            case 's':
                srv_cert = std::string(optarg);
                is_cert = true;
                break;

            case 'k':
                srv_key = std::string(optarg);
                is_key = true;
                break;

            case 'a':
                ip = std::string(optarg);
                break;

            case 'p':
                port = std::atoi(optarg);
                break;

            default:
                std::cerr << "Invalid arguments!" << std::endl;
                print_help();
                exit(EXIT_FAILURE);
        }
    }

    if (!is_cert) {
        std::cerr << "Missing collector's certificate!" << std::endl;
        print_help();
        exit(EXIT_FAILURE);
    }

    if (!is_key) {
        std::cerr << "Missing collector's private key!" << std::endl;
        print_help();
        exit(EXIT_FAILURE);
    }

    try {
        DDP::Collector collector(srv_cert, srv_key, ip, port);
        collector.run();
    }
    catch (const std::exception& e) {
        std::cerr << "Server failed: " << e.what() << std::endl;
    }

    return 0;
}
