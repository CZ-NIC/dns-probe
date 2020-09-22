#!/usr/bin/env python3

import os
import sys
import argparse
import itertools
import tempfile
import subprocess
import pathlib
import pandas as pd

vals = [
    "id",
    #"unixtime",
    #"time",
    "qname",
    "domainname",
    "len",
    "frag",
    "ttl",
    "ipv",
    "prot",
    "src",
    "srcp",
    "dst",
    "dstp",
    "udp_sum",
    "dns_len",
    "aa",
    "tc",
    "rd",
    "ra",
    "z",
    "ad",
    "cd",
    "ancount",
    "arcount",
    "nscount",
    "qdcount",
    "opcode",
    "rcode",
    "qtype",
    "qclass",
    "country",
    "asn",
    "edns_udp",
    "edns_version",
    "edns_do",
    "edns_ping",
    "edns_nsid",
    "edns_dnssec_dau",
    "edns_dnssec_dhu",
    "edns_dnssec_n3u",
    "edns_client_subnet",
    "edns_other",
    "edns_client_subnet_asn",
    "edns_client_subnet_country",
    "labels",
    "res_len",
    #"time_micro",
    "resp_frag",
    "proc_time",
    "is_google",
    "is_opendns",
    "dns_res_len",
    "server_location",
    #"tcp_hs_rtt"
]

def cmp_parquet(parquet, cmd, verbose):
    print("-----------------------------------------------------------")
    print("*** Testing " + parquet + " ***")
    proc = subprocess.Popen(cmd, shell=True)

    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.wait()
        pass
    except:
        proc.kill()
        proc.wait()
        raise

    if len(os.listdir(os.getcwd())) == 0:
        print("Error: No parquet generated")
        print("xxx Fail")
        return 1

    for file in os.listdir(os.getcwd()):
        if file.endswith(".pcap"):
            os.remove(file)
            continue

        p2p = pd.read_parquet("../test_parquets/" + parquet)
        p2p = p2p.drop(['unixtime', 'time', 'time_micro'], axis=1)

        ddp = pd.read_parquet(file)
        ddp = ddp.drop(['unixtime', 'time', 'time_micro'], axis=1)

        result = True
        if len(ddp.index) != len(p2p.index):
            if verbose:
                print("Parquets differ in number of DNS records")
                print("DDP records: " + str(len(ddp.index)))
                print("Correct records: " + str(len(p2p.index)))
                print("")
            result = False

        for ((ddp_i, ddp_row), (p2p_i, p2p_row)) in zip(ddp.iterrows(), p2p.iterrows()):
            for col in vals:
                if not ddp_row[col] == p2p_row[col]:
                    if pd.isna(ddp_row[col]) and pd.isna(p2p_row[col]):
                        continue

                    if verbose:
                        print("Row " + str(ddp_i) + " column " + col + " differs")
                        print("DDP: " + str(ddp_row[col]))
                        print("Correct: " + str(p2p_row[col]))
                        print("")
                    result = False

        os.remove(file)

        if result:
            print("!!! Success")
            return 0
        else:
            print("xxx Fail")
            return 1

def main():
    retval = 0
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--path", help="path to dns-probe binary in build directory", required=True)
    parser.add_argument("-v", "--verbose", action="store_true", default=False, dest="verbose_switch",
                        help="enables more verbose output for failed tests")
    args = parser.parse_args()

    orig_path = os.getcwd()

    if args.path:
        ddp_path = args.path
        if not ddp_path.startswith("/"):
            ddp_path = orig_path  + "/" + ddp_path
    
    test_path = pathlib.Path(sys.argv[0]).parent.absolute()
    cmd_base = ddp_path + " -p " + str(test_path) + "/test_pcaps/"
    tmpdir = str(test_path) + "/test_tmp"

    try:
        os.mkdir(tmpdir)
        os.chdir(tmpdir)
    except:
        os.rmdir(tmpdir)
        pass
    
    # Run default configuration tests
    for (parquet, pcap) in zip(sorted(os.listdir("../test_parquets/base")), sorted(os.listdir("../test_pcaps"))):
        retval = cmp_parquet("base/" + parquet, cmd_base + pcap, args.verbose_switch) or retval

    cfgfile = " -c ../config/config.yml"

    # Run tests for IP anonymization
    for (parquet, pcap) in zip(sorted(os.listdir("../test_parquets/anonymized")), sorted(os.listdir("../test_pcaps"))):
        retval = cmp_parquet("anonymized/" + parquet, cmd_base + pcap + cfgfile + " -n anon", args.verbose_switch) or retval

    # Run test for IP allow-list
    retval = cmp_parquet("ip_filtered/edns_dnssec_nsid_allow.parquet", cmd_base + "edns_dnssec_nsid.pcap"
        + cfgfile + " -n ip_allow", args.verbose_switch) or retval

    # Run test for IP deny-list
    retval = cmp_parquet("ip_filtered/edns_dnssec_nsid_deny.parquet", cmd_base + "edns_dnssec_nsid.pcap"
        + cfgfile + " -n ip_deny", args.verbose_switch) or retval

    for file in os.listdir(os.getcwd()):
        os.remove(file)
    
    os.chdir(orig_path)
    os.rmdir(tmpdir)
    return retval

if __name__ == "__main__":
    sys.exit(main())
