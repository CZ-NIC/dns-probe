.. _yang-module:

***********
YANG module
***********

This section contains the complete YANG module *cznic-dns-probe* that is used for DNS Probe. It is also included in the project repository (`data-model/cznic-dns-probe.yang <https://gitlab.nic.cz/adam/dns-probe/blob/master/data-model/cznic-dns-probe.yang>`_) and packages.

::

  module cznic-dns-probe {

    yang-version 1.1;

    namespace "https://www.nic.cz/ns/yang/dns-probe";

    prefix dp;

    import ietf-yang-types {
      prefix yang;
    }

    import ietf-inet-types {
      prefix inet;
    }

    organization
      "CZ.NIC, z. s. p. o.";

    contact
      "Editor: Ladislav Lhotka
               <mailto:lhotka@nic.cz>

       Editor: Jan Dražil
               <mailto:idrazil@fit.vutbr.cz>

       Editor: Pavel Doležal
               <mailto:pavel.dolezal@nic.cz>";

    description
      "This YANG module defines the data model for the DNS probe.

       DNS Probe is a software tool that extracts DNS queries and
       responses from network traffic (both UDP and TCP) and exports
       records about DNS transactions in C-DNS or Apache Parquet
       format.";

    revision 2020-08-19 {
      description
        "Add 'response_delay' bit to exported C-DNS fields";
    }

    revision 2020-08-17 {
      description
        "Add probe's command line parameters as Sysrepo configuration items.";
    }

    revision 2020-07-15 {
      description
        "Add IP anonymization";
    }

    revision 2020-07-09 {
      description
        "Add IP and port filtering";
    }

    revision 2020-06-09 {
      description
        "Initial revision.";
    }

    /* Data nodes */

    container dns-probe {
      description
        "Configuration of DNS Probe.";
      leaf-list interface-list {
        type string;
        description
          "List of network interfaces to process traffic from in addition to
           interfaces passed with '-i' command line parameter.

           This is a static configuration parameter that is applied
           only upon restarting the probe.";
      }
      leaf-list pcap-list {
        type string;
        description
          "List of PCAPs to process in addition to PCAPs passed with
           '-p' command line parameter.

           This is a static configuration parameter that is applied
           only upon restarting the probe.";
      }
      leaf raw-pcap {
        type boolean;
        default "false";
        description
          "Indicates RAW PCAPs as input in 'pcap-list' or from command line
           with '-p' parameter. Might get overriden by '-r' command line
           parameter.

           MUST be set to 'false' if 'interface-list' or '-i' command line
           parameter are used.

           This is a static configuration parameter that is applied
           only upon restarting the probe.";
      }
      leaf log-file {
        type string;
        description
          "Path (including filename) to log file for storing logs.
           Might get overriden by '-l' command line parameter.

           By default logs are written to stdout.

           This is a static configuration parameter that is applied
           only upon restarting the probe.";
      }
      leaf coremask {
        type uint64 {
          range "7..max";
        }
        default "0x7";
        description
          "This parameter is used for selecting CPU cores where the
           application will be running.

           This is a static configuration parameter that is applied
           only upon restarting the probe.";
      }
      leaf-list ipv4-allowlist {
        type inet:ipv4-address-no-zone;
        description
          "List of allowed IPv4 addresses to process traffic from.
           By default all IPv4 addresses are allowed.";
      }
      leaf-list ipv4-denylist {
        type inet:ipv4-address-no-zone;
        description
          "List of IPv4 addresses from which to NOT process traffic.
           By default all IPv4 addresses are allowed.";
      }
      leaf-list ipv6-allowlist {
        type inet:ipv6-address-no-zone;
        description
          "List of allowed IPv6 addresses to process traffic from.
           By default all IPv6 addresses are allowed.";
      }
      leaf-list ipv6-denylist {
        type inet:ipv6-address-no-zone;
        description
          "List of IPv6 addresses from which to NOT process traffic.
           By default all IPv6 addresses are allowed.";
      }
      leaf-list dns-ports {
        type uint16;
        default "53";
        description
          "List of ports used for identifying DNS traffic.";
      }
      container export {
        description
          "Configuration of exported data.";
        leaf export-dir {
          type string;
          default ".";
          description
            "Directory for exported data.";
        }
        leaf export-format {
          type enumeration {
            enum cdns {
              description
                "Export data in C-DNS format";
              reference
                "RFC 8618: Compacted-DNS (C-DNS): A Format for DNS
                 Packet Capture";
            }
            enum parquet {
              description
                "Export data in Apache Parquet format";
              reference
                "https://parquet.apache.org/";
            }
          }
          default "parquet";
          description
            "Format for exported data.

             This is a static configuration parameter that is applied
             only upon restarting the probe.";
        }
        leaf cdns-fields {
          type bits {
            bit transaction_id;
            bit time_offset;
            bit query_name;
            bit client_hoplimit;
            bit qr_transport_flags;
            bit client_address;
            bit client_port;
            bit server_address;
            bit server_port;
            bit query_size;
            bit qr_dns_flags;
            bit query_ancount;
            bit query_arcount;
            bit query_nscount;
            bit query_qdcount;
            bit query_opcode;
            bit response_rcode;
            bit query_classtype;
            bit query_edns_version;
            bit query_edns_udp_size;
            bit query_opt_rdata;
            bit response_additional_sections;
            bit response_size;
            bit response_delay; // TCP RTT
          }
          default "transaction_id time_offset query_name "
                + "client_hoplimit qr_transport_flags client_address "
                + "client_port server_address server_port query_size "
                + "qr_dns_flags query_ancount query_arcount "
                + "query_nscount query_qdcount query_opcode "
                + "response_rcode query_classtype query_edns_version "
                + "query_edns_udp_size query_opt_rdata "
                + "response_additional_sections response_size response_delay";
          description
            "This bit set indicates which fields from the C-DNS
             standard schema are included in exported data.

             This is a static configuration parameter that is applied
             only upon restarting the probe.";
          reference
            "RFC 8618: Compacted-DNS (C-DNS): A Format for DNS Packet
             Capture";
        }
        leaf cdns-records-per-block {
          type uint64;
          default "10000";
          description
            "Maximum number of DNS records in one exported C-DNS block.

             This is a static configuration parameter that is applied
             only upon restarting the probe.";
        }
        leaf cdns-blocks-per-file {
          type uint64;
          default "0";
          description
            "Maximum number of C-DNS blocks in one exported C-DNS file.

             If this limit is reached, the export file is rotated. The
             value of 0 (default) means no block count-based
             rotation.";
        }
        leaf parquet-records-per-file {
          type uint64;
          default "5000000";
          description
            "Number of Parquet records per file.";
        }
        leaf file-name-prefix {
          type string;
          default "dns_";
          description
            "Common prefix of export file names.";
        }
        leaf timeout {
          type uint32;
          units "seconds";
          default "0";
          description
            "Time interval after which the export file is rotated.

             The value of 0 (default) means no time-based rotation.";
        }
        leaf file-size-limit {
          type uint64;
          units "bytes";
          default "0";
          description
            "Size limit for the export file.

             If the limit is exceeded, the export file is rotated. The
             value of 0 (default) means no size-based rotation.";
        }
        leaf file-compression {
          type boolean;
          default "true";
          description
            "If this flag is true, the exported Parquet or C-DNS files
             will be compressed using GZIP.

             C-DNS will be compressed explicitly with .gz sufix;
             Parquet files will be compressed internally due to the
             nature of the format.

             This is a static configuration parameter that is applied
             only upon restarting the probe.";
        }
        leaf pcap-export {
          type enumeration {
            enum all {
              description
                "Store all packets.";
            }
            enum invalid {
              description
                "Store only transactions with invalid DNS
                 request/response.";
            }
            enum disabled {
              description
                "Turn off PCAP export.";
            }
          }
          default "disabled";
          description
            "Selection of packets to be stored in PCAP files, in
             addition to normal Parquet or C-DNS export.";
        }
      }
      container ip-anonymization {
        description
          "Configuration of client IP anonymization in exported data (Parquet or C-DNS).
           The optional PCAP export does NOT get anonymized!!!";

        leaf anonymize-ip {
          type boolean;
          default "false";
          description
            "If this flag is true, client IP addresses in exported data will be anonymized
             using Crypto-PAn prefix-preserving algorithm.

             This is a static configuration parameter that is applied
             only upon restarting the probe.";
        }

        leaf encryption {
          type enumeration {
            enum aes {
              description
                "AES encryption algorithm.";
            }

            enum blowfish {
              description
                "Blowfish encryption algorithm.";
            }

            enum md5 {
              description
                "MD5 hash function.";
            }

            enum sha1 {
              description
                "SHA1 hash function.";
            }
          }

          default "aes";
          description
            "Encryption algorithm to be used during anonymization of client IP addresses if enabled.

             This is a static configuration parameter that is applied
             only upon restarting the probe.";
        }

        leaf key-path {
          type string;
          default "key.cryptopant";
          description
            "Path (including file's name) to the file with encryption key that is to be used
             for client IP anonymization if enabled. If the file doesn't exist, it is generated
             by the probe.

             The key needs to be compatible with the encryption algorithm set in the 'encryption'
             option above. User should generate the key using 'scramble_ips' tool installed by
             the cryptopANT dependency like this:

             scramble_ips --newkey --type=<encryption> <key_file>

             This is a static configuration parameter that is applied
             only upon restarting the probe.";
        }
      }
      container transaction-table {
        description
          "Configuration of transaction table parameters.";
        leaf max-transactions {
          type uint32;
          default "1048576";
          description
            "Maximum number of entries in the transaction table.

             This is a static configuration parameter that is applied
             only upon restarting the probe.";
        }
        leaf query-timeout {
          type uint64;
          units "milliseconds";
          default "1000";
          description
            "Time interval after which a query record is removed from
             the transaction database if no response is observed.";
        }
        leaf match-qname {
          type boolean;
          default "false";
          description
            "If this flag is true, DNS QNAME (if present) is used as a
             secondary key for matching requests with responses.";
        }
      }
      container tcp-table {
        description
          "Configuration of TCP processing.";
        leaf concurrent-connections {
          type uint32;
          default "1048576";
          description
            "Maximal number of concurrent TCP connections.

             This is a static configuration parameter that is applied
             only upon restarting the probe.";
        }
        leaf timeout {
          type uint64;
          units "milliseconds";
          default "60000";
          description
            "Time interval after which a TCP connection is removed from
             the transaction database if no data is received through
             that connection.";
        }
      }
    }

    container statistics {
      config "false";
      description
        "A collection of probe statistics.";
      leaf processed-packets {
        type yang:counter64;
        description
          "Number of processed packets.";
      }
      leaf processed-transactions {
        type yang:counter64;
        description
          "Number of processed transactions.";
      }
      leaf exported-records {
        type yang:counter64;
        description
          "Number of exported records.";
      }
      leaf queries-per-second-ipv4 {
        type decimal64 {
          fraction-digits "2";
        }
        description
          "Processed queries per second with IPv4 packets.";
      }
      leaf queries-per-second-ipv6 {
        type decimal64 {
          fraction-digits "2";
        }
        description
          "Processed queries per second with IPv6 packets.";
      }
      leaf queries-per-second-tcp {
        type decimal64 {
          fraction-digits "2";
        }
        description
          "Processed queries per second with TCP packets.";
      }
      leaf queries-per-second-udp {
        type decimal64 {
          fraction-digits "2";
        }
        description
          "Processed queries per second with UDP packets.";
      }
      leaf queries-per-second {
        type decimal64 {
          fraction-digits "2";
        }
        description
          "Processed queries per second.";
      }
      leaf pending-transactions {
        type yang:counter64;
        description
          "Number of pending transactions.";
      }
      leaf exported-pcap-packets {
        type yang:counter64;
        description
          "Number of packets exported to PCAP files.";
      }
    }

    /* RPC operations */

    rpc restart {
      description
        "Restart the probe and apply changes in static
         configuration.";
    }
  }
