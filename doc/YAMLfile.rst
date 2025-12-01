.. _yaml-file:

*****************
Default YAML file
*****************

This section contains the complete default YAML configuration file that is used for DNS Probe.
It is also included in the project repository (`data-model/dns-probe.yml <https://gitlab.nic.cz/adam/dns-probe/blob/master/data-model/dns-probe.yml>`_) and packages.

.. code-block:: yaml

  # Last revision: 2025-12-01
  #
  # Default instance configuration.
  # This configuration is always loaded before other configuration specified by given instance's ID.
  # DNS Probe contains default configuration values within itself so this file can be left empty
  # if desired.
  default:

    # List of network interfaces to process traffic from in addition to interfaces passed
    # with '-i' command line parameter.
    interface-list: []

    # List of PCAPs to process in addition to PCAPs passed with '-p' command line parameter.
    pcap-list: []

    # List of unix sockets to process dnstap data from in addition to sockets passed with '-d'
    # command line parameter.
    dnstap-socket-list: []

    # Name of existing user group under which to create dnstap sockets. By default the group of
    # probe's process is used.
    dnstap-socket-group: ''

    # Path to directory in which to create unix sockets for reading Knot interface data. Might get
    # overriden by '-s' command line parameter.
    knot-socket-path: '/tmp'

    # Number of Knot interface sockets to create in 'knot-socket-path' directory. Might get
    # overriden by '-k' command line parameter.
    knot-socket-count: 0

    # Indicates RAW PCAPs as input in 'pcap-list' or from command line with '-p' parameter.
    # Might get overriden by '-r' command line parameter.
    # MUST be set to 'false' if 'interface-list' or '-i' command line parameter are used.
    raw-pcap: false

    # Path (including file's name) to log file for storing logs. Might get overriden by '-l'
    # command line parameter.
    # By default logs are written to stdout.
    log-file: ''

    # This parameter is used for selecting CPU cores on which the application will be running.
    coremask: 0x7

    # List of allowed IPv4 addreses and prefixes to process traffic from.
    # By default all IPv4 addresses are allowed.
    ipv4-allowlist: []

    # List of IPv4 addresses and prefixes from which to NOT process traffic.
    # By default all IPv4 addresses are allowed.
    ipv4-denylist: []

    # List of allowed IPv6 addresses and prefixes to process traffic from.
    # By default all IPv6 addresses are allowed.
    ipv6-allowlist: []

    # List of IPv6 addresses and prefixes from which to NOT process traffic.
    # By default all IPv6 addresses are allowed.
    ipv6-denylist: []

    # List of ports used for identifying DNS traffic.
    dns-ports:
      - 53
      # - 853
      # - 443

    # [SECTION] Items for configuration of exported data
    export:

      # Location for the storage of exported DNS records.
      # Valid values are 'local', 'remote' and 'kafka'.
      location: 'local'

      # Directory for exported data.
      export-dir: '.'

      # IP address for remote export of DNS records.
      remote-ip-address: '127.0.0.1'

      # Transport protocol port number for remote export of DNS records.
      remote-port: 6378

      # Backup IP address for remote export of DNS records
      backup-remote-ip-address: ''

      # Backup transport protocol port number for remote export of DNS records.
      backup-remote-port: 6378

      # Path (including file's name) to the CA certificate against which the remote server's
      # certificate will be authenticated during TLS handshake.
      # By default server's certificate will be authenticated against OpenSSL's default directory
      # with CA certificates.
      remote-ca-cert: ''

      # Comma separated list of Kafka brokers (host or host:port) for export of DNS records
      kafka-brokers: '127.0.0.1'

      # Force IP address family for connection to Kafka brokers for export of DNS records
      # Valid values are 'any', 'v4', 'v6'.
      kafka-address-family: 'any'

      # Kafka topic for export of DNS records
      kafka-topic: 'dns-probe'

      # Kafka message key that will be used to assign all messages (DNS records) to specific
      # partition within Kafka topic.
      # By default no key is set (messages will be partitioned randomly).
      kafka-partition: ''

      # File or directory path to CA certificate(s) for verifying Kafka broker's key
      # By default OpenSSL's default directory with CA certificates is used.
      kafka-ca-location: ''

      # Security protocol used to communicate with Kafka brokers.
      # Valid values are 'plaintext', 'ssl', 'sasl_plaintext', 'sasl_ssl'.
      kafka-security-protocol: 'plaintext'

      # Path (including file's name) to public key (PEM) used for authentication to Kafka cluster
      # when 'kafka-security-protocol' is set to 'ssl' or 'sasl_ssl'.
      kafka-cert-location: ''

      # Path (including file's name) to private key (PEM) used for authentication to Kafka cluster
      # when 'kafka-security-protocol' is set to 'ssl' or 'sasl_ssl'
      kafka-key-location: ''

      # Private key passphrase for key set in 'kafka-key-location'
      kafka-key-password: ''

      # SASL mechanism to use for authentication to Kafka brokers.
      # Valid values are 'plain', 'scram-sha-256', 'scram-sha-512'.
      kafka-sasl-mechanism: 'plain'

      # Username for SASL authentication to Kafka brokers.
      kafka-sasl-username: ''

      # Password for SASL authentication to Kafka brokers.
      kafka-sasl-password: ''

      # Format of exported data.
      # Valid values are 'parquet' and 'cdns'.
      export-format: 'parquet'

      # This sequence indicates which fields from the C-DNS standard schema are included in exported data.
      # 3 implementation specific fields are also included (asn, country_code, round_trip_time).
      # By default all fields available in DNS Probe are enabled as shown below.
      cdns-fields:
        - 'transaction_id'
        - 'time_offset'
        - 'query_name'
        - 'client_hoplimit'
        - 'qr_transport_flags'
        - 'client_address'
        - 'client_port'
        - 'server_address'
        - 'server_port'
        - 'query_size'
        - 'qr_dns_flags'
        - 'query_ancount'
        - 'query_arcount'
        - 'query_nscount'
        - 'query_qdcount'
        - 'query_opcode'
        - 'response_rcode'
        - 'query_classtype'
        - 'query_edns_version'
        - 'query_edns_udp_size'
        - 'query_opt_rdata'
        - 'response_answer_sections'
        - 'response_authority_sections'
        - 'response_additional_sections'
        - 'response_size'
        - 'asn' # asn-maxmind-db configuration option also needs to be set
        - 'country_code' # country-maxmind-db configuration option also needs to be set
        - 'round_trip_time' # TCP RTT
        - 'user_id' # Unique user ID (UUID), collected only from dnstap
        - 'policy_action' # Policy applied to query, collected only from dnstap
        - 'policy_rule' # Rule that triggered applied policy, collected only from dnstap

      # Maximum number of DNS records in one exported C-DNS block.
      cdns-records-per-block: 10000

      # Maximum number of C-DNS blocks in one exported C-DNS file.
      cdns-blocks-per-file: 0

      # If this flag is set to true, exported C-DNS files will contain full Answer, Authority and
      # Additional RRs from responses in each record.
      # NOTE: Won't work for traffic captured via Knot interface as this data doesn't contain full RRs.
      cdns-export-response-rr: false

      # Maximum number of Parquet records per file.
      parquet-records-per-file: 5000000

      # Common prefix of exported files' names.
      file-name-prefix: 'dns_'

      # Time interval after which the current export file is rotated.
      # Value is in seconds.
      timeout: 0

      # Size limit for the export file. If the limit is exceeded, the export file is rotated.
      # The value of 0 (default) means no size-based rotation.
      file-size-limit: 0

      # if this flag is true, the exported Parquet or C-DNS files will be compressed using GZIP.
      # C-DNS willl be compressed explicitly with .gz sufix; Parquet files will be compressed
      # internally due to the nature of the format.
      file-compression: true

      # Selection of packets to be stored in PCAP files, in addition to normal Parquet or C-DNS export.
      # It's recommended to use this option only for testing purposes.
      # Valid values are 'all', 'invalid', 'disabled'.
      pcap-export: 'disabled'

      # Path to Maxmind Country database. If this option is set to a valid database file, the 'country'
      # field in exported Parquets or 'country-code' implementation field in exported C-DNS will be
      # filled with ISO 3166-1 country code based on client's IP address.
      country-maxmind-db: ''

      # Path to Maxmind ASN database. If this iption is set to a valid database file, the 'asn'
      # implementation field in exported Parquets or C-DNS will be filled with Autonomous System
      # Number (ASN) based on client's IP address.
      asn-maxmind-db: ''

    # [SECTION] Configuration of client IP anonymization in exported data (Parquet or C-DNS).
    # The optional PCAP export does NOT get anonymized!!!
    ip-anonymization:

      # If this flag is true, client IP addresses in exported data will be anonymized using
      # Crypto-PAn prefix-preserving algorithm.
      anonymize-ip: false

      # Encryption algorithm to be used during anonymization of client IP addresses if enabled.
      # Valid values are 'aes', 'blowfish', 'md5', 'sha1'.
      encryption: 'aes'

      # Path (including file's name) to the file with encryption key that is to be used for client
      # IP anonymization if enabled. If the file doesn't exist, it is generated by the probe.
      # The key needs to be compatible with the encryption algorithm set in the 'encryption' option
      # above. User should generate the key using 'scramble-ips' tool installed by the cryptopANT
      # dependency like this:
      #
      # scramble_ips --newkey --type=<encryption> <key-file>
      key-path: 'key.cryptopant'

    # [SECTION] Configuration of transaction table parameters.
    transaction-table:

      # Maximum number of entries in the transaction table.
      # MUST be a power of 2.
      max-transactions: 1048576

      # Time interval after which a query record is removed from the transaction database if no
      # response is observed.
      # Value is in milliseconds.
      query-timeout: 1000

      # If this flag is true, DNS QNAME (if present) is used as a secondary key for matching
      # requests with responses.
      match-qname: false

    # [SECTION] Configuration of TCP processing
    tcp-table:

      # Maximum number of concurrent TCP connections.
      # MUST be a power of 2.
      concurrent-connections: 131072

      # Time interval after which a TCP connection is removed from the connection database
      # if no data is received through that connection.
      # Value is in milliseconds.
      timeout: 60000

    # [SECTION] Configuration of run-time statistics export
    statistics:

      # If this flag is true, run-time statistics will be exported in JSON format every
      # 'stats-timeout' seconds.
      export-stats: false

      # If this flag is true and any IP addresses are set in 'ipv4-allowlist' or 'ipv6-allowlist',
      # 'queries*' run-time statistics will be exported for each of the IP addresses in addition
      # to overall statistics in format '"[<IP-address>]queries*":<value>'.
      stats-per-ip: false

      # Time interval after which run-time statistics will be periodically exported in JSON locally
      # or to remote location, if enabled by 'export-stats' option. If value is 0, statistics
      # will be exported only on probe's exit.
      # Value is in seconds.
      # RECOMMENDATION: For optimal results the value should be the same as moving-avg-window.
      stats-timeout: 300

      # Location for the storage of exported run-time statistics in JSON.
      # Valid values are 'local', 'remote' and 'kafka'.
      location: 'local'

      # Directory for exported run-time statistics.
      export-dir: '.'

      # IP address for remote export of run-time statistics.
      remote-ip: '127.0.0.1'

      # Transport protocol port number for remote export of run-time statistics.
      remote-port: 6379

      # Backup IP address for remote export of run-time statistics.
      backup-remote-ip: ''

      # Backup transport protocol port number for remote export of run-time statistics.
      backup-remote-port: 6379

      # Path (including file's name) to the CA certificate against which the remote server's
      # certificate will be authenticated during TLS handshake.
      # By default server's certificate will be authenticated against OpenSSL's default directory
      # with CA certificates.
      remote-ca-cert: ''

      # Comma separated list of Kafka brokers (host or host:port) for export of run-time statistics
      kafka-brokers: '127.0.0.1'

      # Force IP address family for connection to Kafka brokers for export of run-time statistics
      # Valid values are 'any', 'v4', 'v6'.
      kafka-address-family: 'any'

      # Kafka topic for export of run-time statistics
      kafka-topic: 'dns-probe-stats'

      # Kafka message key that will be used to assign all messages (run-time statistics) to specific
      # partition within Kafka topic.
      # By default no key is set (messages will be partitioned randomly).
      kafka-partition: ''

      # File or directory path to CA certificate(s) for verifying Kafka broker's key
      # By default OpenSSL's default directory with CA certificates is used.
      kafka-ca-location: ''

      # Security protocol used to communicate with Kafka brokers.
      # Valid values are 'plaintext', 'ssl', 'sasl_plaintext', 'sasl_ssl'.
      kafka-security-protocol: 'plaintext'

      # Path (including file's name) to public key (PEM) used for authentication to Kafka cluster
      # when 'kafka-security-protocol' is set to 'ssl' or 'sasl_ssl'.
      kafka-cert-location: ''

      # Path (including file's name) to private key (PEM) used for authentication to Kafka cluster
      # when 'kafka-security-protocol' is set to 'ssl' or 'sasl_ssl'
      kafka-key-location: ''

      # Private key passphrase for key set in 'kafka-key-location'
      kafka-key-password: ''

      # SASL mechanism to use for authentication to Kafka brokers.
      # Valid values are 'plain', 'scram-sha-256', 'scram-sha-512'.
      kafka-sasl-mechanism: 'plain'

      # Username for SASL authentication to Kafka brokers.
      kafka-sasl-username: ''

      # Password for SASL authentication to Kafka brokers.
      kafka-sasl-password: ''

      # Time window in seconds for which to compute moving average of queries-per-second*
      # run-time statistics. Window can be set in interval from 1 second to 1 hour.
      moving-avg-window: 300

      # This sequence indicates which run-time statistics should be exported if export is enabled.
      # By default all statistics available in DNS Probe are enabled as shown below.
      stats-fields:
        - 'processed-packets'
        - 'processed-transactions'
        - 'exported-records'
        - 'pending-transactions'
        - 'exported-pcap-packets'
        - 'ipv4-source-entropy'
        - 'queries-ipv4'
        - 'queries-ipv6'
        - 'queries-tcp'
        - 'queries-udp'
        - 'queries-dot'
        - 'queries-doh'
        - 'queries'
        - 'queries-per-second-ipv4'
        - 'queries-per-second-ipv6'
        - 'queries-per-second-tcp'
        - 'queries-per-second-udp'
        - 'queries-per-second-dot'
        - 'queries-per-second-doh'
        - 'queries-per-second'
        - 'unix-timestamp' # timestamp of given export

  # Configuration for specific instances of DNS Probe (set by '-n' command line parameter).
  # Only changes to default configuration need to be specified here.
  #
  # test1:
  #   interface-list:
  #     - 'lo'
  #   ipv4-allowlist:
  #     - '192.168.1.1'
  #     - '192.168.2.0/24'
  #
  # test2:
  #   interface-list:
  #     - 'enp0'
  #   ipv6-denylist:
  #     - '2001:db8:abcd:0012::0/64'
