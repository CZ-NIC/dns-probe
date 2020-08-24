.. highlight:: console
.. program:: dp-collector

============
dp-collector
============

Synopsis
--------

:program:`dp-collector` [-s *server_certificate* -k *server_private_key*] [-a *ip_address*] [-p *port*] [-o *output_directory*] [-c *config_file*] [-h]

Description
-----------

:program:`dp-collector` is a data collector collecting data exported by DNS Probe via TLS network transfer.

:program:`dp-collector` acts as a TLS server accepting incoming connections from DNS Probe and stores the incoming data to local files in a specified directory.

:program:`dp-collector` can be configured either via command line parameters or by editing a configuration file found at ``<install_dir>/etc/dns-probe-collector/dp-collector.conf``.

Options
-------

.. option:: -s server_certificate

   Collector's server certificate for establishing TLS connection.

.. option:: -k server_private_key

   Collector's private key for TLS connection encryption.

.. option:: -a ip_address

   Bind collector to specific interface's IP address. By default collector listens on all available interfaces.

.. option:: -p port

   Transport protocol port the collector will listen on. Default is 6378.

.. option:: -o output_directory

   Directory to store the collected data. Default is ".".

.. option:: -c config_file

   Configuration file where all the available configuration options can be set.

.. option:: -h

   Print help message and exit.

Exit Status
-----------

**EXIT_SUCCESS**
   Normal exit

**EXIT_FAILURE**
   Abnormal exit on collector's failure
