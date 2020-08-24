**************
Data collector
**************

DNS Probe supports transfer of exported DNS data in C-DNS or Parquet format directly to a remote location
via encrypted TLS connection. To collect this data on remote location's side package ``dns-probe-collector``
comes with :doc:`dp-collector <manpages/dp-collector>` binary. It is recommended to run this collector as
a `systemd <https://www.freedesktop.org/wiki/Software/systemd/>`_ service.

Running as systemd service
==========================

Installation package ``dns-probe-collector`` includes a *systemd* unit file ``dns-probe-collector.service``.
The *systemd* service can be run on remote location's side like this:

.. code:: shell

    sudo systemctl start dns-probe-collector.service

Other ``systemctl`` subcommands can be used to stop, enable or restart the service.

By default there's no server certificate or private key set. The directory to store incoming data is also
by default set to directory from which the binary was started. The user is therefore required to configure
the ``dp-collector`` before the first run of its *systemd* service.

The package ``dns-probe-collector`` installs default configuration file to ``/etc/dns-probe-collector/dp-collector.conf``:

::

    # DNS Probe Collector's configuration

    # Path to Collector's server certificate HAS to be specified either here or in command line.
    SERVER_CERTIFICATE=

    # Path to Collector's private key matching the server certificate HAS to be specified
    # either here or in command line.
    SERVER_PRIVATE_KEY=

    # Optionally fill specific interface's IP adress to run the Collector on.
    # By default Collector will listen on all interfaces.
    IP_ADDRESS=

    # Tranport protocol port for the Collector to listen on.
    PORT=6378

    # Directory to store the collected data.
    # By default data will be stored to directory from which the Collector was started.
    OUTPUT_DIRECTORY=

User should edit this file and fill the paths to server certificate, private key and output directory to store the data.
After the modification is done the *systemd* service can be started as usual.

Running from command line
=========================

The ``dp-collector`` binary can also be run from command line with parameters described in its
:doc:`manual page <manpages/dp-collector>`. It reads the same configuration file in
``/etc/dns-probe-collector/dp-collector.conf`` as the *systemd* service. Its configuration can be further
specified via command line parameters which supersede the values in configuration file.
