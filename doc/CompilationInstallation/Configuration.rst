Configuration
=============

The probe is using the `Sysrepo <https://github.com/sysrepo/sysrepo/>`__
as storage for configuration. Sysrepo is using data models written in
YANG language to describe configuration options, their constraints and
dependencies. Complete data model for DNS Probe can be found in
directory
`data-model/cznic-dns-probe.yang <https://gitlab.labs.nic.cz/adam/dns-probe/-/blob/master/data-model/cznic-dns-probe.yang>`_.
The data model contains list of configuration directives which can be
changed, description of runtime statistics and RPC. For modifying and
accessing data from sysrepo please see sysrepo's documentation.

The configuration of DNS Probe contains two basic types. Static
configuration items can be modified while the application is running but
all changes will be applied after restart of the DNS Probe.
Modifications of dynamic configuration items will be applied instantly
after the modification.

YANG modules
************

-  `data-model/cznic-dns-probe.yang <https://gitlab.labs.nic.cz/adam/dns-probe/-/blob/master/data-model/cznic-dns-probe.yang>`_
