Sysrepo Concepts
================

Sysrepo is datastore for application configuration and its operational
data like list of current connected clients, number of processed
packets, progress of some action etc. Sysrepo also allows define RPCs
and notification. Unlike from typical text configurations in Linux
sysrepo using models in `YANG <https://tools.ietf.org/html/rfc7950>`__
modeling language. Model defines format of all configurable items,
operational items, RPC and notifications. Application using sysrepo must
follow associated model.

The application configuration in sysrepo is stored in three datastores.
First is startup, running and candidate. The startup is configuration
used when the application is started. Running is configuration used in
current running instance. Candidate datastore contains new configuration
which must be verified before application into running datastore.

The Sysrepo’s main benefit is standardized API for managing
configuration, subscribing to notifications and calling RPC. With usage
other tools like `Netopeer <https://github.com/CESNET/Netopeer2>`__ it
can be also used to remote configuration through NETCONF and RESTCONF
protocols. It also allows changing configuration while the application
running which is in the most cases unavailable with text configurations.
For manipulation of configurations there are two utilities
``sysrepoctl`` and ``sysrepocfg``. ``Sysrepoctl`` configuring sysrepo as
is (for example installs new models). ``Sysrepocfg`` is used for
managing configurations of all installed models. More on this command
later in the document.

The YANG model is structured into containers, lists and scalar
variables. The configuration itself is represented in the XML format
following structure defined in the associated YANG model. For example,
this YANG model:

::

    module cznic-dns-probe {

        namespace "https://www.nic.cz/ns/yang/dns-probe";

        container dns-probe {
            leaf coremask {
                type uint64 {
                    range "7..max";
                }
                default "0x7";
            }

            leaf dns-port {
                type uint16;
                default 53;
            }

            container export {
                leaf export-dir {
                    type string;
                    default ".";
                }
            }
        }
    }

For more information about YANG model language and its representation in
XML you can visit official `RFC
7950 <https://tools.ietf.org/html/rfc7950>`__ standard. Its default
configuration looks like:

::

    <dns-probe xmlns=”https://www.nic.cz/ns/yang/dns-probe”>
        <coremask>7</coremask>
        <dns-port>53</dns-port>
        <export>
            <export-dir>.</export-dir>
        </export>
    </dns-probe>

Installing DNS Probe model
==========================

The model used by Sysrepo and applications using it has to be first
installed. If you installed ``DNS Probe`` from package it is already
installed. Otherwise you have to run command
``sysrepoctl -i path/to/module.yang``. After successful installation you
can modify the configuration and start the application.

Modifying configuration
=======================

For changing configuration from default values defined in the YANG model
you can use ``sysrepocfg`` utility. It has two categories of parameters.
The first category contains operation parameters which selects what
should be done. The most important are: \* ``-E[=<file/editor>]`` Allows
modifying configuration inside sysrepo datastores \* ``-X[=<file>]``
Export configuration to ``STDOUT`` or into file

The second category are modifiers: \* ``-m <module-name>`` Select model
for operations otherwise given operation will apply for all models \*
``-d <datastore>`` Select which datastore given operation use. By
default it is running datastore.

For more options and more verbose documentation please see help of the
``sysrepocfg``. When you run the command
``sysrepocfg -E -m cznic-dns-probe`` for the first time it will open
empty editor. It is empty because there is no modification towards the
default configuration. For changing port which is used for identifying
incoming DNS traffic from 53 to 64 you can enter this:

::

    <dns-probe xmlns="https://www.nic.cz/ns/yang/dns-probe">
        <dns-port>64</dns-port>
    </dns-probe>

To check the new configuration you can use command ``sysrepocfg -X``.

For all available options look at `YANG module
description <YANG-module-description>`__. Every option contains XPath
which can be used for correct nesting of XML tags. For example, the
XPath ``/dns-probe/export/cdns-records-per-block`` is in XML:

::

    <dns-probe xmlns="https://www.nic.cz/ns/yang/dns-probe">
        <export>
            <cdns-records-per-block>1000</cdns-records-per-block>
        </export>
    </dns-probe>

