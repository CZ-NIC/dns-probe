.. _glossary:

*****************
Glossary of Terms
*****************

.. glossary::
   :sorted:

   backend

      System facility that is used for reading packets from a network interface card. Two backends are currently supported: `raw socket <https://man7.org/linux/man-pages/man7/packet.7.html>`_ (AF_PACKET) and `DPDK <https://www.dpdk.org/>`_.

   dynamic configuration parameter

      A configuration parameter that can be changed dynamically through Sysrepo and takes effect immediately. See :ref:`dynamic-conf-par`.

   static configuration parameter

      A configuration parameter that needs DNS Probe to be restarted in order to take effect. See :ref:`static-conf-par`.

   RPC operation

      Remote procedure call operation that is activated via remote management API.
