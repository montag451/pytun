Linux TUN/TAP wrapper for Python
================================

``pytun`` is a Python module which let you create TUN/TAP device very easily.

License: MIT (see LICENSE)

Installation and Dependencies
-----------------------------

Install ``pytun`` with ``pip install python-pytun`` or `download this archive
<https://github.com/montag451/pytun/zipball/v2.3.0>`_, decompress it and
execute ``python setup.py install``. As ``pytun`` is a C module you will need a
compiler (e.g GCC) and the Python developpement headers installed on your
system (e.g on Debian-like distribution check that ``build-essential`` and
``python-dev`` are present). There are no dependencies other than the Python
Standard Library.

Documentation
-------------

NOTE: On most distributions you will need to be root to create TUN/TAP devices.

To create a TUN device::

    from pytun import TunTapDevice

    tun = TunTapDevice()

To create a TAP device::

    from pytun import TunTapDevice, IFF_TAP

    tap = TunTapDevice(flags=IFF_TAP)

To create a TUN/TAP device with a custom name use the ``name`` keyword::

    tun = TunTapDevice(name='mytun')

You can get/set some parameters of the device directly::

    print tun.name
    tun.addr = '10.8.0.1'
    tun.dstaddr = '10.8.0.2'
    tun.netmask = '255.255.255.0'
    tun.mtu = 1500

If the device is a TAP you can also get/set its MAC address::

    tap.hwaddr = '\x00\x11\x22\x33\x44\x55'
    print tap.hwaddr

To make the device persistent::

    tun.persist(True)

To bring up the device::

    tun.up()

To bring down the device::

    tun.down()

To enable/disable the queue associated with the device (works only if
it has been created with IFF_MULTI_QUEUE)::

    tun.mq_attach() # enable the queue
    tun.mq_attach(False) # disable the queue

To read/write to the device, use the methods ``read(size)`` and
``write(buf)``::

    buf = tun.read(tun.mtu)
    tun.write(buf)

To close the device::

    tun.close()

You can also use ``TunTapDevice`` objects with all functions that expect a
``fileno()`` method (e.g ``select()``)

