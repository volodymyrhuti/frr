#!/usr/bin/env python
#
# SPDX-License-Identifier: ISC
# Copyright (c) 2023 VyOS Inc.
# Volodymyr Huti <v.huti@vyos.io>
#

import platform
import ctypes
import os
import io

"""
XXX:

The `xdp_attach` method expects target dev to be visible (to be in local netns).
It is possible to run some helper via `rnode.popen("bcc_script.py", ...)`,
but we would still need to initialized a separate BPF handler in the root ns.


The functionality is provided by `pyroute2` package - `setns/pushns/popns`
Either we can specify pyroute2 as an required dependencies, or just
adopt the relevant methods, avoiding any extra packages.

/usr/lib/python3/dist-packages/pyroute2/netns/__init__.py
/usr/lib/python3/dist-packages/pyroute2/netns/nslink.py

from pyroute2 import IPRoute, NetNS, IPDB, NSPopen
"""

file = io.IOBase
CLONE_NEWNET = 0x40000000
NETNS_RUN_DIR = "/var/run/netns"
__saved_ns = []

machine = platform.machine()
arch = platform.architecture()[0]
__NR = {
    "x86_": {"64bit": 308},
    "i386": {"32bit": 346},
    "i686": {"32bit": 346},
    "mips": {"32bit": 4344, "64bit": 5303},
    "armv": {"32bit": 375},
    "aarc": {"32bit": 375, "64bit": 268},  # FIXME: EABI vs. OABI?
    "ppc6": {"64bit": 350},
    "s390": {"64bit": 339},
}
__NR_setns = __NR.get(machine[:4], {}).get(arch, 308)


def setns(netns, flags=os.O_CREAT):
    """
    Set netns for the current process.

    The flags semantics is the same as for the `open(2)`
    call:

        - O_CREAT -- create netns, if doesn't exist
        - O_CREAT | O_EXCL -- create only if doesn't exist

    Note that "main" netns has no name. But you can access it with::

        setns('foo')  # move to netns foo
        setns('/proc/1/ns/net')  # go back to default netns

    See also `pushns()`/`popns()`/`dropns()`

    Changed in 0.5.1: the routine closes the ns fd if it's
    not provided via arguments.
    """
    newfd = False
    basestring = (str, bytes)
    lib_name = "libc.so.6"
    # lib_name =  ctypes.util.find_library('c') <- bugged for me
    libc = ctypes.CDLL(lib_name, use_errno=True)
    if isinstance(netns, basestring):
        netnspath = _get_netnspath(netns)
        if os.path.basename(netns) in listnetns(os.path.dirname(netns)):
            if flags & (os.O_CREAT | os.O_EXCL) == (os.O_CREAT | os.O_EXCL):
                raise OSError(errno.EEXIST, "netns exists", netns)
        else:
            if flags & os.O_CREAT:
                create(netns, libc=libc)
        nsfd = os.open(netnspath, os.O_RDONLY)
        newfd = True
    elif isinstance(netns, file):
        nsfd = netns.fileno()
    elif isinstance(netns, int):
        nsfd = netns
    else:
        raise RuntimeError("netns should be a string or an open fd")
    error = libc.syscall(__NR_setns, nsfd, CLONE_NEWNET)
    if newfd:
        os.close(nsfd)
    if error != 0:
        raise OSError(ctypes.get_errno(), "failed to open netns", netns)


def _get_netnspath(name):
    netnspath = name
    dirname = os.path.dirname(name)
    if not dirname:
        netnspath = "%s/%s" % (NETNS_RUN_DIR, name)
    if hasattr(netnspath, "encode"):
        netnspath = netnspath.encode("ascii")
    return netnspath


def listnetns(nspath=None):
    """
    List available network namespaces.
    """
    if nspath:
        nsdir = nspath
    else:
        nsdir = NETNS_RUN_DIR
    try:
        return os.listdir(nsdir)
    except OSError as e:
        if e.errno == errno.ENOENT:
            return []
        else:
            raise


def pushns(newns=None):
    """
    Save the current netns in order to return to it later. If newns is
    specified, change to it::

        # --> the script in the "main" netns
        netns.pushns("test")
        # --> changed to "test", the "main" is saved
        netns.popns()
        # --> "test" is dropped, back to the "main"
    """
    global __saved_ns
    __saved_ns.append(os.open("/proc/self/ns/net", os.O_RDONLY))
    if newns is not None:
        setns(newns)


def popns():
    """
    Restore the previously saved netns.
    """
    global __saved_ns
    fd = __saved_ns.pop()
    try:
        setns(fd)
    except Exception:
        __saved_ns.append(fd)
        raise
    os.close(fd)
