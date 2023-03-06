#!/usr/bin/env python
#
# SPDX-License-Identifier: ISC
# Copyright (c) 2023 VyOS Inc.
# Volodymyr Huti <v.huti@vyos.io>
#


import os
import re
import sys
import time
import functools
import subprocess

from lib import topotest
from lib.topolog import logger
from lib.topojson import build_config_from_json
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.bgp import verify_bgp_convergence
from lib.common_config import (
    create_debug_log_config,
    apply_raw_config,
    start_topology,
    TcpDumpHelper,
    IPerfHelper,
    step,
)

from bgp_qppb_vyos_flow import *
from lib.topotest import version_cmp, interface_to_ifindex

af21_tag = c_ubyte(0x12)
af12_tag = c_ubyte(0x0C)
zero_tag = c_ubyte(0)
# Module
# -------------------------------------------------------
def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()
    # iperf_helper.cleanup()
    # tcpdumpf_helper.cleanup()


def setup_module(mod):
    # XXX: write down [ requirement:verion, ... ]
    # result |= required_linux_kernel_version("5+")
    # result |= required_linux_kernel_features("BPF")
    # result |= required_package_version(bcc, dev)
    #       ...
    # if result is not True:
    #     pytest.skip("Kernel requirements are not met")
    # XXX(?): verify that user XPD env doesn't overlap with test

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    json_file = f"{CWD}/topo_vrf.json"
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo

    start_topology(tgen)
    build_config_from_json(tgen, topo)
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # -----------------------------------------------------------------------
    r1 = tgen.gears["r1"]
    debug_rmap_dict = {"r1": {"raw_config": ["end", "debug route-map"]}}
    debug_config_dict = {
        "r1": {"debug": {"log_file": "debug.log", "enable": ["bgpd", "zebra"]}}
    }
    if DEV_DEBUG:
        create_debug_log_config(tgen, debug_config_dict)
        apply_raw_config(tgen, debug_rmap_dict)


# Test Cases
# -------------------------------------------------------
from ctypes import Structure, c_int, c_uint, c_ubyte, c_uint32
xdp_ifindex = lambda host, iface: c_uint(interface_to_ifindex(host, iface))
xdp_dscp = lambda x: c_ubyte(dscp_tos(x))
dscp_tos = lambda x: x << 2

"""
 ip rule add pref 32765 table local
 ip rule del pref 0
 ip rule show
"""

def tc_bpf_filter(rnode, ifid):
    "Attach tc bpf filter, depends on pyroute2 package"
    import pyroute2
    from pyroute2.netns import pushns, popns

    tc_fn = rnode.bpf.funcs[b"xdp_vrf"]
    rnode_ns = "/proc/{}/ns/net".format(rnode.net.pid)

    logger.debug("Attach TC-BPF handler '{}'\nNetNS --> {})".format(ifid, rnode_ns))
    # ip.tc("add", "clsact", ifid, "1:")
    pushns(rnode_ns)
    ip = pyroute2.IPRoute()
    ip.tc("add", "ingress", ifid, "ffff:")
    ip.tc("add-filter", "bpf", ifid, 20, fd=tc_fn.fd, name=tc_fn.name,
            parent="ffff:", classid=1, action="drop", direct_action=True)
    popns()


def test_dscp_vrf(tgen):
    r1 = tgen.gears['r1']
    r2 = tgen.gears['r2']
    r3 = tgen.gears['r3']
    r4 = tgen.gears['r4']

    # red = xdp_ifindex(r1, "RED")
    # blue = xdp_ifindex(r1, "BLUE")
    red = xdp_ifindex(r1, "r1-r2-eth0")
    blue = xdp_ifindex(r1, "r1-r3-eth1")

    r1.cmd_raises("sysctl -w net.ipv4.conf.all.proxy_arp=1")
    r1.cmd_raises("""
            ip rule add pref 32765 table local
            ip rule del pref 0
            ip rule show
            """)
    # r1.cmd_raises("ip route add 192.168.1.0/24 dev RED")
    # r1.cmd_raises("ip addr add 192.168.1.254/24 dev RED")
    # r1.cmd_raises("ip addr add 192.168.1.254/24 dev BLUE")

    for r in tgen.gears.values():
        load_vrf_plugin(tgen, r)

    for r in [r2, r3, r4]:
        router_attach_xdp(r, "%s-r1-eth0" % r.name, b"xdp_dummy")
        r.cmd_raises("ip route add default dev %s-r1-eth0" % r.name)

    for iface in ["r1-r2-eth0", "r1-r3-eth1"]:
        router_attach_xdp(r1, iface, b"xdp_dummy");

    ingress_if = interface_to_ifindex(r1, "r1-r4-eth2")
    # router_attach_xdp(r1, "r1-r4-eth2")
    # r1.cmd_raises("ip l set r1-r4-eth2 master RED")
    dscp_iface_map = r1.bpf['dscp_iface_map']
    dscp_iface_map[c_uint(10)] = red
    dscp_iface_map[c_uint(20)] = blue
    # breakpoint()
    tc_bpf_filter(r1, ingress_if)
    breakpoint()
"""
- Need requirements/setup clarifications from customer
- Redirecting from root vrf -> vrf should be possible?
The redirection on XDP side requires updating src/dst ether for packet.
Neighbour may be resolved within single vrf while missing in another
You have no TOS for arp packet, which vrf should be used as controll plane?
Otherwise, no such problem if you set arps mannually

For more details - Forwarding from tc classifier
https://lore.kernel.org/bpf/CACAyw9_4Uzh0GqAR16BfEHQ0ZWHKGUKacOQwwhwsfhdCTMtsNQ@mail.gmail.com/

I have tried redirecting to INGRESS from tc classifier, but it doesn`t work well,
would need chatting with devs to figure this out.

- VRF docs
https://github.com/Mellanox/mlxsw/wiki/Virtual-Routing-and-Forwarding-%28VRF%29
https://docs.nvidia.com/networking-ethernet-software/cumulus-linux-54/Layer-3/VRFs/Virtual-Routing-and-Forwarding-VRF/##

- ip rule tos <vrf_table_id>
https://unix.stackexchange.com/questions/493453/ip-rule-doesnt-work-with-tos-greater-than-0x10
https://baturin.org/docs/iproute2/#ip-rule-add-tos

- setsockopt(SO_BINDTODEVICE), bind connection (socket) to specific vrf, 
https://lore.kernel.org/bpf/20200521125247.30178-1-fejes@inf.elte.hu/
https://lwn.net/Articles/708019/  net: Add bpf support for sockets
https://github.com/torvalds/linux/tree/master/samples/bpf
https://elixir.bootlin.com/linux/latest/source/samples/bpf/tcp_clamp_kern.c
https://github.com/torvalds/linux/blob/master/samples/bpf/tcp_tos_reflect_kern.c
- map/hash packet to socket in specific vrf ?
https://github.com/zachidan/ebpf-sockops/blob/master/bpf_sockops.c

- cilium SRv6, example vrf in bpf
https://github.com/cilium/cilium/commit/f42a49011ca7fac4ae824cf767de18059b40da78
https://github.com/cilium/cilium/commit/86777c241f83dacede5191a950c35eda0c446bea

- Redir example
https://github.com/p4lang/p4c/blob/main/backends/ebpf/psa/README.md
https://github.com/p4lang/p4c/blob/f1181a071844f759b618ed3c894cf56e2df1dd05/backends/ebpf/psa/ebpfPipeline.cpp#L594

- random
https://github.com/SPYFF/ebpf-vrf
"""

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))


def router_attach_xdp(rnode, iface, fn=b"xdp_vrf"):
    """
    - swap netns to rnode,
    - attach `xdp_qppb` to `iface`
    - switch back to root ns
    """
    ns = "/proc/%d/ns/net" % rnode.net.pid
    vrf_fn = rnode.bpf.funcs[fn]

    pushns(ns)
    logger.debug("Attach XDP handler '{}|{}'\nNetNS --> {})".format(iface, fn, ns))
    rnode.bpf.attach_xdp(iface, vrf_fn, 0)
    popns()


def load_vrf_plugin(tgen, rnode, debug_on=True):
    """
    Initialize rnode XDP hooks and BPF mapping handlers
      - compile xdp handlers from `xdp_qppb.c` in specified `mode`
      - load `xdp_qppb` and `xdp_tc_mark` hooks
      - restart router with QPPB plugin

    Parameters
    ----------
    * `tgen`: topogen object
    * `rnode`: router object
    * `mode`: xdp processing mode required
    * `debug_on`: enable debug logs for bpf compilation / xdp handlers

    Usage
    ---------
    load_qppb_plugin(tgen, r1, mode=XdpMode.META)
    Returns -> None (XXX)
    """
    debug_flags = DEBUG_BPF | DEBUG_PREPROCESSOR | DEBUG_SOURCE | DEBUG_BTF
    debug = debug_flags if debug_on else 0
    src_file = CWD + "/xdp_vrf.c"
    bpf_flags = [
        '-DBPF_PIN_DIR="{}"'.format(rnode.bpfdir),
        "-w",
    ]

    try:
        logger.info("Preparing the XDP src: " + src_file)
        b = BPF(src_file=src_file.encode(), cflags=bpf_flags, debug=debug)

        logger.info("Loading XDP hooks -- xdp_vrf")
        b.load_func(b"xdp_vrf", BPF.SCHED_CLS)
        b.load_func(b"xdp_dummy", BPF.XDP)
        rnode.bpf = b
    except Exception as e:
        breakpoint()
        pytest.skip("Failed to configure XDP environment -- \n" + str(e))


