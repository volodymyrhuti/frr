#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# <template>.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
<template>.py: Test <template>.
"""
import os
import re
import sys
import time
import json
import pytest
import functools
import subprocess

from lib import topotest
from lib.topolog import logger
from lib.topojson import build_config_from_json
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topotest import version_cmp, interface_to_ifindex
from lib.bgp import verify_bgp_convergence, create_router_bgp, verify_bgp_rib


from lib.common_config import (
    IPerfHelper,
    check_address_types,
    create_route_maps,
    create_static_routes,
    reset_config_on_routers,
    tcpdump_capture_start,
    tcpdump_capture_stop,
    find_msg_in_tcpdump,
    shutdown_bringup_interface,
    start_topology,
    start_router,
    stop_router,
    step,
    verify_ip_nht,
    verify_rib,
    write_test_footer,
    write_test_header,
)

from pyroute2 import IPRoute, NetNS, IPDB, NSPopen
from pyroute2.netns import setns

from bgp_qppb_vyos_flow import *

os.environ["PYTHONBREAKPOINT"] = "pudb.set_trace"
pytestmark = [pytest.mark.bgpd]

# -------------------------------------------------------
#  Globals
r3_lo_key = KeyV4(32, (1, 0, 3, 17))
r1_lo_key = KeyV4(32, (1, 0, 1, 17))
R3_L0 = "1.0.3.17"
R1_L0 = "1.0.1.17"
R1_ETH0 = "10.0.0.1"

R3_NS = R2_NS = R1_NS = None
CAP_FILE = "ping_test.txt"
PING_COUNT = 10

# -------------------------------------------------------
SET_QPPB_TABLE_MAP = f"""
      configure
        router bgp 100
          table-map QPPB
"""

R2_MINIMAL_QPPB_MAP = {
        "r2": {
            "route_maps": {
                "QPPB": [{
                    "action": "permit",
                    "set": { "dscp": "af21" }
                    }]
                }
            }
        }
# -------------------------------------------------------

@pytest.mark.skip
def test_get_version(tgen):
    "Test the logs the FRR version"
    # keep for debugging
    r1 = tgen.gears["r3"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    version = r1.vtysh_cmd("show version")
    logger.info("FRR version is: " + version)
    breakpoint()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    # app_helper.cleanup()
    tgen.stop_topology()


def setup_module(mod):
    # XXX: compile a list of requirements:verions
    # result |= required_linux_kernel_version("5+")
    # result |= required_linux_kernel_features("BPF")
    # result |= required_package_version(bcc, dev)
    # if result is not True:
    #     pytest.skip("Kernel requirements are not met")

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    json_file = "{}/topojson.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo

    start_topology(tgen)
    build_config_from_json(tgen, topo)
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # enable arp forwarding for diffrenet subnets
    # required to communicate with lo`s in different subnet
    router_list = tgen.routers()
    proxy_arp = "net.ipv4.conf.all.proxy_arp"
    for _, router in router_list.items():
        topotest.sysctl_assure(router, proxy_arp, 1)

    # breakpoint()
    global ADDR_TYPES
    global BGP_CONVERGENCE
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    r2 = tgen.gears["r2"]
    init_qppb_plugin(tgen, r2, setup=True)

    global R2_NS
    R2_NS = "/proc/{}/ns/net".format(r2.net.pid)
    # XXX: verify that host XPD doesn't overlap with test env(?)


def check_ping4(rnode, dst, connected=True, src=None, tos=None, count=10, timeout=0):
    ping = "ping {} -c{}".format(dst, count)
    if timeout:
        ping = "{} -w{}".format(ping, timeout)
    if src:
        ping = "{} -I{}".format(ping, src)
    if tos:
        ping = "{} -Q{}".format(ping, src)

    match = ", {} packet loss".format("100%" if connected else "0%")
    logger.info(
        "[+] {} ping -> {}, status expected -> {}".format(
            rnode, dst, "up" if connected else "down"
        )
    )
    logger.debug("Executing the ping -> {}".format(ping))

    def _match_missing(rnode, dst, match):
        output = rnode.run(ping)
        logger.info(output)
        return match not in output
    func = functools.partial(_match_missing, rnode, dst, match)
    success, result = topotest.run_and_expect(func, True, count, wait=1)
    assert result is True

def tcpdump_helper(tgen, sender, dst, cap_dev, cap_iface, tos, src=None, ping_tos=None):
    global CAP_FILE
    tcpdump = tcpdump_capture_start(
        tgen,
        cap_dev,
        cap_iface,
        background=True,
        timeout=PING_COUNT,
        protocol="icmp[0] == 8",  # ICMP Echo Request
        options="-A -vv > {}".format(CAP_FILE),
    )
    assert tcpdump, "Failed run tcpdump on {}:\n{}".format(sender.name, tcpdump)
    check_ping4(sender, dst, src=src, count=PING_COUNT, timeout=PING_COUNT, tos=ping_tos)
    time.sleep(1.5)
    return find_msg_in_tcpdump(tgen, cap_dev, "tos 0x%x" % tos, CAP_FILE)


# @pytest.mark.skip
def test_xdp_lpm(tgen):
    """
    Manually setup the XDP mappings, no route destribution.
    Assume that R1 is pinging managment interface on R3 [lo(1.0.3.17)]
    The R2 is marking/forwarding based on QPPB mappings:
        R1 [sender,eth0] <-> R2 [eth0,forward,eth1] <-> R3 [eth0,receiver]

    The packet marking happens on R2 ingress XDP hook, as follows:
    -----------------------------------------
    xdp_qppb(xdp_md *skb):
        switch qppb_map[eth0_ifindex]:
            BGP_POLICY_SRC: mark = dscp_map[(skb.src, 32)]
            BGP_POLICY_DST: mark = dscp_map[(skb.dst, 32)]
                      NONE: return pass

        if MARK_SKB:  skb->tos = mark
        if MARK_META: skb->classid = mark
        return pass
    -----------------------------------------
    """
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r2_eth0_idx = c_uint(interface_to_ifindex(r2, "r2-r1-eth0"))
    r2_eth1_idx = c_uint(interface_to_ifindex(r2, "r2-r3-eth1"))

    bpf = r2.bpf
    qppb_fn = bpf.funcs[b"xdp_qppb"]
    qppb_map = bpf[b"qppb_mode_map"]
    dscp_map = bpf[b"dscp_map"]

    af21_tag = 0x12
    af12_tag = 0x0C

    STEP = """
    (On R2) Verify that XDP was loaded and markings work properly
        1. Attach XDP hook to ingress iface in MARK_SKB mode
        2. Set BGP policy in DST mode
        3. Initialize LPM with prefix of targeted iface
        4. Send ping, verify that traffic was marked
    """
    global R2_NS
    setns(R2_NS)
    qppb_map[r2_eth0_idx] = BGP_POLICY_DST
    bpf.attach_xdp(b"r2-r1-eth0", qppb_fn, BPF.XDP_FLAGS_DRV_MODE)

    step(STEP)
    # --------------------------------------------------------------------------------
    global R1_L0
    global R3_L0
    global r1_lo_key
    global r3_lo_key
    global PING_COUNT

    # refresh arp cache, etc ...
    # check_ping4(tgen, r1, R3_L0, connected=False)
    # r1.run("ping {} -c 1 -w 1".format(R3_L0))
    # --------------------------------------------------------------------------------
    _tcpdump = functools.partial(tcpdump_helper, tgen, r1, R3_L0, "r3", "r3-r2-eth0")
    dscp_map[r3_lo_key] = c_ubyte(af21_tag)
    found, matches = _tcpdump(af21_tag)
    assert found and matches >= (
        # XXX: first packet is not tagged (need to resolve arps upfront?)
        PING_COUNT - 1
    ), "LPM doesn't work as expected, mark detected only {} times ".format(matches)

    # --------------------------------------------------------------------------------
    dscp_map[r3_lo_key] = c_ubyte(af12_tag)
    found, matches = _tcpdump(af12_tag)
    assert found and matches >= (
        # XXX: still 1 packet - not tagged, arps should be present ;\
        PING_COUNT - 1
    ), "LPM doesn't work as expected, mark detected only {} times ".format(matches)

    #---------------------------------------------------------------------------------
    dscp_map[r3_lo_key] = c_ubyte(0)
    dscp_map[r1_lo_key] = c_ubyte(af12_tag)
    qppb_map[r2_eth0_idx] = BGP_POLICY_SRC
    found, matches = _tcpdump(af12_tag, src=R1_L0)
    assert found and matches >= (
        PING_COUNT - 1
    ), "LPM doesn't work as expected, mark detected only {} times ".format(matches)

    # --------------------------------------------------------------------------------
    # XXX: Run some flows into opposite directions
    # XXX: Use ping with custom tos ...
    # XXX: Try configuring invalid values
    #      ...
    # --------------------------------------------------------------------------------
    qppb_map.clear()
    dscp_map[r1_lo_key] = c_ubyte(af21_tag)
    dscp_map[r3_lo_key] = c_ubyte(af12_tag)
    found, _ = _tcpdump(af12_tag)
    assert not found, "LPM misbehaviour, markings not expected after clearing dscp map"

    # breakpoint()
    # bpf_print_trace(bpf)
    # Cleanup the initialized resources:
    bpf.remove_xdp(b"r2-r1-eth0")
    dscp_map.clear()
    # --------------------------------------------------------------------------------
    """
     TBD/XXX: Implement test logic to verify stats tracking using one of these

     There is a range of utilities that can be used to interact with XDP/BPF
     Implement an example of using some of these, for the illustration purposes
         bpftool | tool for interacting with BPF mappings
        xdp-dump | tool for xdp troubleshooting, i.e. collecting stats for packets
       xdp_stats | a minimal packet tracking tool from the tutorial
        ip-route | attaching the XDP hook
           ip-tc | attaching the SCH hook
    """

# @pytest.mark.skip
def test_qppb_match_all_map(tgen):
    """
    Minimal match all map + redistributio example
    """
    global R2_MINIMAL_QPPB_MAP
    result = create_route_maps(tgen, R2_MINIMAL_QPPB_MAP)
    assert result is True, "Minimal QPPB map failed\n Error: {}".format(result)

    r2 = tgen.gears["r2"]
    init_qppb_plugin(tgen, r2, SET_QPPB_TABLE_MAP)

    nhFile = "{}/bgp_ipv4_nh.ref".format(CWD)
    expected = open(nhFile).read().rstrip()
    expected = ("\n".join(expected.splitlines()) + "\n").rstrip()

    def check_dscp_displayed():
        actual = r2.vtysh_cmd("show bgp ipv4 1.0.3.17")
        actual = ("\n".join(actual.splitlines()) + "\n").rstrip()
        actual = re.sub(r" version [0-9]+", " version XX", actual)
        actual = re.sub(r"Last update: .*", "Last update: XXXX", actual)
        return topotest.get_textdiff(
            actual,
            expected,
            title1="Actual bgp nh show",
            title2="Expected bgp nh show",
        )

    ok, result = topotest.run_and_expect(check_dscp_displayed, "", count=5, wait=1)
    assert ok, result
    # breakpoint()
    # -----------------------------------------------------------------------------------


def setup_test_hosts(tgen, router):
    """
    Iface:     10.0.0.100/28
    HostMin:   10.0.0.97
    HostMax:   10.0.0.110
    """
    h1 = tgen.add_host("h1", "10.0.0.101/28", "dev h1-eth0")
    h2 = tgen.add_host("h2", "10.0.0.102/28", "dev h2-eth0")

    switch = tgen.add_switch("sw1")
    switch.add_link(router)
    switch.add_link(h1)
    switch.add_link(h2)

    ip_cmd = "ip addr add {} {}"
    router.run(ip_cmd.format("10.0.0.100/28", "dev " + router.name + "-eth0"))
    # XXX, extra args are configured only after call to topo_start (?) ;(
    h1.run(ip_cmd.format(h1.params['ip'], h1.params['defaultRoute']))
    h2.run(ip_cmd.format(h2.params['ip'], h2.params['defaultRoute']))


@pytest.mark.skip
def test_single_router(tgen):
    """

    Statically configure prioritized routes without redistribution
    Prioritize connection for the loopback?
    Can you force initialize 
    """
    global R2_NS
    setns(R2_NS)

    r2 = tgen.gears["r2"]
    # r2.link_enable("r2-r1-eth0", False)
    # r2.link_enable("r2-r3-eth1", False)
    setup_test_hosts(tgen, r2)

    bpf = r2.bpf
    tc_fn = bpf.funcs[b"xdp_tc_mark"]
    qppb_fn = bpf.funcs[b"xdp_qppb"]
    qppb_map = bpf[b"qppb_mode_map"]
    dscp_map = bpf[b"dscp_map"]

    r2_eth0_idx = c_uint(interface_to_ifindex(r2, "r2-r1-eth0"))
    r2_eth0_idx = c_uint(interface_to_ifindex(r2, "r2-eth0"))

    global R2_MINIMAL_QPPB_MAP
    result = create_route_maps(tgen, R2_MINIMAL_QPPB_MAP)
    assert result is True, "Minimal QPPB map failed\n Error: {}".format(result)
    init_qppb_plugin(tgen, r2, SET_QPPB_TABLE_MAP)

"""
    The original idea was to force to advertise, therefore initiating QPPB initalization
    from the device itself. Although, looks like route-table doesn't work on routes
    advertised with `network` command.

    TODO: Instead, later I will convert this to 1 router + exa-bgp,
          unless I can figure out the original idea imple
---------------------------------------------------------------------------------------------------------
    input_dict_1 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "advertise_networks": [
                                    {"network": "20.0.0.0/32", "no_of_network": 10},
                                    {"network": "30.0.0.0/32", "no_of_network": 10},
                                    ]
                                }
                            }
                        }
                    },
            }
    }


    # result = create_router_bgp(tgen, topo, input_dict_1)
    # assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)
    # breakpoint()
"""

    # --------------------------------------------------------------------------------------------------------- 
    # r2.link_enable("r2-r1-eth0", True)
    # r2.link_enable("r2-r3-eth1", True)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))



@pytest.mark.skip
def test_tc_setup(tgen):
    """
    - setup iproute tc tree
    - limit bandwidth per interface
    - load xdp for r2
    - run list of iperf helpers
    - verify traffic bandwidth within used limits
    """

    global app_helper
    app_helper = IPerfHelper(tgen)
    breakpoint()


# XXX,TBD: need someone to explain how common this would
# XXX: likely, there will be many ways to acidentally leak traffic (;
@pytest.mark.skip
def test_xdp_overlap(tgen):
    """
    Scenario: assume eth2 is the ingress iface:
    1. Route announced from neighbour + associated dscp mapping
        bgp> ip route add 1.0.0.0/24 dev eth0   =>   dscp af22
    2. A more specific static route installed by `admin` from CLI
       I.e. for temporary debugging sessions, etc ...
         sh> ip route add 1.0.1.0/25 dev eth1   =>   None

    Problem: Traffic matching a more specific prefix will get tagged
    by a marking from the lesser one
    1. Send ping to 1.0.3.17 /24 => af22, traffic is tagged by /24 route
    2. Send ping to 1.0.1.17 /25 => af22, still tagged by /24 route,
       although it will use different egress iface / attached TC hooks
       The associated tag may affect packet processing unexpectedly
    """

    pass

