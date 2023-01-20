# import os
# import subprocess

from ctypes import Structure, c_int, c_uint, c_ubyte
from bcc import (
    DEBUG_PREPROCESSOR,
    DEBUG_SOURCE,
    DEBUG_BPF,
    DEBUG_BTF,
    BPF,
)
import bcc
import sys
import os

from lib import topotest
from lib.topolog import logger
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import (
    kill_router_daemons,
    start_router_daemons,
    start_router,
    stop_router
)
from lib.bgp import (
    clear_bgp_and_verify,
    clear_bgp,
)


CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

class KeyV4(Structure):
    _fields_ = [("prefixlen", c_uint),
                ("data", c_ubyte * 4)]

BGP_POLICY_NONE = c_int(0)
BGP_POLICY_DST = c_int(1)
BGP_POLICY_SRC = c_int(2)

def init_qppb_plugin(tgen, rnode, vtysh_cmd=None, setup=False, debug_enabled=True):
    DEBUG_FLAGS = DEBUG_BPF | DEBUG_PREPROCESSOR | DEBUG_SOURCE | DEBUG_BTF
    cflags = [
        "-DMARK_CLASSID", "-DDEBUG_LOG", "-DMARK_SKB", "-w",
        '-DBPF_PIN_DIR="{}"'.format(rnode.bpfdir)
    ]
    src_file = CWD + "/xdp_qppb.c"

    if setup:
        try:
            debug = DEBUG_FLAGS if debug_enabled else 0
            logger.info("Preparing the XDP setup: " + src_file)
            b = BPF(src_file=src_file.encode(), cflags=cflags, debug=debug)

            logger.info("Loading XDP hooks -- xdp_qppb, xdp_tc_mark")
            b.load_func(b"xdp_qppb", BPF.XDP)
            b.load_func(b"xdp_tc_mark", BPF.SCHED_CLS)
            rnode.bpf = b
        except Exception as e:
            logger.error("Failed to compile QPPB handlers -- \n%s", str(e))
            pytest.skip("Failed to configure XDP environment -- \n%s", str(e))

    qppb_module = "-M vyos_qppb:" + rnode.bpfdir
    logger.info("Restart {}, XDP hooks loading...\nPlugin args:: {}".format(rnode.name, qppb_module))
    kill_router_daemons(tgen, rnode.name, ["bgpd"])
    start_router_daemons(tgen, rnode.name, ["bgpd"], {"bgpd":qppb_module})
    if vtysh_cmd:
        rnode.vtysh_cmd(vtysh_cmd)


# Adopted from: ipmininet/tests/test_tc.py
def assert_bw(topo, src, dst, bw_target, tolerance=1):
    """
        bw_target: MB/s
    """
    dst_ip = topo["routers"][dst.name]["links"][src.name]["ipv4"].split("/")[0]
    server = dst.popen(["iperf3", "-s", "-J", "--one-off"], universal_newlines=True)
    client = src.popen(["iperf3", "-c", dst_ip], stdin=None, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # breakpoint()
    out, err = server.communicate()
    assert server.poll() == 0, "Cannot use iperf3 server between {} and {}: " \
                              "{}".format(src.name, dst.name, err)

    bws = []
    data = json.loads(out)
    for sample in data["intervals"]:
        # average rate in MB/s
        # <= bw_target + tolerance:
        bw = int(sample["sum"]["bits_per_second"]) / 8 / 1024 / 1024
        if bw_target - tolerance <= bw:
            bws.append(bw)
    assert len(bws) >= 5, \
        "Less than half of the packets between {} and {}" \
        " had the desired bandwidth".format(src.name, dst.name)
    # breakpoint()


# XXX: Call this from debugger, to avoid Ctrl+C collisions
def bpf_print_trace(b):
    try:
        b.trace_print()
    except KeyboardInterrupt:
        pass

