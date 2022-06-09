#!/usr/bin/python3
import pprint
import grpc

import frr_northbound_pb2 as frr_nb
import frr_northbound_pb2_grpc as frr_nb_grpc

from libyang import Context
from libyang import LibyangError
from libyang.data import DNode

YANG_SEACH_PATH = "/usr/share/yang"
# FRR_GRPC_ADDR =  "127.0.0.1:50051"
FRR_GRPC_ADDR =  "172.17.0.2:50051"
CHUNK_SIZE = 30

# TODO: add error handling
def get_data(ctx, path):
    # connect to FRR

    with grpc.insecure_channel(FRR_GRPC_ADDR) as channel:
        stub = frr_nb_grpc.NorthboundStub(channel)
        dnode = None
        offset = None

        while True:
            # get data chunk
            stream = stub.Get(frr_nb.GetRequest(type='STATE',
                                                encoding='JSON',
                                                path=path,
                                                chunk_size=CHUNK_SIZE,
                                                offset=offset))
            # use "next" since FRR will send a single response instead of an
            # actual stream of responses. In the future we should have separate
            # unary and streaming RPCs to fetch YANG-modeled state data.
            response = next(stream)

            # parse data chunk
            # import pdb; pdb.set_trace()
            chunk = ctx.parse_data_mem(response.data.data, 'json') #, get=True)

            # merge chunk into final data tree
            if dnode:
                dnode.merge(chunk, destruct=True)
            else:
                dnode = chunk

            # proceed to the next data chunk
            offset = response.offset
            if not offset:
                return dnode

def main():
    # setup libyang
    ctx = Context(YANG_SEACH_PATH)
    # import pdb; pdb.set_trace()
    mod = ctx.load_module('frr-zebra')

    # get RIB information from FRR, convert it to a dictionary and display it
    ribs = get_data(ctx, "/frr-vrf:lib/vrf[name='default']/frr-zebra:zebra/ribs")
    # ribs = get_data(ctx, "/frr-interface:lib")
    pprint.pprint(ribs.print_dict())
    ribs.free()

    # libyang teardown
    ctx.destroy()

if __name__ == "__main__":
    main()
