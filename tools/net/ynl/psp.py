#!/usr/bin/env python
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import json
import pprint
import time
import struct
import socket

from lib import YnlFamily


def test1(ynl):
    devices = ynl.dev_get({}, dump=True)
    print("# Devices:")
    pprint.PrettyPrinter().pprint(devices)
    dev = devices[0]
    print()

    rx_assoc = ynl.rx_assoc_alloc({"version": 0, "dev-id": dev['id']})
    print("# Rx assoc:")
    pprint.PrettyPrinter().pprint(rx_assoc)
    print()

    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

    assoc = ynl.assoc_add({"dev-id": dev['id'],
                           "version": 0,
                           "rx-key": rx_assoc['rx-key'],
                           "tx-key": rx_assoc['rx-key'],
                           "sock-fd": s.fileno()})
    print("# Assoc reply:")
    pprint.PrettyPrinter().pprint(assoc)
    print()

    print("# Rotate replies (x2):")
    rot = ynl.key_rotate({"id": dev['id']})
    pprint.PrettyPrinter().pprint(rot)
    rot = ynl.key_rotate({"id": dev['id']})
    pprint.PrettyPrinter().pprint(rot)
    print()


def spi_xchg(s, rx_spi):
    s.send(struct.pack('I', rx_spi))
    return struct.unpack('I', s.recv(4))[0]


def test2(ynl):
    devices = ynl.dev_get({}, dump=True)
    dev = devices[0]

    rx_assoc = ynl.rx_assoc_alloc({"version": 0, "dev-id": dev['id']})
    rx_spi = rx_assoc['rx-key']['spi']
    print('Local SPI:', rx_spi)

    serv = socket.create_server(("", 1234), family=socket.AF_INET6, backlog=5,
                                reuse_port=True, dualstack_ipv6=False)
    while True:
        (s, _) = serv.accept()

        tx_spi = spi_xchg(s, rx_spi)
        print('Remote SPI:', tx_spi)

        assoc = ynl.assoc_add({"dev-id": dev['id'],
                               "version": 0,
                               "rx-key": rx_assoc['rx-key'],
                               "tx-key": {'key': rx_assoc['rx-key']['key'],
                                          'spi': tx_spi},
                               "sock-fd": s.fileno()})

        cnt = 0
        while True:
            n = s.recv(10000)
            cnt += len(n)
            if not n:
                break
            print('Received', cnt, end='\r')
        print()


def test3(ynl):
    devices = ynl.dev_get({}, dump=True)
    dev = devices[0]

    rx_assoc = ynl.rx_assoc_alloc({"version": 0, "dev-id": dev['id']})
    print('Local SPI:', rx_assoc['rx-key']['spi'])

    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.connect(("db01::1:2", 1234))

    tx_spi = spi_xchg(s, rx_assoc['rx-key']['spi'])
    print('Remote SPI:', tx_spi)

    assoc = ynl.assoc_add({"dev-id": dev['id'],
                           "version": 0,
                           "rx-key": rx_assoc['rx-key'],
                           "tx-key": {'key': rx_assoc['rx-key']['key'],
                                      'spi': tx_spi},
                           "sock-fd": s.fileno()})

    for i in range(100):
        print(i, s.send(b'0123456789' * 200), end='\r')
    print("Sent", (i + 1) * 2000)


def main():
    parser = argparse.ArgumentParser(description='YNL sample')
    parser.add_argument('--spec', dest='spec', type=str, default='psp.yaml')
    parser.add_argument('--schema', dest='schema', type=str)
    parser.add_argument('--no-schema', action='store_true')
    parser.add_argument('--json', dest='json_text', type=str)
    parser.add_argument('--do', dest='do', type=str)
    parser.add_argument('--dump', dest='dump', type=str)
    parser.add_argument('--sleep', dest='sleep', type=int)
    parser.add_argument('--subscribe', dest='ntf', type=str)
    parser.add_argument('--test', dest='test', type=int)
    args = parser.parse_args()

    if args.no_schema:
        args.schema = ''

    attrs = {}
    if args.json_text:
        attrs = json.loads(args.json_text)

    ynl = YnlFamily(args.spec, args.schema)

    if args.test == 1:
        test1(ynl)
    elif args.test == 2:
        test2(ynl)
    elif args.test == 3:
        test3(ynl)

    if args.ntf:
        ynl.ntf_subscribe(args.ntf)

    if args.sleep:
        time.sleep(args.sleep)

    if args.do or args.dump:
        method = getattr(ynl, args.do if args.do else args.dump)

        reply = method(attrs, dump=bool(args.dump))
        pprint.PrettyPrinter().pprint(reply)

    if args.ntf:
        ynl.check_ntf()
        pprint.PrettyPrinter().pprint(ynl.async_msg_queue)


if __name__ == "__main__":
    main()
