#!/usr/bin/env python
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import json
import fcntl
import pprint
import time
import termios
import struct
import socket

from lib import YnlFamily


def test1(ynl):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

    devices = ynl.dev_get({}, dump=True)
    print("# Devices:")
    pprint.PrettyPrinter().pprint(devices)
    dev = devices[0]
    print()

    print("# Rx assoc:")
    rx_assoc = ynl.rx_assoc({"version": 0, "dev-id": dev['id'], "sock-fd": s.fileno()})
    pprint.PrettyPrinter().pprint(rx_assoc)
    print()

    assoc = ynl.tx_assoc({"dev-id": dev['id'],
                          "version": 0,
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


def spi_xchg(s, rx):
    s.send(struct.pack('I', rx['spi']) + rx['key'])
    tx = s.recv(4 + len(rx['key']))
    return {
        'spi': struct.unpack('I', tx[:4])[0],
        'key': tx[4:]
    }


def test2(ynl):
    devices = ynl.dev_get({}, dump=True)
    dev = devices[0]

    serv = socket.create_server(("", 1234), family=socket.AF_INET6, backlog=5,
                                reuse_port=True, dualstack_ipv6=False)
    while True:
        (s, _) = serv.accept()

        rx_assoc = ynl.rx_assoc({"version": 0, "dev-id": dev['id'], "sock-fd": s.fileno()})
        rx = rx_assoc['rx-key']
        print('Local SPI:', rx['spi'], 'key:', rx['key'])

        tx = spi_xchg(s, rx)
        print('Remote SPI:', tx['spi'], 'key:', tx['key'])

        assoc = ynl.tx_assoc({"dev-id": dev['id'],
                              "version": 0,
                              "tx-key": tx,
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

    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.connect(("db01::1:2", 1234))

    rx_assoc = ynl.rx_assoc({"version": 0, "dev-id": dev['id'], "sock-fd": s.fileno()})
    rx = rx_assoc['rx-key']
    print('Local SPI:', rx['spi'], 'key:', rx['key'])

    tx = spi_xchg(s, rx)
    print('Remote SPI:', tx['spi'], 'key:', tx['key'])

    assoc = ynl.tx_assoc({"dev-id": dev['id'],
                          "version": 0,
                          "tx-key": tx,
                          "sock-fd": s.fileno()})

    for i in range(100):
        print(i, s.send(b'0123456789' * 200), end='\r')
    print("Sent", (i + 1) * 2000)


def test4(ynl):
    devices = ynl.dev_get({}, dump=True)
    dev = devices[1]

    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.connect(("db01::1:2", 1234))

    rx_assoc = ynl.rx_assoc({"version": 0, "dev-id": dev['id'], "sock-fd": s.fileno()})
    rx = rx_assoc['rx-key']
    print('Local SPI:', rx['spi'], 'key:', rx['key'])

    tx = spi_xchg(s, rx)
    print('Remote SPI:', tx['spi'], 'key:', tx['key'])

    assoc = ynl.tx_assoc({"dev-id": dev['id'],
                          "version": 0,
                          "tx-key": tx,
                          "sock-fd": s.fileno()})

    print("Queued", s.send(b'0123456789' * 200))
    one = b'\0' * 4
    for i in range(5):
        data = fcntl.ioctl(s.fileno(), termios.TIOCOUTQ, one)
        outq = struct.unpack("I", data)[0]
        if outq != 2000:
            raise Exception(f"Data got out: {outq}")
        time.sleep(0.1)
    s.close()


def test5(ynl):
    devices = ynl.dev_get({}, dump=True)
    dev = devices[0]

    prev_stale = ynl.get_stats({'dev-id': dev['id']})['stale-events']

    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.connect(("db01::1:2", 1234))

    rx_assoc = ynl.rx_assoc({"version": 0, "dev-id": dev['id'], "sock-fd": s.fileno()})
    rx = rx_assoc['rx-key']
    print('Local SPI:', rx['spi'], 'key:', rx['key'])

    tx = spi_xchg(s, rx)
    print('Remote SPI:', tx['spi'], 'key:', tx['key'])

    assoc = ynl.tx_assoc({"dev-id": dev['id'],
                          "version": 0,
                          "tx-key": tx,
                          "sock-fd": s.fileno()})

    for i in range(100):
        print(i, s.send(b'0123456789' * 200), end='\r')
    print("Sent", (i + 1) * 2000)

    # Wait to flush
    one = b'\0' * 4
    for i in range(50):
        data = fcntl.ioctl(s.fileno(), termios.TIOCOUTQ, one)
        outq = struct.unpack("I", data)[0]
        if outq == 0:
            break
        time.sleep(0.01)

    print("# Rotate (x2):")
    rot = ynl.key_rotate({"id": dev['id']})
    pprint.PrettyPrinter().pprint(rot)
    rot = ynl.key_rotate({"id": dev['id']})
    pprint.PrettyPrinter().pprint(rot)

    cur_stale = ynl.get_stats({'dev-id': dev['id']})['stale-events']
    if cur_stale == prev_stale:
        raise Exception(f"Stale socket stat did not change: {prev_stale}")

    print("Queued", s.send(b'0123456789' * 200))
    one = b'\0' * 4
    for i in range(5):
        data = fcntl.ioctl(s.fileno(), termios.TIOCOUTQ, one)
        outq = struct.unpack("I", data)[0]
        if outq != 2000:
            raise Exception(f"Data got out: {outq}")
        time.sleep(0.1)

    s.close()


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
    elif args.test == 4:
        test4(ynl)
    elif args.test == 5:
        test5(ynl)

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
