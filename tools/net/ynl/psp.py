#!/usr/bin/env python
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import json
import pprint
import time
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


def main():
    parser = argparse.ArgumentParser(description='YNL sample')
    parser.add_argument('--spec', dest='spec', type=str, default='psp.yaml')
    parser.add_argument('--schema', dest='schema', type=str)
    parser.add_argument('--json', dest='json_text', type=str)
    parser.add_argument('--do', dest='do', type=str)
    parser.add_argument('--dump', dest='dump', type=str)
    parser.add_argument('--sleep', dest='sleep', type=int)
    parser.add_argument('--subscribe', dest='ntf', type=str)
    parser.add_argument('--test', dest='test', type=str)
    args = parser.parse_args()

    attrs = {}
    if args.json_text:
        attrs = json.loads(args.json_text)

    ynl = YnlFamily(args.spec, args.schema)

    if args.test is not None:
        test1(ynl)

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
