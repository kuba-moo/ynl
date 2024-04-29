#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

import fcntl
import socket
import struct
import termios
import time

from lib.py import ksft_run, ksft_exit, ksft_pr
from lib.py import ksft_true, ksft_eq, ksft_ne, ksft_gt, ksft_raises, KsftSkipEx
from lib.py import NetDrvEpEnv, PSPFamily, NlError
from lib.py import bkg, cmd, rand_port, wait_port_listen


class PSPExceptShortIO(Exception):
    pass


def _get_outq(s):
    one = b'\0' * 4
    outq = fcntl.ioctl(s.fileno(), termios.TIOCOUTQ, one)
    return struct.unpack("I", outq)[0]


def _send_with_ack(cfg, msg):
    cfg.comm_sock.send(msg)
    response = cfg.comm_sock.recv(4)
    if response != b'ack\0':
        raise Exception("Unexpected server response", response)


def _remote_read_len(cfg):
    cfg.comm_sock.send(b'read len\0')
    return int(cfg.comm_sock.recv(1024)[:-1].decode('utf-8'))


def _make_clr_conn(cfg):
    _send_with_ack(cfg, b'conn clr\0')
    s = socket.create_connection((cfg.remote_addr, cfg.comm_port), )
    return s


def _make_psp_conn(cfg, version=0):
    _send_with_ack(cfg, b'conn psp\0' + struct.pack('BB', version, version))
    s = socket.create_connection((cfg.remote_addr, cfg.comm_port), )
    return s


def _close_conn(cfg, s):
    _send_with_ack(cfg, b'data close\0')
    s.close()


def _close_psp_conn(cfg, s):
    _close_conn(cfg, s)


def _spi_xchg(s, rx):
    s.send(struct.pack('I', rx['spi']) + rx['key'])
    tx = s.recv(4 + len(rx['key']))
    return {
        'spi': struct.unpack('I', tx[:4])[0],
        'key': tx[4:]
    }


def _send_careful(cfg, s, rounds):
    data = b'0123456789' * 200
    for i in range(rounds):
        n = 0
        retries = 0
        while True:
            try:
                n += s.send(data[n:], socket.MSG_DONTWAIT)
                if n == len(data):
                    break
            except BlockingIOError:
                time.sleep(0.05)

            retries += 1
            if retries > 10:
                rlen = _remote_read_len(cfg)
                outq = _get_outq(s)
                report = f'sent: {i * len(data) + n} remote len: {rlen} outq: {outq}'
                if retries > 10:
                    raise Exception(report)

    return len(data) * rounds


def _recv_careful(cfg, s, target, rounds=100):
    data = b''
    for i in range(rounds):
        try:
            data += s.recv(target - len(data), socket.MSG_DONTWAIT)
            if len(data) == target:
                return data
        except BlockingIOError:
            time.sleep(0.001)
    raise PSPExceptShortIO(target, len(data), data)


def _check_data_rx(cfg, exp_len):
    read_len = -1
    for i in range(30):
        cfg.comm_sock.send(b'read len\0')
        read_len = int(cfg.comm_sock.recv(1024)[:-1].decode('utf-8'))
        if read_len == exp_len:
            break
        time.sleep(0.01)
    ksft_eq(read_len, exp_len)


def _check_data_outq(s, exp_len, force_wait=False):
    outq = 0
    for i in range(10):
        outq = _get_outq(s)
        if not force_wait and outq == exp_len:
            break
        time.sleep(0.01)
    ksft_eq(outq, exp_len)


def _get_stat(cfg, key):
    return cfg.pspnl.get_stats({'dev-id': cfg.psp_dev_id})[key]


def _req_echo(cfg, s, expect_fail=False):
    _send_with_ack(cfg, b'data echo\0')
    try:
        _recv_careful(cfg, s, 5)
        if expect_fail:
            raise Exception("Received unexpected echo reply")
    except PSPExceptShortIO:
            if not expect_fail:
                raise

#
# Test cases
#

def dev_list_devices(cfg):
    """ Dump all devices """
    devices = cfg.pspnl.dev_get({}, dump=True)

    found = False
    for dev in devices:
        found |= dev['id'] == cfg.psp_dev_id
    ksft_true(found)


def dev_get_device(cfg):
    """ Get the device we intend to use """
    dev = cfg.pspnl.dev_get({'id': cfg.psp_dev_id})
    ksft_eq(dev['id'], cfg.psp_dev_id)


def dev_get_device_bad(cfg):
    """ Test getting device which doesn't exist """
    raised = False
    try:
        cfg.pspnl.dev_get({'id': cfg.psp_dev_id + 1234567})
    except NlError as e:
        ksft_eq(e.nl_msg.error, -19)
        raised = True
    ksft_true(raised)


def dev_rotate(cfg):
    """ Test key rotation """
    rot = cfg.pspnl.key_rotate({"id": cfg.psp_dev_id})
    ksft_eq(rot['id'], cfg.psp_dev_id)
    rot = cfg.pspnl.key_rotate({"id": cfg.psp_dev_id})
    ksft_eq(rot['id'], cfg.psp_dev_id)


def dev_rotate_spi(cfg):
    """ Test key rotation and SPI check """
    topA = topB = 0
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        assocA = cfg.pspnl.rx_assoc({"version": 0,
                                     "dev-id": cfg.psp_dev_id,
                                     "sock-fd": s.fileno()})
        topA = assocA['rx-key']['spi'] >> 31
        s.close()
    rot = cfg.pspnl.key_rotate({"id": cfg.psp_dev_id})
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        ksft_eq(rot['id'], cfg.psp_dev_id)
        assocB = cfg.pspnl.rx_assoc({"version": 0,
                                    "dev-id": cfg.psp_dev_id,
                                    "sock-fd": s.fileno()})
        topB = assocB['rx-key']['spi'] >> 31
        s.close()
    ksft_ne(topA, topB)


def assoc_basic(cfg):
    """ Test creating associations """
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        assoc = cfg.pspnl.rx_assoc({"version": 0,
                                  "dev-id": cfg.psp_dev_id,
                                  "sock-fd": s.fileno()})
        ksft_eq(assoc['version'], 'hdr0-aes-gcm-128')
        ksft_eq(assoc['dev-id'], cfg.psp_dev_id)
        ksft_gt(assoc['rx-key']['spi'], 0)
        ksft_eq(len(assoc['rx-key']['key']), 16)

        assoc = cfg.pspnl.tx_assoc({"dev-id": cfg.psp_dev_id,
                                  "version": 0,
                                  "tx-key": assoc['rx-key'],
                                  "sock-fd": s.fileno()})
        ksft_eq(len(assoc), 0)
        s.close()


def assoc_bad_dev(cfg):
    """ Test creating associations with bad device ID """
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        with ksft_raises(NlError) as cm:
            cfg.pspnl.rx_assoc({"version": 0,
                              "dev-id": cfg.psp_dev_id + 1234567,
                              "sock-fd": s.fileno()})
        ksft_eq(cm.exception.nl_msg.error, -19)


def assoc_sk_only_conn(cfg):
    """ Test creating associations based on socket """
    with _make_clr_conn(cfg) as s:
        assoc = cfg.pspnl.rx_assoc({"version": 0,
                                  "sock-fd": s.fileno()})
        ksft_eq(assoc['dev-id'], cfg.psp_dev_id)
        cfg.pspnl.tx_assoc({"version": 0,
                          "tx-key": assoc['rx-key'],
                          "sock-fd": s.fileno()})
        _close_conn(cfg, s)


def assoc_sk_only_mismatch(cfg):
    """ Test creating associations based on socket (dev mismatch) """
    with _make_clr_conn(cfg) as s:
        with ksft_raises(NlError) as cm:
            cfg.pspnl.rx_assoc({"version": 0,
                              "dev-id": cfg.psp_dev_id + 1234567,
                              "sock-fd": s.fileno()})
        the_exception = cm.exception
        ksft_eq(the_exception.nl_msg.extack['bad-attr'], ".dev-id")
        ksft_eq(the_exception.nl_msg.error, -22)


def assoc_sk_only_mismatch_tx(cfg):
    """ Test creating associations based on socket (dev mismatch) """
    with _make_clr_conn(cfg) as s:
        with ksft_raises(NlError) as cm:
            assoc = cfg.pspnl.rx_assoc({"version": 0,
                                      "sock-fd": s.fileno()})
            cfg.pspnl.tx_assoc({"version": 0,
                              "tx-key": assoc['rx-key'],
                              "dev-id": cfg.psp_dev_id + 1234567,
                              "sock-fd": s.fileno()})
        the_exception = cm.exception
        ksft_eq(the_exception.nl_msg.extack['bad-attr'], ".dev-id")
        ksft_eq(the_exception.nl_msg.error, -22)


def assoc_sk_only_unconn(cfg):
    """ Test creating associations based on socket (unconnected, should fail) """
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        with ksft_raises(NlError) as cm:
            cfg.pspnl.rx_assoc({"version": 0,
                              "sock-fd": s.fileno()})
        the_exception = cm.exception
        ksft_eq(the_exception.nl_msg.extack['miss-type'], "dev-id")
        ksft_eq(the_exception.nl_msg.error, -22)


def assoc_version_mismatch(cfg):
    """ Test creating associations where Rx and Tx PSP versions do not match """
    versions = list(cfg.psp_supported_versions)
    if len(versions) < 2:
        raise KsftSkipEx("Not enough PSP versions supported by the device for the test")

    # Translate versions to integers
    versions = [cfg.pspnl.consts["version"].entries[v].value for v in versions]

    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        rx = cfg.pspnl.rx_assoc({"version": versions[0],
                                 "dev-id": cfg.psp_dev_id,
                                 "sock-fd": s.fileno()})

        for version in versions[1:]:
            with ksft_raises(NlError) as cm:
                cfg.pspnl.tx_assoc({"dev-id": cfg.psp_dev_id,
                                    "version": version,
                                    "tx-key": rx['rx-key'],
                                    "sock-fd": s.fileno()})
            the_exception = cm.exception
            ksft_eq(the_exception.nl_msg.error, -22)


def assoc_twice(cfg):
    """ Test reusing Tx assoc for two sockets """
    def rx_assoc_check(s):
        assoc = cfg.pspnl.rx_assoc({"version": 0,
                                  "dev-id": cfg.psp_dev_id,
                                  "sock-fd": s.fileno()})
        ksft_eq(assoc['version'], 'hdr0-aes-gcm-128')
        ksft_eq(assoc['dev-id'], cfg.psp_dev_id)
        ksft_gt(assoc['rx-key']['spi'], 0)
        ksft_eq(len(assoc['rx-key']['key']), 16)

        return assoc

    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        assoc = rx_assoc_check(s)
        tx = cfg.pspnl.tx_assoc({"dev-id": cfg.psp_dev_id,
                               "version": 0,
                               "tx-key": assoc['rx-key'],
                               "sock-fd": s.fileno()})
        ksft_eq(len(tx), 0)

        # Use the same Tx assoc second time
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s2:
            rx_assoc_check(s2)
            tx = cfg.pspnl.tx_assoc({"dev-id": cfg.psp_dev_id,
                                   "version": 0,
                                   "tx-key": assoc['rx-key'],
                                   "sock-fd": s2.fileno()})
            ksft_eq(len(tx), 0)

        s.close()


def data_basic_send(cfg, version=0):
    """ Test basic data send """
    # Version 0 is required by spec, don't let it skip
    if version:
        name = cfg.pspnl.consts["version"].entries_by_val[version].name
        if name not in cfg.psp_supported_versions:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
                with ksft_raises(NlError) as cm:
                    cfg.pspnl.rx_assoc({"version": version,
                                        "dev-id": cfg.psp_dev_id,
                                        "sock-fd": s.fileno()})
                ksft_eq(cm.exception.nl_msg.error, -95)
            raise KsftSkipEx("PSP version not supported", name)

    s = _make_psp_conn(cfg, version)

    rx_assoc = cfg.pspnl.rx_assoc({"version": version,
                                   "dev-id": cfg.psp_dev_id,
                                   "sock-fd": s.fileno()})
    rx = rx_assoc['rx-key']
    tx = _spi_xchg(s, rx)

    cfg.pspnl.tx_assoc({"dev-id": cfg.psp_dev_id,
                        "version": version,
                        "tx-key": tx,
                        "sock-fd": s.fileno()})

    data_len = _send_careful(cfg, s, 100)
    _check_data_rx(cfg, data_len)
    _close_psp_conn(cfg, s)


def data_basic_send_v1(cfg):
    data_basic_send(cfg, version=1)


def data_basic_send_v2(cfg):
    data_basic_send(cfg, version=2)


def data_basic_send_v3(cfg):
    data_basic_send(cfg, version=3)


def __bad_xfer_do(cfg, s, tx, version='hdr0-aes-gcm-128'):
    # Make sure we accept the ACK for the SPI before we seal with the bad assoc
    _check_data_outq(s, 0)

    cfg.pspnl.tx_assoc({"dev-id": cfg.psp_dev_id,
                        "version": version,
                        "tx-key": tx,
                        "sock-fd": s.fileno()})

    data_len = _send_careful(cfg, s, 20)
    _check_data_outq(s, data_len, force_wait=True)
    _check_data_rx(cfg, 0)
    _close_psp_conn(cfg, s)


def data_bad_version_send(cfg):
    """
    Test data transfer where we expect different version than is being used by peer
    """

    version = 'hdr0-aes-gmac-128'
    versions = list(cfg.psp_supported_versions & {'hdr0-aes-gcm-128', 'hdr0-aes-gmac-128'})
    if len(versions) < 2:
        raise KsftSkipEx("Not enough PSP versions supported by the device for the test")

    # Peer will use version 0 but we expect something higher
    s = _make_psp_conn(cfg)

    rx_assoc = cfg.pspnl.rx_assoc({"version": version,
                                   "dev-id": cfg.psp_dev_id,
                                   "sock-fd": s.fileno()})
    rx = rx_assoc['rx-key']
    tx = _spi_xchg(s, rx)

    __bad_xfer_do(cfg, s, tx, version=version)


def data_send_bad_key(cfg):
    """ Test send data with bad key """
    s = _make_psp_conn(cfg)

    rx_assoc = cfg.pspnl.rx_assoc({"version": 0,
                                   "dev-id": cfg.psp_dev_id,
                                   "sock-fd": s.fileno()})
    rx = rx_assoc['rx-key']
    tx = _spi_xchg(s, rx)
    tx['key'] = (tx['key'][0] ^ 0xff).to_bytes(1, 'little') + tx['key'][1:]
    __bad_xfer_do(cfg, s, tx)


def data_send_disconnect(cfg):
    with _make_psp_conn(cfg) as s:
        assoc = cfg.pspnl.rx_assoc({"version": 0,
                                  "sock-fd": s.fileno()})
        tx = _spi_xchg(s, assoc['rx-key'])
        cfg.pspnl.tx_assoc({"version": 0,
                          "tx-key": tx,
                          "sock-fd": s.fileno()})

        data_len = _send_careful(cfg, s, 100)
        _check_data_rx(cfg, data_len)

        s.shutdown(socket.SHUT_RDWR)
        s.close()


def data_mss_adjust(cfg):
    """ Test that kernel auto-adjusts MSS """

    # First figure out what the MSS would be without any adjustments
    s = _make_clr_conn(cfg)
    s.send(b"0123456789abcdef" * 1024)
    _check_data_rx(cfg, 16 * 1024)
    mss = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
    _close_conn(cfg, s)

    s = _make_psp_conn(cfg)
    try:
        rx_assoc = cfg.pspnl.rx_assoc({"version": 0,
                                     "dev-id": cfg.psp_dev_id,
                                     "sock-fd": s.fileno()})
        rx = rx_assoc['rx-key']
        tx = _spi_xchg(s, rx)

        rxmss = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
        ksft_eq(mss, rxmss)

        cfg.pspnl.tx_assoc({"dev-id": cfg.psp_dev_id,
                          "version": 0,
                          "tx-key": tx,
                          "sock-fd": s.fileno()})

        txmss = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
        ksft_eq(mss, txmss + 32)

        data_len = _send_careful(cfg, s, 100)
        _check_data_rx(cfg, data_len)
        _check_data_outq(s, 0)

        txmss = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
        ksft_eq(mss, txmss + 32)
    finally:
        _close_psp_conn(cfg, s)


def data_stale_key(cfg):
    """ Test send on a double-rotated key """

    prev_stale = _get_stat(cfg, 'stale-events')

    s = _make_psp_conn(cfg)
    try:
        rx_assoc = cfg.pspnl.rx_assoc({"version": 0,
                                     "dev-id": cfg.psp_dev_id,
                                     "sock-fd": s.fileno()})
        rx = rx_assoc['rx-key']
        tx = _spi_xchg(s, rx)

        cfg.pspnl.tx_assoc({"dev-id": cfg.psp_dev_id,
                          "version": 0,
                          "tx-key": tx,
                          "sock-fd": s.fileno()})

        data_len = _send_careful(cfg, s, 100)
        _check_data_rx(cfg, data_len)
        _check_data_outq(s, 0)

        rot = cfg.pspnl.key_rotate({"id": cfg.psp_dev_id})
        rot = cfg.pspnl.key_rotate({"id": cfg.psp_dev_id})

        cur_stale = _get_stat(cfg, 'stale-events')
        ksft_gt(cur_stale, prev_stale)

        n = s.send(b'0123456789' * 200)
        _check_data_outq(s, 2000, force_wait=True)
    finally:
        _close_psp_conn(cfg, s)


def data_send_off(cfg):
    """ Test data send when PSP is turned off """

    s = info = udps = None
    try:
        s = _make_psp_conn(cfg)

        rx_assoc = cfg.pspnl.rx_assoc({"version": 0,
                                     "sock-fd": s.fileno()})
        tx = _spi_xchg(s, rx_assoc['rx-key'])
        cfg.pspnl.tx_assoc({"version": 0,
                          "tx-key": tx,
                          "sock-fd": s.fileno()})

        _req_echo(cfg, s)

        info = cfg.pspnl.dev_get({"id": cfg.psp_dev_id})
        cfg.pspnl.dev_set({"id": cfg.psp_dev_id,
                         "psp-versions-ena": 0})

        # Try to catch the still-encapsulated PSP packets on a UDP socket
        udps = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        udps.bind(('::', 1000))
        wait_port_listen(1000, proto="udp")

        _req_echo(cfg, s, expect_fail=True)

        cfg.pspnl.dev_set({"id": cfg.psp_dev_id,
                         "psp-versions-ena": info['psp-versions-ena']})
        info = None
        # We need some more TCP RTOs so lots of rounds
        _recv_careful(cfg, s, 5, rounds=350)

        # Will raise BlockingIOError if there are no packets
        udps.recv(8192, socket.MSG_DONTWAIT)
    finally:
        if s:
            _close_psp_conn(cfg, s)
        if info:
            cfg.pspnl.dev_set({"id": cfg.psp_dev_id,
                             "psp-versions-ena": info['psp-versions-ena']})
        if udps:
            udps.close()


def main() -> None:
    with NetDrvEpEnv(__file__) as cfg:
        cfg.pspnl = PSPFamily()

        # Figure out which local device we are testing against
        cfg.psp_dev_id = None
        versions = None
        devs = [dev for dev in cfg.pspnl.dev_get({}, dump=True) if dev["ifindex"] == cfg.ifindex]
        if devs:
            info = devs[0]
            cfg.psp_dev_id = info['id']

            # Enable PSP if necessary
            if info['psp-versions-ena'] != info['psp-versions-cap']:
                versions = info['psp-versions-ena']
                cfg.pspnl.dev_set({"id": cfg.psp_dev_id,
                                   "psp-versions-ena": info['psp-versions-cap']})
            cfg.psp_supported_versions = info['psp-versions-cap']

        # Set up responder and communication sock
        responder = cfg.remote.deploy("psp_responder")

        cfg.comm_port = rand_port()
        try:
            with bkg(responder + f" -p {cfg.comm_port}", host=cfg.remote, exit_wait=True) as srv:
                wait_port_listen(cfg.comm_port, host=cfg.remote)

                cfg.comm_sock = socket.create_connection((cfg.remote_addr,
                                                          cfg.comm_port), timeout=1)

                ksft_run(globs=globals(), case_pfx={"dev_", "data_", "assoc_"},
                         args=(cfg, ), skip_all=(cfg.psp_dev_id is None))
                cfg.comm_sock.send(b"exit\0")
                cfg.comm_sock.close()

            if versions is not None:
                cfg.pspnl.dev_set({"id": cfg.psp_dev_id, "psp-versions-ena": versions})

        finally:
            if srv.stdout or srv.stderr:
                ksft_pr("")
                ksft_pr(f"Responder logs ({srv.ret}):")
            if srv.stdout:
                ksft_pr("STDOUT:\n#  " + srv.stdout.strip().replace("\n", "\n#  "))
            if srv.stderr:
                ksft_pr("STDERR:\n#  " + srv.stderr.strip().replace("\n", "\n#  "))
    ksft_exit()


if __name__ == "__main__":
    main()
