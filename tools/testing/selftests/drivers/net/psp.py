#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

from lib.py import ksft_run, ksft_exit
from lib.py import ksft_true, ksft_eq
from lib.py import NetDrvEpEnv, PSPFamily, NlError

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

        ksft_run(globs=globals(), case_pfx={"dev_"},
                 args=(cfg, ), skip_all=(cfg.psp_dev_id is None))

        if versions is not None:
            cfg.pspnl.dev_set({"id": cfg.psp_dev_id, "psp-versions-ena": versions})
    ksft_exit()


if __name__ == "__main__":
    main()
