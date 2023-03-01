.. SPDX-License-Identifier: GPL-2.0-only

=====================
PSP Security Protocol
=====================

Expected initial state
======================

- no versions enabled
- device MKs are in unknown state, but can't be all-zero if can be used
- user space has to rotate to invalidate old keys

- enabled algos are primarily for Rx

Operation
=========

- rx-assoc:
  - create key
  - put it on the socket
  - socket state: RX_READY
[Rx PSP packet which moves RCV.NXT]
  - socket state: RX_SEALED
- tx-assoc:
  - add Tx key
  - socket state: SEALED

States
======

 - RX_READY
   - Tx all clear text
   - Rx clear text okay
   - Rx PSP act
 - RX_SEALED
   - Tx all clear text
   - Rx all PSP
 - SEALED
   - Tx PSP
   - Rx PSP

We prevent rtx of clear text data by marking packets as decrypted
during enqueue. Device will only act on skbs with decrypted set.
