/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef _LIB_PSP_DEFS_H
#define _LIB_PSP_DEFS_H

/*  PSP Security Payload (PSP) Header
 *
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Next Header  |  Hdr Ext Len  |  Crypt Offset | R |Version|V|1|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                Security Parameters Index (SPI)                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                  Initialization Vector (IV)                   +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                Virtualization Key (VK) [Optional]             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                  Pad to 8*N bytes [if needed]                 |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/* total length of headers for PSP encapsulation (UDP + PSP) */
#define PSP_ENCAP_HLEN (sizeof(struct udphdr) + sizeof(struct psphdr))

#endif  /* _LIB_PSP_DEFS_H */
