# SPDX-License-Identifier: GPL-2.0

TEST_INCLUDES := $(wildcard lib/py/*.py) \
		 $(wildcard lib/sh/*.sh) \
		 ../../net/net_helper.sh \
		 ../../net/lib.sh \

TEST_PROGS := \
	netcons_basic.sh \
	netcons_overflow.sh \
	ping.py \
	psp.py \
	queues.py \
	stats.py \
	shaper.py \
	hds.py \
# end of TEST_PROGS

# YNL files, must be before "include ..lib.mk"
EXTRA_CLEAN += $(OUTPUT)/libynl.a
YNL_GEN_FILES := psp_responder
TEST_GEN_FILES += $(YNL_GEN_FILES)

include ../../lib.mk

# YNL build
YNL_GENS := psp

include ../../net/ynl.mk
