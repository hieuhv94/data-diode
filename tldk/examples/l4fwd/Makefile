# Copyright (c) 2016 Intel Corporation.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

ifeq ($(RTE_TARGET),)
$(error "Please define RTE_TARGET environment variable")
endif

ifeq ($(TLDK_ROOT),)
$(error "Please define TLDK_ROOT environment variable")
endif

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = l4fwd

# all source are stored in SRCS-y
SRCS-y += parse.c
SRCS-y += pkt.c
SRCS-y += main.c

CFLAGS += -DNETFE_DEBUG
CFLAGS += $(WERROR_FLAGS) 
CFLAGS += -I$(RTE_OUTPUT)/include

LDLIBS += -L$(RTE_OUTPUT)/lib
LDLIBS += -ltle_l4p
LDLIBS += -ltle_memtank
LDLIBS += -ltle_timer

EXTRA_CFLAGS += -O3
CFLAGS_parse.o += -D_GNU_SOURCE
CFLAGS_main.o += -D_GNU_SOURCE

include $(TLDK_ROOT)/mk/tle.app.mk
