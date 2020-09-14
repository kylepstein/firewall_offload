# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

# binary name
APP = firewall_offload

ROOT_DIR ?= $(HOME)

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

include $(RTE_SDK)/mk/rte.vars.mk

INCLUDES += -I $(ROOT_DIR)/local/include \
	    -I /usr/include/c++/4.8.5 \
	    -I /usr/include/c++/4.8.5/aarch64-redhat-linux/ \
	    -I $(RTE_SDK)/daemon \
	    -I $(RTE_SDK)/daemon/include

CFLAGS += $(INCLUDES)
CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -O3 -g

LIBDIR := $(ROOT_DIR)/local/lib
LIB64DIR := $(ROOT_DIR)/local/lib64
GPR_LIB := $(LIBDIR)/libgpr.a
CHANNELZ_LIB := $(LIBDIR)/libgrpcpp_channelz.a
GRPCPP_LIB := $(LIBDIR)/libgrpc++.a
GRPC_LIB := $(LIBDIR)/libgrpc.a
PROTOBUF_LIB := $(LIB64DIR)/libprotobuf.a
CARES_LIB := $(LIB64DIR)/libcares.a
REFLECTION_LIB := $(LIBDIR)/libgrpc++_reflection.a
UPB_LIB := $(LIBDIR)/libupb.a
ABSL_BASE_LIB := $(LIBDIR)/libabsl_base.a
ABSL_FORMAT_LIB := $(LIBDIR)/libabsl_str_format_internal.a
ABSL_INT28_LIB := $(LIBDIR)/libabsl_int128.a
ABSL_STRINGS_LIB := $(LIBDIR)/libabsl_strings.a
ABSL_BAD_LIB := $(LIBDIR)/libabsl_bad_optional_access.a
SSL_LIB := $(LIBDIR)/libssl.a
CRYPTO_LIB := $(LIBDIR)/libcrypto.a
ABSL_STR_INTERNAL_LIB := $(LIBDIR)/libabsl_strings_internal.a
ADDRESS_SORT_LIB := $(LIBDIR)/libaddress_sorting.a
Z_LIB := $(LIBDIR)/libz.a
ABSL_LOGGING_LIB := $(LIBDIR)/libabsl_raw_logging_internal.a
ABSL_THROW := $(LIBDIR)/libabsl_throw_delegate.a
ABSL_TIME_LIB := $(LIBDIR)/libabsl_time.a
ABSL_TIME_ZONE_LIB := $(LIBDIR)/libabsl_time_zone.a

LIBS ?= \
	$(PROTOBUF_LIB) \
	$(GRPCPP_LIB) \
	$(UPB_LIB) \
	$(GRPC_LIB) \
	$(GPR_LIB) \
	$(Z_LIB) \
	$(SSL_LIB) \
	$(CRYPTO_LIB) \
	$(CARES_LIB) \
	$(ADDRESS_SORT_LIB) \
	$(ABSL_BAD_LIB) \
	$(ABSL_BASE_LIB) \
	$(ABSL_FORMAT_LIB) \
	$(ABSL_INT28_LIB) \
	$(ABSL_STRINGS_LIB) \
	$(ABSL_STR_INTERNAL_LIB) \
	$(ABSL_LOGGING_LIB) \
	$(ABSL_THROW) \
	$(ABSL_TIME_LIB) \
	$(ABSL_TIME_ZONE_LIB)


LDLIBS += $(RTE_SDK)/daemon/lib/libopof.a
LDLIBS += $(LIBS)

LDFLAGS = -lc -lstdc++

# all source are stored in SRCS-y
SRCS-y := main.c flow.c thread.c init.c cmd.c opof_server.c

include $(RTE_SDK)/mk/rte.extapp.mk


.PHONY: clean

clean:
	rm -f ./*.o \
	rm -rf build

