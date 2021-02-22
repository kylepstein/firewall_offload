# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

# binary name
APP = firewall_offload
CC=gcc

GRPC_DIR ?= ./build/deps
LIBDIR := $(GRPC_DIR)/lib
LIB64DIR := $(GRPC_DIR)/lib64

INCLUDES += -I $(GRPC_DIR)/include \
	    -I /usr/include/c++/9 \
	    -I include \
	    -I src

PKGCONF ?= pkg-config

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk)
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk)

CFLAGS += $(INCLUDES)
CFLAGS += -DALLOW_EXPERIMENTAL_API

GPR_LIB := $(LIBDIR)/libgpr.a
CHANNELZ_LIB := $(LIBDIR)/libgrpcpp_channelz.a
GRPCPP_LIB := $(LIBDIR)/libgrpc++.a
GRPC_LIB := $(LIBDIR)/libgrpc.a
PROTOBUF_LIB := $(LIBDIR)/libprotobuf.a
CARES_LIB := $(LIBDIR)/libcares.a
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

LDLIBS += lib/libopof_server.a
LDLIBS += $(LIBS)

LDFLAGS = -lc -lstdc++ -lm -pthread

# all source are stored in SRCS-y
SRCS-y := src/main.c src/flow.c src/thread.c src/init.c src/cmd.c src/opof_server.c

build/$(APP): $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDLIBS) $(LDFLAGS_SHARED) $(LDFLAGS) 

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP)
	test -d build && rmdir -p build || true
