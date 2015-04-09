OBJ += encode_base64.out

OBJ += fixed_xor.out

OBJ += single_byte_xor.out

OBJ += detect_single_byte_xor.out
OBJ += libsingle_byte_xor.so
detect_single_byte_xor.out: libsingle_byte_xor.so
detect_single_byte_xor.out_CFLAGS := -lsingle_byte_xor

TMD := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
include $(TMD)/../env.mk
