OBJ += encode_base64.out

OBJ += fixed_xor.out

OBJ += single_byte_xor.out

OBJ += detect_single_byte_xor.out
detect_single_byte_xor.out_LIBS := single_byte_xor

OBJ += repeating_key_xor.out

OBJ += hamming_distance.out

TMD := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
include $(TMD)/../env.mk

detect_single_byte_xor.out: libsingle_byte_xor.so
