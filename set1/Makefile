OBJ += encode_base64.out
encode_base64.out_LIBS := base64_core

OBJ += fixed_xor.out

OBJ += single_byte_xor.out

OBJ += detect_single_byte_xor.out
detect_single_byte_xor.out_LIBS := single_byte_xor

OBJ += repeating_key_xor.out

OBJ += break_repeating_key_xor.out
break_repeating_key_xor.out_LIBS += hamming_distance single_byte_xor
break_repeating_key_xor.out_LIBS += repeating_key_xor

TMD := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
include $(TMD)/../env.mk

encode_base64.out: $(encode_base64.out_LIBS:%=lib%.so)

detect_single_byte_xor.out: $(detect_single_byte_xor.out_LIBS:%=lib%.so)

break_repeating_key_xor.out: $(break_repeating_key_xor.out_LIBS:%=lib%.so)
