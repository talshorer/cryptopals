THISDIR := $(realpath $(dir $(realpath $(lastword $(MAKEFILE_LIST)))))

_LIB_OBJS := base64_core.o fixed_xor.o single_byte_xor.o repeating_key_xor.o \
  hamming_distance.o break_repeating_key_xor.o

OBJ += $(foreach o, $(shell ls $(THISDIR)/ch*.c),$(subst .c,.out,$(o)))

$(THISDIR)/ch7.out_LIBS := crypto


LIB_OBJS += $(foreach o,$(_LIB_OBJS),$(THISDIR)/$(o))
