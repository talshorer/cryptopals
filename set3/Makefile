THISDIR := $(realpath $(dir $(realpath $(lastword $(MAKEFILE_LIST)))))

_LIB_OBJS := aes_ctr.o

OBJ += $(foreach o, $(shell ls $(THISDIR)/ch*.c),$(subst .c,.out,$(o)))

LIB_OBJS += $(foreach o,$(_LIB_OBJS),$(THISDIR)/$(o))
