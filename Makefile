CFLAGS += -Wall -Werror -fPIC -D_GNU_SOURCE -L. -Iinclude

CLEAN = @find . -name "$(1)" -exec rm -f {} \;

LIB := libcryptopals.so

$(LIB)_LIBS := crypto

cflags = $(CFLAGS) $($(1)_CFLAGS) $($(1)_LIBS:%=-l%)

default: all

OBJ := $(foreach o, $(wildcard set*/ch*.c),$(subst .c,.out,$(o)))

LIB_OBJS :=

define get-set-lib
lib =
include $(1)/Makefile
endef # get-set-lib

define add-set-lib
$(eval $(call get-set-lib,$(1)))
LIB_OBJS += $(foreach o,$(lib),$(1)/$(o))
endef # add-set-lib

$(eval $(foreach s,$(wildcard set*),$(call add-set-lib,$(s))))

%.o: %.c
	$(CC) -c $< -o $@ $(call cflags,$@)

%.out: %.o
	$(CC) $< -o $@ $(call cflags,$@) -lcryptopals

ifeq ($(wildcard $(LIB)),)
$(OBJ): $(LIB)
endif

$(LIB): $(LIB_OBJS)
	$(CC) $^ -o $@ -shared $(call cflags,$@)

lib: $(LIB)

all: lib $(OBJ)

clean: clean-obj clean-backup

clean-obj:
	$(call CLEAN,*.o)
	$(call CLEAN,*.out)
	$(call CLEAN,*.so)

clean-backup:
	$(call CLEAN,*~)
