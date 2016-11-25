CFLAGS += -Wall -Werror -fPIC -D_GNU_SOURCE -L. -Iinclude

CLEAN = @find . -name "$(1)" -exec rm -f {} \;

LIB := libcryptopals.so

cflags = $(CFLAGS) $($(1)_CFLAGS) $($(1)_LIBS:%=-l%)

default: all

include set*/Makefile

%.o: %.c
	$(CC) -c $< -o $@ $(call cflags,$@)

%.out: %.o
	$(CC) $< -o $@ $(call cflags,$@) -lcryptopals

$(LIB): $(LIB_OBJS)
	$(CC) $^ -o $@ -shared $(call cflags,$@)

all: $(LIB) $(OBJ)

clean: clean-obj clean-backup

clean-obj:
	$(call CLEAN,*.o)
	$(call CLEAN,*.out)
	$(call CLEAN,*.so)

clean-backup:
	$(call CLEAN,*~)

%.gen.txt: %.txt
	tr -d '\n' < $< > $@
