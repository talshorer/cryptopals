CFLAGS += -Wall -Werror -fPIC -D_GNU_SOURCE -L.

CLEAN := rm -rf

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

# clean: clean-obj clean-backup
# 	$(CLEAN) *.o *.so *.out
#
# clean-obj:
# 	$(CLEAN) $(OBJ)
#
# clean-backup:
# 	$(CLEAN) *~

%.gen.txt: %.txt
	tr -d '\n' < $< > $@
