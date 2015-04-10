CFLAGS += -Wall -Werror -fPIC -D_GNU_SOURCE -L.

CLEAN := rm -rf

cflags = $(CFLAGS) $($(1)_CFLAGS) $($(1)_LIBS:%=-l%)

default: all

%.o: %.c
	$(CC) -c $< -o $@ $(call cflags,$@)

%.out: %.o
	$(CC) $< -o $@ $(call cflags,$@)

lib%.so: %.o
	$(CC) $< -o $@ -shared $(call cflags,$@)

all: $(OBJ)

clean: clean-obj clean-backup
	$(CLEAN) *.o *.so *.out

clean-obj:
	$(CLEAN) $(OBJ)

clean-backup:
	$(CLEAN) *~
