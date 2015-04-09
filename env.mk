CFLAGS += -Wall -Werror -D_GNU_SOURCE -L.

CLEAN := rm -rf

default: all

%.out: %.c
	$(CC) $< -o $@ $(CFLAGS) $($@_CFLAGS)

lib%.so: %.c
	$(CC) $< -o $@ -shared -fPIC $(LMOD_US_CFLAGS) $($@_CFLAGS)

all: $(OBJ)

clean: clean-obj clean-backup

clean-obj:
	$(CLEAN) $(OBJ)

clean-backup:
	$(CLEAN) *~
