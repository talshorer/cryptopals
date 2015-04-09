CFLAGS += -Wall -Werror -fPIC -D_GNU_SOURCE -L.

CLEAN := rm -rf

default: all

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS) $($@_CFLAGS)

%.out: %.o
	$(CC) $< -o $@ $(CFLAGS) $($@_CFLAGS)

lib%.so: %.o
	$(CC) $< -o $@ -shared $(CFLAGS) $($@_CFLAGS)

all: $(OBJ)

clean: clean-obj clean-backup
	$(CLEAN) *.o *.so *.out

clean-obj:
	$(CLEAN) $(OBJ)

clean-backup:
	$(CLEAN) *~
