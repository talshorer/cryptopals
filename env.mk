CFLAGS += -Wall -Werror -D_GNU_SOURCE

CLEAN := rm -rf

default: all

%.out: %.c
	$(CC) $< -o $@ $(CFLAGS) $($@_CFLAGS)

all: $(OBJ)

clean: clean-obj clean-backup

clean-obj:
	$(CLEAN) $(OBJ)

clean-backup:
	$(CLEAN) *~
