CC=gcc
NAME=promisc_check

CFLAGS = -ggdb -Wall -Wmissing-prototypes -Wmissing-declarations \
-Wpointer-arith -m486 -O2 -finline-functions -fkeep-inline-functions

OBJ=promisc_check.o

promisc_check: $(OBJ)
	$(CC) $(OBJ) -o $(NAME)

install:
	cp $(NAME) /usr/bin
