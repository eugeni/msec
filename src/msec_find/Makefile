CC=gcc
NAME=msec_find

CFLAGS = -ggdb -Wall -Wmissing-prototypes -Wmissing-declarations \
-Wpointer-arith -m486 -O2 -finline-functions -fkeep-inline-functions

OBJ=find.o

msec_find: $(OBJ)
	$(CC) $(OBJ) -o $(NAME)

install:
	cp $(NAME) /usr/bin
