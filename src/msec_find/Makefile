CC=gcc
NAME=msec_find

CFLAGS = -ggdb -Wall -Wmissing-prototypes -Wmissing-declarations \
-Wpointer-arith -m486 -O2 -finline-functions -fkeep-inline-functions

OBJ=find.o

msec_find: $(OBJ)
	$(CC) $(OBJ) -o $(NAME)

install:
	mkdir -p $(RPM_BUILD_ROOT)/usr/bin
	cp $(NAME) $(RPM_BUILD_ROOT)/usr/bin
