/*****************************************************************************
 * Mandrake Security                                                         *
 * Written by Vandoorselaere Yoann                                           *
 * (C) 1999, Mandrakesoft		                                             *
 *****************************************************************************/

/*****
*
* Copyright (C) 1999 Mandrakesoft
* All Rights Reserved
*
* This file is part of the Mandrake Security program.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by 
* the Free Software Foundation; either version 2, or (at your option)
* any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING.  If not, write to
* the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*
*****/

/* 
 * This program will verify each interface on the machine to
 * see if one of them is in promisc state.
 *
 * In this program, buf is an array containing many structure ifreq...
 * this allow you to print out :
 * ( BUFSIZ / sizeof(struct ifreq )) number of ether card configuration.
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

static int quiet_mode = 0;

void usage(void);
void check_args(int argc, char **argv);
void PrintResult(struct ifreq *ifr);

int main(int argc, char **argv)
{
	struct ifconf ifc;
	char buf[BUFSIZ], *ptr, *ptr_end;
	int ret, sock;

	check_args(argc, argv);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("socket");
		exit(1);
	}

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;

	ret = ioctl(sock, SIOCGIFCONF, (char *) &ifc);
	if (ret < 0) {
		perror("ioctl: SIOCGIFCONF");
		exit(1);
	}

	ptr_end = buf + ifc.ifc_len;
	for (ptr = ifc.ifc_buf; ptr < ptr_end; ptr += sizeof(struct ifreq)) {
		struct ifreq *ifr;

		ifr = (struct ifreq *) ptr;

		ret = ioctl(sock, SIOCGIFFLAGS, (char *) ifr);
		if (ret < 0) {
			perror("ioctl : SIOCGIFFLAGS");
			exit(1);
		}

		PrintResult(ifr);
	}

	close(sock);
	exit(0);
}

void PrintResult(struct ifreq *ifr)
{
	if (quiet_mode == 0) {
		if ((ifr->ifr_flags & IFF_PROMISC) != 0)
			printf("%s : Promiscuous mode detected.\n",
			       ifr->ifr_name);
		else
			printf("%s : Not in promiscuous mode.\n",
			       ifr->ifr_name);
	} else {
		if ((ifr->ifr_flags & IFF_PROMISC) != 0)
			printf("%s\n", ifr->ifr_name);
	}
}



void check_args(int argc, char **argv)
{
	while (1) {
		int c;

		c = getopt(argc, argv, "qh");
		if (c == -1)
			break;

		switch (c) {
		case 'q':
			quiet_mode = 1;
			break;
		case 'h':
			usage();
			exit(0);
		default:
			exit(1);
		}
	}
}

void usage(void)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr,
		"\t-q Quiet mode ( only report interface name ).\n\n");
}
