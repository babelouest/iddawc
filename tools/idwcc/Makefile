#
# idwcc: OAuth2/OIDC client program to test or validate OAuth2/OIDC AS
#
# Makefile used to build the software
#
# Copyright 2021 Nicolas Mora <mail@babelouest.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU GENERAL PUBLIC LICENSE
# License as published by the Free Software Foundation;
# version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU GENERAL PUBLIC LICENSE for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
CC=gcc
IDDAWC_INCLUDE=../../include
IDDAWC_LOCATION=../../src
DESTDIR=/usr/local
IDDAWC_LIBRARY=../../src/libiddawc.so

CFLAGS+=-c -Wall -I$(IDDAWC_INCLUDE) $(ADDITIONALFLAGS) $(CPPFLAGS)
LIBS=-lc -liddawc -L$(IDDAWC_LOCATION) $(shell pkg-config --libs liborcania) $(shell pkg-config --libs libyder) $(shell pkg-config --libs libulfius) $(shell pkg-config --libs jansson) -lpthread -lz
VALGRIND_COMMAND=valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all --track-origins=yes
OBJECTS=idwcc.o static_compressed_inmemory_website_callback.o http_compression_callback.o

all: idwcc

all: ADDITIONALFLAGS= -O3

clean:
	rm -f *.o idwcc

debug: idwcc

debug: ADDITIONALFLAGS=-DDEBUG -g -O0

$(IDDAWC_LIBRARY): $(IDDAWC_INCLUDE)/iddawc.h $(IDDAWC_LOCATION)/iddawc.c
	cd $(IDDAWC_LOCATION) && $(MAKE) debug

%.o: %.c $(IDDAWC_LIBRARY) static_compressed_inmemory_website_callback.h static_compressed_inmemory_website_callback.c http_compression_callback.h http_compression_callback.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $<

idwcc: $(OBJECTS)
	$(CC) -o $@ $^ $(LIBS) $(LDFLAGS)

install: idwcc
	mkdir -p $(DESTDIR)/bin $(DESTDIR)/man/man1/
	install -m755 idwcc $(DESTDIR)/bin
	install -m644 idwcc.1 $(DESTDIR)/man/man1/

uninstall:
	rm -f $(DESTDIR)/bin/idwcc

test: idwcc
	LD_LIBRARY_PATH=$(IDDAWC_LOCATION): ./idwcc

memcheck: debug
	LD_LIBRARY_PATH=$(IDDAWC_LOCATION): valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all --track-origins=yes ./idwcc 2>valgrind.txt

manpage: idwcc
	help2man ./idwcc -s 1 -n "OAuth2/OIDC client program to test or validate OAuth2/OIDC AS." > idwcc.1
