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
IDDAWC_VERSION=$(shell curl -s https://api.github.com/repos/babelouest/iddawc/releases/latest | grep tag_name | cut -d '"' -f 4 | cut -c 2-)
ALPINE_VERSION=3.13.4

CFLAGS+=-c -Wall -I$(IDDAWC_INCLUDE) $(ADDITIONALFLAGS) $(CPPFLAGS)
LIBS=-lc -liddawc -L$(IDDAWC_LOCATION) $(shell pkg-config --libs liborcania) $(shell pkg-config --libs libyder) $(shell pkg-config --libs libulfius) $(shell pkg-config --libs jansson) -lpthread -lz
VALGRIND_COMMAND=valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all --track-origins=yes
OBJECTS=idwcc.o static_compressed_inmemory_website_callback.o http_compression_callback.o

all: idwcc

all: ADDITIONALFLAGS= -O3

clean:
	rm -f *.o idwcc
	rm -f iddawc-dev-full_*_alpine_*_x86_64.tar.gz
	docker rmi -f babelouest/idwcc:latest babelouest/idwcc:$(IDDAWC_VERSION)
	docker system prune -f

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
	LD_LIBRARY_PATH=$(IDDAWC_LOCATION): ./idwcc -w webapp

memcheck: debug
	LD_LIBRARY_PATH=$(IDDAWC_LOCATION): valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all --track-origins=yes ./idwcc -w webapp 2>valgrind.txt

manpage: idwcc
	help2man ./idwcc -s 1 -n "OAuth2/OIDC client program to test or validate OAuth2/OIDC AS." > idwcc.1

iddawc-dev-full_$(IDDAWC_VERSION)_alpine_$(ALPINE_VERSION)_x86_64.tar.gz:
	wget https://github.com/babelouest/iddawc/releases/download/v${IDDAWC_VERSION}/iddawc-dev-full_$(IDDAWC_VERSION)_alpine_$(ALPINE_VERSION)_x86_64.tar.gz

docker-build: iddawc-dev-full_$(IDDAWC_VERSION)_alpine_$(ALPINE_VERSION)_x86_64.tar.gz
	docker build -t babelouest/idwcc:$(IDDAWC_VERSION) --build-arg IDDAWC_VERSION=$(IDDAWC_VERSION) --build-arg ALPINE_VERSION=$(ALPINE_VERSION) .
	docker tag babelouest/idwcc:$(IDDAWC_VERSION) babelouest/idwcc:latest

docker-run:
	docker run -it --rm -p 4398:4398 babelouest/idwcc:latest
