#
# Iddawc library
#
# Makefile used to build the tests
#
# Copyright 2019 Nicolas Mora <mail@babelouest.org>
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

IDDAWC_INCLUDE=../include
IDDAWC_LOCATION=../src
IDDAWC_LIBRARY=$(IDDAWC_LOCATION)/libiddawc.so
CC=gcc
CFLAGS+=-Wall -D_REENTRANT -I$(IDDAWC_INCLUDE) -DDEBUG -g -O0 $(CPPFLAGS)
LDFLAGS=-lc -lorcania -lulfius -liddawc -L$(IDDAWC_LOCATION) -lyder $(shell pkg-config --libs check)
VALGRIND_COMMAND=valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all
TARGET=core oauth2

all: test

clean:
	rm -f *.o $(TARGET) valgrind-*.txt

$(IDDAWC_LIBRARY):
	cd $(IDDAWC_LOCATION) && $(MAKE) debug

%: %.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test_%: %
	LD_LIBRARY_PATH=$(IDDAWC_LOCATION):${LD_LIBRARY_PATH} ./$^

test: $(IDDAWC_LIBRARY) $(TARGET)

check: test

memcheck: $(IDDAWC_LIBRARY) $(TARGET)
	-CK_FORK=no LD_LIBRARY_PATH=$(IDDAWC_LOCATION):${LD_LIBRARY_PATH} $(VALGRIND_COMMAND) ./core 2>valgrind-core.txt
	-CK_FORK=no LD_LIBRARY_PATH=$(IDDAWC_LOCATION):${LD_LIBRARY_PATH} $(VALGRIND_COMMAND) ./oauth2 2>valgrind-oauth2.txt
