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
LDFLAGS=-lc -lorcania -liddawc -lrhonabwy -ljansson -ljwt -L$(IDDAWC_LOCATION) -lyder $(shell pkg-config --libs check) -lulfius
VALGRIND_COMMAND=valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all
TARGET=core implicit id_token token load_config load_userinfo flow
TARGET_TEST=test_core test_implicit test_id_token test_token test_load_config test_load_userinfo test_flow
MEMCHECK=0

all: test

clean:
	rm -f *.o $(TARGET) valgrind-*.txt

$(IDDAWC_LIBRARY): $(IDDAWC_INCLUDE)/iddawc.h $(IDDAWC_LOCATION)/iddawc.c
	cd $(IDDAWC_LOCATION) && $(MAKE) debug

%: $(IDDAWC_LIBRARY) %.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test_%: %
	@if [ "$(MEMCHECK)" = "0" ]; then \
	  LD_LIBRARY_PATH=$(IDDAWC_LOCATION):$(LD_LIBRARY_PATH) ./$^ ; \
	else \
	  CK_FORK=no LD_LIBRARY_PATH=$(IDDAWC_LOCATION):$(LD_LIBRARY_PATH) $(VALGRIND_COMMAND) ./$^ 2>valgrind-$@.txt; \
	fi

test: $(TARGET) $(TARGET_TEST)

check: test
