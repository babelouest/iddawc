#
# Iddawc library
#
# Makefile used to build the example files
#
# Copyright 2020 Nicolas Mora <mail@babelouest.org>
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
LDFLAGS=-lc -liddawc -ljansson -L$(IDDAWC_LOCATION) -lyder
TARGET=github_example gitlab_example glewlwyd_oidc_id_token_code google_example microsoft_example facebook_example

all: $(TARGET)

clean:
	rm -f *.o $(TARGET)

$(IDDAWC_LIBRARY): $(IDDAWC_INCLUDE)/iddawc.h $(IDDAWC_LOCATION)/iddawc.c
	cd $(IDDAWC_LOCATION) && $(MAKE) debug

%: $(IDDAWC_LIBRARY) %.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

run_%: %
	LD_LIBRARY_PATH=$(IDDAWC_LOCATION):$(LD_LIBRARY_PATH) ./$^
