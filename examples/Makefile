#
# Iddawc library
#
# Makefile used to build the example files
#
# Copyright 2020 Nicolas Mora <mail@babelouest.org>
#
# License MIT
#

IDDAWC_INCLUDE=../include
IDDAWC_LOCATION=../src
IDDAWC_LIBRARY=$(IDDAWC_LOCATION)/libiddawc.so
CC=gcc
CFLAGS+=-Wall -D_REENTRANT -I$(IDDAWC_INCLUDE) -DDEBUG -g -O0 $(CPPFLAGS)
LDFLAGS=-lc -liddawc -ljansson -L$(IDDAWC_LOCATION) -lyder -lorcania
TARGET=github_example gitlab_example glewlwyd_oidc_id_token_code google_example microsoft_example facebook_example token_introspection token_revocation client_registration

all: $(TARGET)

clean:
	rm -f *.o $(TARGET)

$(IDDAWC_LIBRARY): $(IDDAWC_INCLUDE)/iddawc.h $(IDDAWC_LOCATION)/iddawc.c
	cd $(IDDAWC_LOCATION) && $(MAKE) debug

%: $(IDDAWC_LIBRARY) %.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

run_%: %
	LD_LIBRARY_PATH=$(IDDAWC_LOCATION):$(LD_LIBRARY_PATH) ./$^
