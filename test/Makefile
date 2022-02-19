#
# Iddawc library
#
# Makefile used to build the tests
#
# Public domain, no copyright. Use at your own risk.
#

IDDAWC_INCLUDE=../include
IDDAWC_LOCATION=../src
IDDAWC_LIBRARY=$(IDDAWC_LOCATION)/libiddawc.so
CC=gcc
CFLAGS+=-Wall -D_REENTRANT -I$(IDDAWC_INCLUDE) -DDEBUG -g -O0 $(CPPFLAGS)
LDFLAGS=-lc -liddawc -L$(IDDAWC_LOCATION) $(shell pkg-config --libs liborcania) $(shell pkg-config --libs libyder) $(shell pkg-config --libs libulfius) $(shell pkg-config --libs librhonabwy) $(shell pkg-config --libs jansson) $(shell pkg-config --libs check) $(shell pkg-config --libs gnutls)
VALGRIND_COMMAND=valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all
TARGET=core implicit id_token token load_config load_userinfo flow introspection revocation registration dpop api_request device par ciba session
TARGET_TEST=test_core test_implicit test_id_token test_token test_load_config test_load_userinfo test_flow test_introspection test_revocation test_registration test_dpop test_api_request test_device test_par test_ciba test_session
VERBOSE=0
MEMCHECK=0
CERT=cert

all: test

clean:
	rm -f *.o $(TARGET) valgrind-*.txt *.log $(CERT)/*.crt $(CERT)/*.key

$(IDDAWC_LIBRARY): $(IDDAWC_INCLUDE)/iddawc.h $(IDDAWC_LOCATION)/iddawc.c
	cd $(IDDAWC_LOCATION) && $(MAKE) debug

$(CERT)/server.key:
	./$(CERT)/create-cert.sh

%: $(IDDAWC_LIBRARY) %.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test_%: % $(IDDAWC_LIBRARY) $(CERT)/server.key
	@if [ "$(VERBOSE)" = "0" ] && [ "$(MEMCHECK)" = "0" ]; then \
		LD_LIBRARY_PATH=$(IDDAWC_LOCATION):${LD_LIBRARY_PATH} ./run_test.sh ./$^; \
	elif [ "$(MEMCHECK)" = "0" ]; then \
		LD_LIBRARY_PATH=$(IDDAWC_LOCATION):${LD_LIBRARY_PATH} ./$^ ; \
	else \
		CK_FORK=no LD_LIBRARY_PATH=$(IDDAWC_LOCATION):${LD_LIBRARY_PATH} $(VALGRIND_COMMAND) ./$^ 2>valgrind-$@.txt; \
	fi

test: $(TARGET) $(TARGET_TEST)

check: test
