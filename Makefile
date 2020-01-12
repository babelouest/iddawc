#
# Iddawc library
#
# Makefile used to build all programs
#
# Copyright 201i9 Nicolas Mora <mail@babelouest.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the MIT License
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#

LIBIDDAWC_LOCATION=./src
TESTS_LOCATION=./test

all:
	cd $(LIBIDDAWC_LOCATION) && $(MAKE) $*

debug:
	cd $(LIBIDDAWC_LOCATION) && $(MAKE) debug $*

clean:
	cd $(LIBIDDAWC_LOCATION) && $(MAKE) clean
	cd $(TESTS_LOCATION) && $(MAKE) clean

install:
	cd $(LIBIDDAWC_LOCATION) && $(MAKE) install

uninstall:
	cd $(LIBIDDAWC_LOCATION) && $(MAKE) uninstall

check:
	cd $(TESTS_LOCATION) && $(MAKE)

doxygen:
	doxygen doc/doxygen.cfg
