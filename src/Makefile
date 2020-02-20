#
# Iddawc Library
#
# Makefile used to build the software
#
# Copyright 2019-2020 Nicolas Mora <mail@babelouest.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation;
# version 2.1 of the License.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
# GNU GENERAL PUBLIC LICENSE for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library.	If not, see <http://www.gnu.org/licenses/>.
#
PROJECT_NAME=iddawc
PROJECT_DESCRIPTION=OAuth2 client library
PROJECT_BUGREPORT_PATH=https://github.com/babelouest/iddawc/issues
PKGCONF_REQ=
PKGCONF_REQ_PRIVATE=
IDDAWC_INCLUDE=../include
PKGCONFIG_FILE=../libiddawc.pc
PKGCONFIG_TEMPLATE=../libiddawc.pc.in
CONFIG_FILE=$(IDDAWC_INCLUDE)/iddawc-cfg.h
CONFIG_TEMPLATE=$(IDDAWC_INCLUDE)/iddawc-cfg.h.in
DESTDIR=/usr/local
CC=gcc
CFLAGS+=-c -pedantic -std=gnu99 -fPIC -Wall -Werror -Wextra -D_REENTRANT -I$(IDDAWC_INCLUDE) $(ADDITIONALFLAGS) $(CPPFLAGS)
LIBS=-L$(DESTDIR)/lib -lc -lulfius -lorcania -lrhonabwy -ljwt -lgnutls $(LDFLAGS)
SONAME=-soname
OBJECTS=iddawc.o
OUTPUT=libiddawc.so
VERSION_MAJOR=0
VERSION_MINOR=9
VERSION_PATCH=4

.PHONY: all clean

all: release

$(CONFIG_FILE):
	@cp $(CONFIG_TEMPLATE) $(CONFIG_FILE)
	@echo Config file $(CONFIG_FILE) generated
	@sed -i -e 's/$${PROJECT_VERSION}/$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)/g' $(CONFIG_FILE)        
	@sed -i -e 's/$${PROJECT_VERSION_MAJOR}/$(VERSION_MAJOR)/g' $(CONFIG_FILE)        
	@sed -i -e 's/$${PROJECT_VERSION_MINOR}/$(VERSION_MINOR)/g' $(CONFIG_FILE)        
	@sed -i -e 's/$${PROJECT_VERSION_PATCH}/$(VERSION_PATCH)/g' $(CONFIG_FILE)        
	@sed -i -e 's/$${PROJECT_VERSION_NUMBER}/$(shell printf '%02d' $(VERSION_MAJOR))$(shell printf '%02d' $(VERSION_MINOR))$(shell printf '%02d' $(VERSION_PATCH))/g' $(CONFIG_FILE)        

$(PKGCONFIG_FILE):
	@cp $(PKGCONFIG_TEMPLATE) $(PKGCONFIG_FILE)
	@echo Pkgconfig file $(PKGCONFIG_FILE) generated
	@sed -i -e 's#@CMAKE_INSTALL_PREFIX@#$(DESTDIR)#g' $(PKGCONFIG_FILE)
	@sed -i -e 's/@CMAKE_INSTALL_LIBDIR@/lib/g' $(PKGCONFIG_FILE)
	@sed -i -e 's/@CMAKE_INSTALL_INCLUDEDIR@/include/g' $(PKGCONFIG_FILE)
	@sed -i -e 's/@PROJECT_NAME@/$(PROJECT_NAME)/g' $(PKGCONFIG_FILE)
	@sed -i -e 's/@PROJECT_DESCRIPTION@/$(PROJECT_DESCRIPTION)/g' $(PKGCONFIG_FILE)
	@sed -i -e 's|@PROJECT_BUGREPORT_PATH@|$(PROJECT_BUGREPORT_PATH)|g' $(PKGCONFIG_FILE)
	@sed -i -e 's/@LIBRARY_VERSION@/$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)/g' $(PKGCONFIG_FILE)
	@sed -i -e 's/@PKGCONF_REQ@/$(PKGCONF_REQ)/g' $(PKGCONFIG_FILE)
	@sed -i -e 's/@PKGCONF_REQ_PRIVATE@/$(PKGCONF_REQ_PRIVATE)/g' $(PKGCONFIG_FILE)

target: $(OBJECTS)

%.o: %.c $(CONFIG_FILE) $(IDDAWC_INCLUDE)/iddawc.h
	$(CC) $(CFLAGS) $<

libiddawc.so: $(CONFIG_FILE) $(OBJECTS)
	$(CC) -shared -fPIC -Wl,$(SONAME),$(OUTPUT) -o $(OUTPUT).$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH) $(OBJECTS) $(LIBS) $(LYDER) $(LJANSSON) $(LCURL) $(LGNUTLS)
	ln -sf $(OUTPUT).$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH) $(OUTPUT)

clean:
	rm -f *.o *.so *.a $(OUTPUT) $(OUTPUT).* $(CONFIG_FILE) $(PKGCONFIG_FILE) $(CONFIG_FILE)

install: all $(PKGCONFIG_FILE)
	install $(OUTPUT).$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH) $(DESTDIR)/lib
	install -m644 $(PKGCONFIG_FILE) $(DESTDIR)/lib/pkgconfig
	install -m644 $(IDDAWC_INCLUDE)/iddawc.h $(DESTDIR)/include
	install -m644 $(CONFIG_FILE) $(DESTDIR)/include
	-ldconfig $(DESTDIR)/lib

uninstall:
	rm -f $(DESTDIR)/lib/$(OUTPUT) $(DESTDIR)/lib/libiddawc.a
	rm -f $(DESTDIR)/lib/$(OUTPUT).*
	rm -f $(DESTDIR)/include/iddawc.h
	rm -f $(DESTDIR)/include/$(CONFIG_FILE)
	rm -f $(DESTDIR)/lib/pkgconfig/$(PKGCONFIG_FILE)

debug: ADDITIONALFLAGS=-DDEBUG -g -O0

debug: libiddawc.so

release: ADDITIONALFLAGS=-O3

release: libiddawc.so
