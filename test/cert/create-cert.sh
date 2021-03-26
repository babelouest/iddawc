#!/bin/sh

#
# Iddawc
#
# Create certificates
#
# Public domain, no copyright. Use at your own risk.
#

DEST=../test/cert
RET=0

case "$OSTYPE" in
*"darwin"*)
  # Apple has its own certtool which is incompatible. GnuTLS' certtool is renamed as
  # gnutls-certtool in MacPorts/homebrew.
  CERTTOOL=gnutls-certtool;;
         *)
  CERTTOOL=certtool;;
esac

# clean old certs
rm -f $DEST/server* $DEST/root* $DEST/user* $DEST/fullchain*

echo >> $DEST/certtool.log
echo Generate Iddawc test certificates >> $DEST/certtool.log
echo >> $DEST/certtool.log

# www cert
$CERTTOOL --generate-privkey --outfile $DEST/server.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "server.key         \033[0;32mOK\033[0m\n"
else
  printf "server.key         \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-self-signed --load-privkey $DEST/server.key --outfile $DEST/server.crt --template $DEST/template-server.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "server.crt         \033[0;32mOK\033[0m\n"
else
  printf "server.crt         \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# CA root
$CERTTOOL --generate-privkey --outfile $DEST/root1.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "root1.key          \033[0;32mOK\033[0m\n"
else
  printf "root1.key          \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-self-signed --load-privkey $DEST/root1.key --outfile $DEST/root1.crt --template $DEST/template-ca.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "root1.crt          \033[0;32mOK\033[0m\n"
else
  printf "root1.crt          \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# user 1
$CERTTOOL --generate-privkey --outfile $DEST/user1.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "user1.key          \033[0;32mOK\033[0m\n"
else
  printf "user1.key          \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-certificate --load-privkey $DEST/user1.key --load-ca-certificate $DEST/root1.crt --load-ca-privkey $DEST/root1.key --outfile $DEST/user1.crt --template $DEST/template-user.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "user1.crt          \033[0;32mOK\033[0m\n"
else
  printf "user1.crt          \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# CA root 2
$CERTTOOL --generate-privkey --outfile $DEST/root2.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "root2.key          \033[0;32mOK\033[0m\n"
else
  printf "root2.key          \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-self-signed --load-privkey $DEST/root2.key --outfile $DEST/root2.crt --template $DEST/template-ca2.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "root2.crt          \033[0;32mOK\033[0m\n"
else
  printf "root2.crt          \033[0;31mError\033[0m\n"
  RET=$STATUS
fi

# user 2
$CERTTOOL --generate-privkey --outfile $DEST/user2.key --sec-param High 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "user2.key          \033[0;32mOK\033[0m\n"
else
  printf "user2.key          \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
$CERTTOOL --generate-certificate --load-privkey $DEST/user2.key --load-ca-certificate $DEST/root2.crt --load-ca-privkey $DEST/root2.key --outfile $DEST/user2.crt --template $DEST/template-user.cfg 2>>$DEST/certtool.log
STATUS=$?
if [ $STATUS -eq 0 ]; then
  printf "user2.crt          \033[0;32mOK\033[0m\n"
else
  printf "user2.crt          \033[0;31mError\033[0m\n"
  RET=$STATUS
fi
