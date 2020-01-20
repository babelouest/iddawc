# Iddawc - OAuth2 client library

[![Build Status](https://travis-ci.com/babelouest/iddawc.svg?branch=master)](https://travis-ci.com/babelouest/iddawc)

Handles the flow of OAuth2 and OpenID Connect authentication process from the client side.
- Genrates requests based on input parameters
- Parses response
- Validates response values

Example for code and id_token flow on an OpenID Connect server.

```C
/**
 * Compile with
 * gcc -o test_iddawc test_iddawc.c -liddawc
 */
#include <stdio.h>
#include <iddawc.h>

int main() {
  struct _i_session i_session;

  i_init_session(&i_session);
  i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_ID_TOKEN|I_RESPONSE_TYPE_CODE,
                                                        I_OPT_OPENID_CONFIG_ENDPOINT, "https://oidc.tld/.well-known/openid-configuration",
                                                        I_OPT_CLIENT_ID, "client1",
                                                        I_OPT_CIENT_SECRET, "mySecret",
                                                        I_OPT_REDIRECT_URI, "https://my-client.tld",
                                                        I_OPT_SCOPE, "openid",
                                                        I_OPT_STATE, "myState1234",
                                                        I_OPT_NONE);
  i_load_openid_config(&i_session);
  
  // First step: get redirection to login page
  i_run_auth_request(&i_session);
  printf("Redirect to: %s\n", i_get_parameter(&i_session, I_OPT_REDIRECT_TO));
  
  // When the user has loggined in the external application, gets redirected with a result, we parse the result
  i_set_parameter(&i_session, I_OPT_REDIRECT_TO, "https://https://my-client.tld#code=xyz1234&id_token=tokenXYZ1234");
  i_parse_redirect_to(&i_session);
  
  // Run the token request, get the refresh and access tokens
  i_run_token_request(&i_session);
  
  // And finally we load user info using the access token
  i_load_userinfo(&i_session);
  printf("userinfo: %s\n", i_get_parameter(&i_session, I_OPT_USERINFO));
  
  // Cleanup session
  i_clean_session(&i_session);
}
```

## Install

- Using Cmake

```shell
$ mkdir build
$ cd build
$ cmake ..
$ make && sudo make install
```

## API Documentation

Read the [online documentation](https://babelouest.github.io/iddawc/doc/html/).
