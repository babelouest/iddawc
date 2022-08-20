/**
 * Token introspection using Iddawc library
 *
 * Copyright 2022 Nicolas Mora <mail@babelouest.org>
 *
 * License MIT
 *
 * Compile with
 * gcc -o token_introspection token_introspection.c -liddawc -lyder -ljansson
 */
#include <stdio.h>
#include <string.h>
#include <yder.h>
#include <iddawc.h>

/**
 * This is a sample config value for Glewlwyd OIDC API
 * Update with the glewlwyd OIDC instance you want to use
 */
#define CONFIG_ENDPOINT "https://auth.tld/.well-known/openid-configuration"

/**
 * Alternatively, you can specify manuall the required urls
 */
#define AUTH_ENDPOINT "https://auth.tld/auth"
#define TOKEN_ENDPOINT "https://auth.tld/token"
#define INTROSPECTION_ENDPOINT "https://auth.tld/introspect"

/**
 * Update the values below with your client values
 */
#define CLIENT_ID "clientXyz"
#define CLIENT_SECRET "secretXyz"
#define REDIRECT_URI "https://www.example.com/"
#define SCOPE "openid"

int main() {
  struct _i_session i_session;
  int ret;
  char redirect_to[4097] = {0}, * str_introspect = NULL;
  json_t * j_introspect = NULL;

  y_init_logs("iddawc tests", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Introspection example");

  i_init_session(&i_session);
  i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                   I_OPT_OPENID_CONFIG_ENDPOINT, CONFIG_ENDPOINT,
                                   I_OPT_CLIENT_ID, CLIENT_ID,
                                   I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                   I_OPT_REDIRECT_URI, REDIRECT_URI,
                                   I_OPT_SCOPE, SCOPE,
                                   I_OPT_STATE_GENERATE, 16,
                                   I_OPT_NONCE_GENERATE, 32,
                                   I_OPT_NONE);
  if (i_get_openid_config(&i_session) != I_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Error loading openid config");
    i_clean_session(&i_session);
    return 1;
  }

  // First step: get redirection to login page
  if ((ret = i_run_auth_request(&i_session)) != I_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Error running auth request: %d", ret);
    i_clean_session(&i_session);
    return 1;
  }
  printf("Redirect to: %s\n", i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO));

  // When the user has logged in the external application, gets redirected with a result, we parse the result
  y_log_message(Y_LOG_LEVEL_INFO, "Enter redirect URL");
  fgets(redirect_to, 4096, stdin);
  redirect_to[strlen(redirect_to)-1] = '\0';
  i_set_str_parameter(&i_session, I_OPT_REDIRECT_TO, redirect_to);
  if (i_parse_redirect_to(&i_session) != I_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Error parsing redirect_to url");
    i_clean_session(&i_session);
    return 1;
  }

  // Run the token request, get the refresh and access tokens
  if (i_run_token_request(&i_session) != I_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Error running token request");
    i_clean_session(&i_session);
    return 1;
  }

  // Run the introspection command
  if (i_get_token_introspection(&i_session, &j_introspect, I_INTROSPECT_REVOKE_AUTH_CLIENT_TARGET, 0) != I_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Error running token introspection");
    i_clean_session(&i_session);
    return 1;
  }
  str_introspect = json_dumps(j_introspect, JSON_INDENT(2));
  y_log_message(Y_LOG_LEVEL_INFO, "Introspection result: %s", str_introspect);
  i_free(str_introspect);
  json_decref(j_introspect);

  // Cleanup session
  i_clean_session(&i_session);
  y_close_logs();

  return 0;
}
