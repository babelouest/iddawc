/**
 * Glewlwyd example using Iddawc library
 * 
 * Copyright 2020 Nicolas Mora <mail@babelouest.org>
 *
 * License MIT
 * 
 * Compile with
 * gcc -o glewlwyd_oidc_id_token_code glewlwyd_oidc_id_token_code.c -liddawc -lyder -ljansson
 */
#include <stdio.h>
#include <string.h>
#include <yder.h>
#include <iddawc.h>

/**
 * This is a sample config value for Glewlwyd OIDC API
 * Update with the glewlwyd OIDC instance you want to use
 */
#define CONFIG_ENDPOINT "https://glewlwyd.tld/api/oidc/.well-known/openid-configuration"

/**
 * Update the values below with your client values
 * Glewlwyd documentation:
 * https://github.com/babelouest/glewlwyd/blob/master/docs/GETTING_STARTED.md
 */
#define CLIENT_ID "clientXyz"
#define CLIENT_SECRET "secretXyz"
#define REDIRECT_URI "https://www.example.com/"
#define SCOPE "openid"

int main() {
  struct _i_session i_session;
  int ret;
  char redirect_to[4097] = {0}, * id_token_payload;

  y_init_logs("iddawc tests", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Glewlwyd OIDC example");

  i_init_session(&i_session);
  i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_ID_TOKEN|I_RESPONSE_TYPE_CODE,
                                                        I_OPT_OPENID_CONFIG_ENDPOINT, CONFIG_ENDPOINT,
                                                        I_OPT_CLIENT_ID, CLIENT_ID,
                                                        I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                        I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                        I_OPT_SCOPE, SCOPE,
                                                        I_OPT_STATE_GENERATE, 16,
                                                        I_OPT_NONCE_GENERATE, 32,
                                                        I_OPT_NONE);
  if (i_load_openid_config(&i_session) != I_OK) {
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
  
  // And finally we load user info using the access token
  if (i_load_userinfo(&i_session) != I_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Error loading userinfo");
    i_clean_session(&i_session);
    return 1;
  }

  y_log_message(Y_LOG_LEVEL_DEBUG, "userinfo:\n%s", i_get_str_parameter(&i_session, I_OPT_USERINFO));
  
  // Cleanup session
  i_clean_session(&i_session);
  y_close_logs();

  return 0;
}
