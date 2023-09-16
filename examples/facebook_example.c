/**
 * Facebook OAuth2 example using Iddawc library
 * 
 * Copyright 2020-2021 Nicolas Mora <mail@babelouest.org>
 *
 * License MIT
 * 
 * Compile with
 * gcc -o facebook_example facebook_example.c -liddawc -lyder
 */
#include <stdio.h>
#include <string.h>
#include <yder.h>
#include <iddawc.h>

/**
 * These are the specific values for Facebook OAuth2 API at the time this code was written
 */
#define AUTH_ENDPOINT "https://www.facebook.com/v5.0/dialog/oauth"
#define TOKEN_ENDPOINT "https://graph.facebook.com/v5.0/oauth/access_token"
#define USERINFO_ENDPOINT "https://graph.facebook.com/v5.0/me?fields=id,name,email"

/**
 * Update the values below with your client values
 * Register a new OAuth2 client for Facebook:
 * https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow/
 */
#define CLIENT_ID "clientXyz"
#define CLIENT_SECRET "secretXyz"
#define REDIRECT_URI "https://www.example.com/"

int main() {
  struct _i_session i_session;
  int ret;
  char redirect_to[4097] = {0};

  y_init_logs("iddawc tests", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Facebook OAuth2 example");

  i_init_session(&i_session);
  i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                   I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                   I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                   I_OPT_USERINFO_ENDPOINT, USERINFO_ENDPOINT,
                                   I_OPT_CLIENT_ID, CLIENT_ID,
                                   I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                   I_OPT_TOKEN_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                   I_OPT_REDIRECT_URI, REDIRECT_URI,
                                   I_OPT_STATE_GENERATE, 16,
                                   I_OPT_NONE);
  // First step: get redirection to login page
  if ((ret = i_build_auth_url_get(&i_session)) != I_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Error building auth request: %d", ret);
    i_clean_session(&i_session);
    return 1;
  }
  printf("Redirect to:\n%s\n", i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO));

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
  if (i_get_userinfo(&i_session, 0) != I_OK) {
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
