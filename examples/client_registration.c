/**
 * Client registration using Iddawc library
 * - Register
 * - Get registration
 * - Update registration
 * - Delete registration
 *
 * Copyright 2022 Nicolas Mora <mail@babelouest.org>
 *
 * License MIT
 *
 * Compile with
 * gcc -o client_registration client_registration.c -liddawc -lyder -ljansson
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
#define REGISTRATION_ENDPOINT "https://auth.tld/register"

/**
 * Access token used to authenticate the registration
 */
#define REGISTRATION_ACCESS_TOKEN "abcdXyz1234"

/**
 * New client redirect_uri
 */
#define NEW_CLIENT_REDIRECT_URI "https://client.example.org/callback"
#define UPDATED_CLIENT_REDIRECT_URI "https://client.example.org/callback_updated"

#define REGISTRATION_PARAMETERS "{"\
"\"redirect_uris\": [\""NEW_CLIENT_REDIRECT_URI"\",\"https://client.example.org/callback2\"],"\
"\"client_name\": \"My Example Client\","\
"\"client_name#ja-Jpan-JP\":\"\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D\","\
"\"token_endpoint_auth_method\": \"client_secret_basic\","\
"\"policy_uri\": \"https://client.example.org/policy.html\","\
"\"jwks\": {\"keys\": [{\"e\": \"AQAB\",\"n\": \"nj3YJwsLUFl9BmpAb"\
"kOswCNVx17Eh9wMO-_AReZwBqfaWFcfGHrZXsIV2VMCNVNU8Tpb4obUaSXcRcQ-VM"\
"sfQPJm9IzgtRdAY8NN8Xb7PEcYyklBjvTtuPbpzIaqyiUepzUXNDFuAOOkrIol3Wm"\
"flPUUgMKULBN0EUd1fpOD70pRM0rlp_gg_WNUKoW1V-3keYUJoXH9NztEDm_D2MQX"\
"j9eGOJJ8yPgGL8PAZMLe2R7jb9TxOCPDED7tY_TU4nFPlxptw59A42mldEmViXsKQ"\
"t60s1SLboazxFKveqXC_jpLUt22OC6GUG63p-REw-ZOr3r845z50wMuzifQrMI9bQ"\
"\",\"kty\": \"RSA\"}]},"\
"\"example_extension_parameter\": \"example_value\""\
"}"

int main() {
  struct _i_session i_session;
  json_t * j_register_params = NULL, * j_register_result = NULL;
  char * str_result = NULL;

  y_init_logs("iddawc tests", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Client registration example");

  i_init_session(&i_session);
  i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                   I_OPT_OPENID_CONFIG_ENDPOINT, CONFIG_ENDPOINT,
                                   I_OPT_ACCESS_TOKEN, REGISTRATION_ACCESS_TOKEN,
                                   I_OPT_NONE);
  if (i_get_openid_config(&i_session) != I_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Error loading openid config");
    i_clean_session(&i_session);
    return 1;
  }
  
  // Build registration parameter object
  // At least one redirect_uri is the minimal parameter for registration
  j_register_params = json_loads("{\"redirect_uris\":[\""NEW_CLIENT_REDIRECT_URI"\"]}", JSON_DECODE_ANY, NULL);
  
  // Other parameters can be set during the registration, depending on the AS and your requirements for the new client
  //j_register_params = json_loads(REGISTRATION_PARAMETERS, JSON_DECODE_ANY, NULL);
  
  // Run registration command and set the parameter update_session to 1 so the i_session structure will be updated with the results on success
  // Especially, the registration access token provided by the AS will be stored in the I_OPT_ACCESS_TOKEN property
  // Be careful to save this token before running a token endpoint
  if (i_register_client(&i_session, j_register_params, 1, &j_register_result) != I_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Error registering client");
    i_clean_session(&i_session);
    json_decref(j_register_params);
    return 1;
  }
  str_result = json_dumps(j_register_result, JSON_INDENT(2));
  y_log_message(Y_LOG_LEVEL_INFO, "Registration result: %s", str_result);
  i_free(str_result);
  json_decref(j_register_result);

  // Run the get registration command
  if (i_get_registration_client(&i_session, &j_register_result) != I_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Error registering client");
    i_clean_session(&i_session);
    return 1;
  }
  str_result = json_dumps(j_register_result, JSON_INDENT(2));
  y_log_message(Y_LOG_LEVEL_INFO, "Get registration result: %s", str_result);
  i_free(str_result);
  json_decref(j_register_result);

  // Update the client registration with a new redirect_uri and a new name
  j_register_params = json_loads(REGISTRATION_PARAMETERS, JSON_DECODE_ANY, NULL);
  json_array_append_new(json_object_get(j_register_params, "redirect_uris"), json_string(UPDATED_CLIENT_REDIRECT_URI));
  json_object_set_new(j_register_params, "client_name", json_string("My updated client name"));
  
  if (i_manage_registration_client(&i_session, j_register_params, 1, &j_register_result) != I_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Error updating client registration");
    i_clean_session(&i_session);
    json_decref(j_register_params);
    return 1;
  }
  str_result = json_dumps(j_register_result, JSON_INDENT(2));
  y_log_message(Y_LOG_LEVEL_INFO, "Registration management result: %s", str_result);
  i_free(str_result);
  json_decref(j_register_result);
  
  // Delete the client registration
  if (i_delete_registration_client(&i_session) != I_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Error deleting client registration");
    i_clean_session(&i_session);
    return 1;
  }
  
  // Cleanup session
  i_clean_session(&i_session);
  json_decref(j_register_params);
  y_close_logs();

  return 0;
}
