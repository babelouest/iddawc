/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <iddawc.h>

#define SCOPE1 "scope1"
#define SCOPE2 "scope2"
#define SCOPE_LIST "scope1 scope2"
#define STATE "stateXyz1234"
#define REDIRECT_URI "https://iddawc.tld"
#define REDIRECT_TO "https://iddawc.tld#access_token=plop"
#define CLIENT_ID "clientXyz1234"
#define CLIENT_SECRET "secretXyx1234"
#define TOKEN_ENDPOINT "http://localhost:8080/token"
#define ACCESS_TOKEN_VALIDATION_ENDPOINT "https://isp.tld/profile"
#define CODE "codeXyz1234"
#define REFRESH_TOKEN "refreshXyz1234"
#define ACCESS_TOKEN "accessXyz1234"
#define TOKEN_TYPE "typeXyz1234"
#define EXPIRES_IN 3600
#define ID_TOKEN "idTokenXyz1234"
#define ERROR "errorXyz1234"
#define ERROR_DESCRIPTION "errorDescriptionXyz1234"
#define ERROR_URI "errorUriXyz1234"
#define GLEWLWYD_API_URL "https://glewlwyd.tld/api"
#define GLEWLWYD_COOKIE_SESSION "cookieXyz1234"
#define USERNAME "dev"
#define USER_PASSWORD "password"

int callback_oauth2_token_invalid_request (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * error = json_pack("{ssssss}", 
                             "error", "invalid_request",
                             "error_description", "invalid_request description",
                             "error_uri", "invalid_request uri");
  ulfius_set_json_body_response(response, 400, error);
  json_decref(error);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_token_invalid_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * error = json_pack("{ssssss}", 
                             "error", "invalid_client",
                             "error_description", "invalid_client description",
                             "error_uri", "invalid_client uri");
  ulfius_set_json_body_response(response, 400, error);
  json_decref(error);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_token_invalid_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * error = json_pack("{ssssss}", 
                             "error", "invalid_grant",
                             "error_description", "invalid_grant description",
                             "error_uri", "invalid_grant uri");
  ulfius_set_json_body_response(response, 400, error);
  json_decref(error);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_token_unauthorized_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * error = json_pack("{ssssss}", 
                             "error", "unauthorized_client",
                             "error_description", "unauthorized_client description",
                             "error_uri", "unauthorized_client uri");
  ulfius_set_json_body_response(response, 400, error);
  json_decref(error);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_token_unsupported_grant_type (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * error = json_pack("{ssssss}", 
                             "error", "unsupported_grant_type",
                             "error_description", "unsupported_grant_type description",
                             "error_uri", "unsupported_grant_type uri");
  ulfius_set_json_body_response(response, 400, error);
  json_decref(error);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_token_invalid_scope (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * error = json_pack("{ssssss}", 
                             "error", "invalid_scope",
                             "error_description", "invalid_scope description",
                             "error_uri", "invalid_scope uri");
  ulfius_set_json_body_response(response, 400, error);
  json_decref(error);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_token_code_ok (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * result = json_pack("{sssssiss}", 
                             "access_token", "2YotnFZFEjr1zCsicMWpAA",
                             "token_type", "bearer",
                             "expires_in", 3600,
                             "refresh_token", "tGzv3JOkF0XG5Qx2TlKWIA");
  ulfius_set_json_body_response(response, 200, result);
  json_decref(result);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_token_access_token_ok (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * result = json_pack("{sssssi}", 
                             "access_token", "2YotnFZFEjr1zCsicMWpAA",
                             "token_type", "bearer",
                             "expires_in", 3600);
  ulfius_set_json_body_response(response, 200, result);
  json_decref(result);
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_iddawc_token_code_invalid_parameters)
{
  struct _i_session i_session;
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_CODE, CODE,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_CODE, CODE,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_CODE, CODE,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);
  
}
END_TEST

START_TEST(test_iddawc_token_code_invalid_request)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_invalid_request, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_CODE, CODE,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_request");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "invalid_request description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "invalid_request uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_code_invalid_client)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_invalid_client, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_CLIENT_ID, "error",
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_CODE, CODE,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_client");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "invalid_client description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "invalid_client uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_code_invalid_grant)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_invalid_grant, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_CODE, "error",
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_grant");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "invalid_grant description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "invalid_grant uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_code_unauthorized_client)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_unauthorized_client, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_CLIENT_ID, "error",
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_CODE, CODE,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "unauthorized_client");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "unauthorized_client description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "unauthorized_client uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_code_unsupported_grant_type)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_unsupported_grant_type, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_CODE, CODE,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "unsupported_grant_type");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "unsupported_grant_type description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "unsupported_grant_type uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_code_invalid_scope)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_invalid_scope, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_CODE, CODE,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_scope");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "invalid_scope description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "invalid_scope uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_code_ok)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_code_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_CODE, CODE,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), "bearer");
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 3600);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_password_invalid_parameters)
{
  struct _i_session i_session;

  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_PASSWORD,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_USERNAME, USERNAME,
                                                  I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_PASSWORD,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_PASSWORD,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_USERNAME, USERNAME,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);
  
}
END_TEST

START_TEST(test_iddawc_token_password_noclient_invalid_request)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_invalid_request, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_PASSWORD,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_USERNAME, USERNAME,
                                                  I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_request");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "invalid_request description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "invalid_request uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_password_noclient_unsupported_grant_type)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_unsupported_grant_type, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_PASSWORD,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_USERNAME, USERNAME,
                                                  I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "unsupported_grant_type");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "unsupported_grant_type description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "unsupported_grant_type uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_password_noclient_invalid_scope)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_invalid_scope, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_PASSWORD,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_USERNAME, USERNAME,
                                                  I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_scope");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "invalid_scope description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "invalid_scope uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_password_noclient_ok)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_code_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_PASSWORD,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_USERNAME, USERNAME,
                                                  I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), "bearer");
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 3600);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_password_client_invalid_client)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_invalid_client, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_PASSWORD,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_CLIENT_ID, "error",
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_USERNAME, USERNAME,
                                                  I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_client");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "invalid_client description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "invalid_client uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_password_noclient_unauthorized_client)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_unauthorized_client, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_PASSWORD,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, "error",
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_USERNAME, USERNAME,
                                                  I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "unauthorized_client");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "unauthorized_client description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "unauthorized_client uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_password_client_ok)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_code_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_PASSWORD,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_USERNAME, USERNAME,
                                                  I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), "bearer");
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 3600);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_client_credentials_client_invalid_client)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_invalid_client, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CLIENT_CREDENTIALS,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_CLIENT_ID, "error",
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_client");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "invalid_client description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "invalid_client uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_client_credentials_client_unauthorized_client)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_unauthorized_client, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CLIENT_CREDENTIALS,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, "error",
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "unauthorized_client");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "unauthorized_client description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "unauthorized_client uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_client_credentials_client_ok)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_access_token_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CLIENT_CREDENTIALS,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), "bearer");
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 3600);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_refresh_token_noclient_invalid_parameters)
{
  struct _i_session i_session;
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_REFRESH_TOKEN,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_REFRESH_TOKEN, REFRESH_TOKEN,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);

  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_REFRESH_TOKEN,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);

}
END_TEST

START_TEST(test_iddawc_token_refresh_token_noclient_invalid_grant)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_invalid_grant, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_REFRESH_TOKEN,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_CLIENT_ID, "error",
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_REFRESH_TOKEN, "error",
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_grant");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "invalid_grant description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "invalid_grant uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_refresh_token_noclient_unauthorized_client)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_unauthorized_client, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_REFRESH_TOKEN,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_REFRESH_TOKEN, "error",
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "unauthorized_client");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "unauthorized_client description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "unauthorized_client uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_refresh_token_noclient_invalid_client)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_invalid_client, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_REFRESH_TOKEN,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_REFRESH_TOKEN, "error",
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_client");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "invalid_client description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "invalid_client uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_refresh_token_noclient_ok)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_access_token_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_REFRESH_TOKEN,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_REFRESH_TOKEN, REFRESH_TOKEN,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), "bearer");
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 3600);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

static Suite *iddawc_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Iddawc id_token tests");
  tc_core = tcase_create("test_iddawc_oken");
  tcase_add_test(tc_core, test_iddawc_token_code_invalid_parameters);
  tcase_add_test(tc_core, test_iddawc_token_code_invalid_request);
  tcase_add_test(tc_core, test_iddawc_token_code_invalid_client);
  tcase_add_test(tc_core, test_iddawc_token_code_invalid_grant);
  tcase_add_test(tc_core, test_iddawc_token_code_unauthorized_client);
  tcase_add_test(tc_core, test_iddawc_token_code_unsupported_grant_type);
  tcase_add_test(tc_core, test_iddawc_token_code_invalid_scope);
  tcase_add_test(tc_core, test_iddawc_token_code_ok);
  tcase_add_test(tc_core, test_iddawc_token_password_invalid_parameters);
  tcase_add_test(tc_core, test_iddawc_token_password_noclient_invalid_request);
  tcase_add_test(tc_core, test_iddawc_token_password_noclient_unsupported_grant_type);
  tcase_add_test(tc_core, test_iddawc_token_password_noclient_invalid_scope);
  tcase_add_test(tc_core, test_iddawc_token_password_noclient_ok);
  tcase_add_test(tc_core, test_iddawc_token_password_client_invalid_client);
  tcase_add_test(tc_core, test_iddawc_token_password_noclient_unauthorized_client);
  tcase_add_test(tc_core, test_iddawc_token_password_client_ok);
  tcase_add_test(tc_core, test_iddawc_token_client_credentials_client_invalid_client);
  tcase_add_test(tc_core, test_iddawc_token_client_credentials_client_unauthorized_client);
  tcase_add_test(tc_core, test_iddawc_token_client_credentials_client_ok);
  tcase_add_test(tc_core, test_iddawc_token_refresh_token_noclient_invalid_parameters);
  tcase_add_test(tc_core, test_iddawc_token_refresh_token_noclient_invalid_grant);
  tcase_add_test(tc_core, test_iddawc_token_refresh_token_noclient_unauthorized_client);
  tcase_add_test(tc_core, test_iddawc_token_refresh_token_noclient_invalid_client);
  tcase_add_test(tc_core, test_iddawc_token_refresh_token_noclient_ok);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc token tests");
  s = iddawc_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
