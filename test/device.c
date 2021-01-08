/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <jansson.h>
#include <check.h>
#include <yder.h>
#include <iddawc.h>

#define DEVICE_ERROR "invalid_request"
#define DEVICE_ERROR_DESCRIPTION "invalid_request description"
#define DEVICE_ERROR_URI "https://as.tld/#error"
#define CLIENT_ID "client"
#define CLIENT_SECRET "client_secret"
#define DEVICE_AUTHORIZATION_ENDPOINT "http://localhost:8080/device"
#define TOKEN_ENDPOINT "http://localhost:8080/token"
#define SCOPE "scope1 scope2"
#define DEVICE_AUTH_CODE "deviceCode1234"
#define DEVICE_AUTH_USER_CODE "deviceUserCode1234"
#define DEVICE_AUTH_VERIFICATION_URI "https://isp.tld/deviceUserAuth"
#define DEVICE_AUTH_VERIFICATION_URI_COMPLETE "https://isp.tld/deviceUserAuth?code=deviceUserCode1234"
#define DEVICE_AUTH_EXPIRES_IN 90
#define DEVICE_AUTH_INTERVAL 5
#define ACCESS_TOKEN "2YotnFZFEjr1zCsicMWpAA"
#define REFRESH_TOKEN "tGzv3JOkF0XG5Qx2TlKWIA"
#define EXPIRES_IN 3600
#define TOKEN_TYPE "bearer"

int callback_device_token_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * result = json_pack("{sssssiss}", 
                             "access_token", ACCESS_TOKEN,
                             "token_type", TOKEN_TYPE,
                             "expires_in", EXPIRES_IN,
                             "refresh_token", REFRESH_TOKEN);
  ulfius_set_json_body_response(response, 200, result);
  json_decref(result);
  return U_CALLBACK_CONTINUE;
}

int callback_device_token_invalid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_error = json_pack("{ssssss}", "error", DEVICE_ERROR, "error_description", DEVICE_ERROR_DESCRIPTION, "error_uri", DEVICE_ERROR_URI);
  ulfius_set_json_body_response(response, 400, j_error);
  json_decref(j_error);
  return U_CALLBACK_CONTINUE;
}

int callback_device_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_error = json_pack("{ss ss ss ss si si}", 
                               "device_code", DEVICE_AUTH_CODE, 
                               "user_code", DEVICE_AUTH_USER_CODE, 
                               "verification_uri", DEVICE_AUTH_VERIFICATION_URI,
                               "verification_uri_complete", DEVICE_AUTH_VERIFICATION_URI_COMPLETE,
                               "expires_in", DEVICE_AUTH_EXPIRES_IN,
                               "interval", DEVICE_AUTH_INTERVAL);
  ulfius_set_json_body_response(response, 200, j_error);
  json_decref(j_error);
  return U_CALLBACK_CONTINUE;
}

int callback_device_invalid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_error = json_pack("{ssssss}", "error", DEVICE_ERROR, "error_description", DEVICE_ERROR_DESCRIPTION, "error_uri", DEVICE_ERROR_URI);
  ulfius_set_json_body_response(response, 400, j_error);
  json_decref(j_error);
  return U_CALLBACK_CONTINUE;
}

int callback_device_unauthorized (const struct _u_request * request, struct _u_response * response, void * user_data) {
  response->status = 403;
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_iddawc_device_auth_invalid_parameters)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/device", 0, &callback_device_invalid, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/device_403", 0, &callback_device_unauthorized, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, DEVICE_AUTHORIZATION_ENDPOINT,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_str_eq(DEVICE_ERROR, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_str_eq(DEVICE_ERROR_DESCRIPTION, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_str_eq(DEVICE_ERROR_URI, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, DEVICE_AUTHORIZATION_ENDPOINT "_403",
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_ERROR_UNAUTHORIZED);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_device_auth_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/device", 0, &callback_device_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, DEVICE_AUTHORIZATION_ENDPOINT,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_OK);
  ck_assert_str_eq(DEVICE_AUTH_CODE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_CODE));
  ck_assert_str_eq(DEVICE_AUTH_USER_CODE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_USER_CODE));
  ck_assert_str_eq(DEVICE_AUTH_VERIFICATION_URI, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI));
  ck_assert_str_eq(DEVICE_AUTH_VERIFICATION_URI_COMPLETE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE));
  ck_assert_int_eq(DEVICE_AUTH_EXPIRES_IN, i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_EXPIRES_IN));
  ck_assert_int_eq(DEVICE_AUTH_INTERVAL, i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_INTERVAL));
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_device_auth_token_invalid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/device", 0, &callback_device_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_device_token_invalid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, DEVICE_AUTHORIZATION_ENDPOINT,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_OK);
  ck_assert_str_eq(DEVICE_AUTH_CODE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_CODE));
  ck_assert_str_eq(DEVICE_AUTH_USER_CODE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_USER_CODE));
  ck_assert_str_eq(DEVICE_AUTH_VERIFICATION_URI, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI));
  ck_assert_str_eq(DEVICE_AUTH_VERIFICATION_URI_COMPLETE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE));
  ck_assert_int_eq(DEVICE_AUTH_EXPIRES_IN, i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_EXPIRES_IN));
  ck_assert_int_eq(DEVICE_AUTH_INTERVAL, i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_INTERVAL));
  
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_str_eq(DEVICE_ERROR, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_str_eq(DEVICE_ERROR_DESCRIPTION, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_str_eq(DEVICE_ERROR_URI, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_device_auth_token_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/device", 0, &callback_device_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_device_token_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, DEVICE_AUTHORIZATION_ENDPOINT,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_OK);
  ck_assert_str_eq(DEVICE_AUTH_CODE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_CODE));
  ck_assert_str_eq(DEVICE_AUTH_USER_CODE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_USER_CODE));
  ck_assert_str_eq(DEVICE_AUTH_VERIFICATION_URI, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI));
  ck_assert_str_eq(DEVICE_AUTH_VERIFICATION_URI_COMPLETE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE));
  ck_assert_int_eq(DEVICE_AUTH_EXPIRES_IN, i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_EXPIRES_IN));
  ck_assert_int_eq(DEVICE_AUTH_INTERVAL, i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_INTERVAL));
  
  ck_assert_int_eq(i_run_token_request(&i_session), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), ACCESS_TOKEN);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), REFRESH_TOKEN);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), TOKEN_TYPE);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), EXPIRES_IN);
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

static Suite *iddawc_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Iddawc device tests");
  tc_core = tcase_create("test_iddawc_device");
  tcase_add_test(tc_core, test_iddawc_device_auth_invalid_parameters);
  tcase_add_test(tc_core, test_iddawc_device_auth_valid);
  tcase_add_test(tc_core, test_iddawc_device_auth_token_invalid);
  tcase_add_test(tc_core, test_iddawc_device_auth_token_valid);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc device tests");
  i_global_init();
  s = iddawc_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  i_global_close();
  y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
