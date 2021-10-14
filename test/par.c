/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <jansson.h>
#include <check.h>
#include <yder.h>
#include <iddawc.h>

#define PAR_ERROR "invalid_request"
#define PAR_ERROR_DESCRIPTION "invalid_request description"
#define PAR_ERROR_URI "https://as.tld/#error"
#define CLIENT_ID "client"
#define CLIENT_SECRET "client_secret"
#define CLIENT_REDIRECT "https://client.tld"
#define PUSHED_AUTH_REQ_ENDPOINT "http://localhost:8080/par"
#define AUTH_ENDPOINT "http://localhost:8080/auth"
#define TOKEN_ENDPOINT "http://localhost:8080/token"
#define SCOPE "scope1 scope2"
#define REQUEST_URI "request_uri_abcd1234"
#define EXPIRES_IN 90
#define CLAIM1 "claim1"
#define CLAIM2 "claim2"
#define CLAIM1_VALUE "248289761001"
#define CLAIM1_CONTENT "{\"value\":\""CLAIM1_VALUE"\"}"
#define RESOURCE_INDICATOR "https://resource.iddawc.tld/"

int callback_par_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_response = json_pack("{sssi}", "request_uri", REQUEST_URI, "expires_in", EXPIRES_IN);
  ulfius_set_json_body_response(response, 201, j_response);
  json_decref(j_response);
  return U_CALLBACK_CONTINUE;
}

int callback_par_claims_resource_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_response = json_pack("{sssi}", "request_uri", REQUEST_URI, "expires_in", EXPIRES_IN), * j_claims = json_pack("{s{so}s{s{so}}}", "userinfo", CLAIM1, json_loads(CLAIM1_CONTENT, JSON_DECODE_ANY, NULL), "id_token", CLAIM2, "essential", json_false());
  char * str_claims = json_dumps(j_claims, JSON_COMPACT);
  ck_assert_str_eq(u_map_get(request->map_post_body, "claims"), str_claims);
  ck_assert_str_eq(u_map_get(request->map_post_body, "resource"), RESOURCE_INDICATOR);
  ulfius_set_json_body_response(response, 201, j_response);
  json_decref(j_claims);
  json_decref(j_response);
  o_free(str_claims);
  return U_CALLBACK_CONTINUE;
}

int callback_par_invalid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_error = json_pack("{ssssss}", "error", PAR_ERROR, "error_description", PAR_ERROR_DESCRIPTION, "error_uri", PAR_ERROR_URI);
  ulfius_set_json_body_response(response, 400, j_error);
  json_decref(j_error);
  return U_CALLBACK_CONTINUE;
}

int callback_par_unauthorized (const struct _u_request * request, struct _u_response * response, void * user_data) {
  response->status = 403;
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_iddawc_par_invalid_parameters)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/par", 0, &callback_par_invalid, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/par_403", 0, &callback_par_unauthorized, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_par_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_par_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_par_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_par_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_par_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_REDIRECT_URI, CLIENT_REDIRECT,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_par_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_PUSHED_AUTH_REQ_ENDPOINT, PUSHED_AUTH_REQ_ENDPOINT,
                                                    I_OPT_REDIRECT_URI, CLIENT_REDIRECT,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_par_request(&i_session), I_ERROR_PARAM);
  ck_assert_str_eq(PAR_ERROR, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_str_eq(PAR_ERROR_DESCRIPTION, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_str_eq(PAR_ERROR_URI, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_REDIRECT_URI, CLIENT_REDIRECT,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_PUSHED_AUTH_REQ_ENDPOINT, PUSHED_AUTH_REQ_ENDPOINT "_403",
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_par_request(&i_session), I_ERROR_UNAUTHORIZED);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_par_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/par", 0, &callback_par_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_REDIRECT_URI, CLIENT_REDIRECT,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_PUSHED_AUTH_REQ_ENDPOINT, PUSHED_AUTH_REQ_ENDPOINT,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_par_request(&i_session), I_OK);
  ck_assert_str_eq(REQUEST_URI, i_get_str_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_URI));
  ck_assert_int_eq(EXPIRES_IN, i_get_int_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN));
  ck_assert_int_eq(I_OK, i_build_auth_url_get(&i_session));
  ck_assert_ptr_ne(NULL, o_strstr(i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO), AUTH_ENDPOINT));
  ck_assert_ptr_ne(NULL, o_strstr(i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO), "request_uri=" REQUEST_URI));
  ck_assert_ptr_ne(NULL, o_strstr(i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO), "client_id=" CLIENT_ID));
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_par_claims_resource_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/par", 0, &callback_par_claims_resource_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_REDIRECT_URI, CLIENT_REDIRECT,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_PUSHED_AUTH_REQ_ENDPOINT, PUSHED_AUTH_REQ_ENDPOINT,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_RESOURCE_INDICATOR, RESOURCE_INDICATOR,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(I_OK, i_add_claim_request(&i_session, I_CLAIM_TARGET_USERINFO, CLAIM1, I_CLAIM_ESSENTIAL_IGNORE, CLAIM1_CONTENT));
  ck_assert_int_eq(I_OK, i_add_claim_request(&i_session, I_CLAIM_TARGET_ID_TOKEN, CLAIM2, I_CLAIM_ESSENTIAL_FALSE, NULL));
  ck_assert_int_eq(i_run_par_request(&i_session), I_OK);
  ck_assert_str_eq(REQUEST_URI, i_get_str_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_URI));
  ck_assert_int_eq(EXPIRES_IN, i_get_int_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN));
  ck_assert_int_eq(I_OK, i_build_auth_url_get(&i_session));
  ck_assert_ptr_ne(NULL, o_strstr(i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO), AUTH_ENDPOINT));
  ck_assert_ptr_ne(NULL, o_strstr(i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO), "request_uri=" REQUEST_URI));
  ck_assert_ptr_ne(NULL, o_strstr(i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO), "client_id=" CLIENT_ID));
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

static Suite *iddawc_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Iddawc pushed authorization requests tests");
  tc_core = tcase_create("test_iddawc_par");
  tcase_add_test(tc_core, test_iddawc_par_invalid_parameters);
  tcase_add_test(tc_core, test_iddawc_par_valid);
  tcase_add_test(tc_core, test_iddawc_par_claims_resource_valid);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc pushed authrozation requests tests");
  i_global_init();
  s = iddawc_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  i_global_close();
  //y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
