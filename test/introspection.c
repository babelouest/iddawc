/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <jansson.h>
#include <check.h>
#include <yder.h>
#include <iddawc.h>

#define TOKEN "accessTokenXyz1234"

const char result[] = "{\"active\":true,\"client_id\":\"l238j323ds-23ij4\",\"username\":\"jdoe\",\"scope\":\"read write dolphin\",\"sub\":\"Z5O3upPC88QrAjx00dis\",\"aud\":\"https://protected.example.net/resource\",\"iss\":\"https://server.example.com/\",\"exp\":1419356238,\"iat\":1419350238,\"extension_field\":\"twenty-seven\"}";

int callback_introspect (const struct _u_request * request, struct _u_response * response, void * user_data) {
  if (0 == o_strcmp("Bearer "TOKEN, u_map_get(request->map_header, "Authorization"))) {
    if (0 == o_strcmp(TOKEN, u_map_get(request->map_post_body, "token"))) {
      json_t * j_response = json_loads(result, JSON_DECODE_ANY, NULL);
      ulfius_set_json_body_response(response, 200, j_response);
      json_decref(j_response);
    } else {
      json_t * j_response = json_loads("{\"active\":false}", JSON_DECODE_ANY, NULL);
      ulfius_set_json_body_response(response, 200, j_response);
      json_decref(j_response);
    }
  } else {
    response->status = 403;
  }
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_iddawc_introspection_invalid)
{
  struct _i_session i_session;
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_introspect_token(&i_session, NULL), I_ERROR_PARAM);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_INTROSPECTION_ENDPOINT, "http://localhost:8080/introspect"), I_OK);
  ck_assert_int_eq(i_introspect_token(&i_session, NULL), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_INTROSPECTION_ENDPOINT, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TOKEN_TARGET, TOKEN), I_OK);
  ck_assert_int_eq(i_introspect_token(&i_session, NULL), I_ERROR_PARAM);
  
  i_clean_session(&i_session);
  
}
END_TEST

START_TEST(test_iddawc_introspection_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  json_t * j_result = NULL, * j_expected;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/introspect", 0, &callback_introspect, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_INTROSPECTION_ENDPOINT, "http://localhost:8080/introspect",
                                                  I_OPT_ACCESS_TOKEN, TOKEN,
                                                  I_OPT_TOKEN_TARGET, TOKEN,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_introspect_token(&i_session, &j_result), I_OK);
  j_expected = json_loads(result, JSON_DECODE_ANY, NULL);
  ck_assert_int_eq(1, json_equal(j_expected, j_result));
  i_clean_session(&i_session);
  json_decref(j_result);
  json_decref(j_expected);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_INTROSPECTION_ENDPOINT, "http://localhost:8080/introspect",
                                                  I_OPT_ACCESS_TOKEN, TOKEN,
                                                  I_OPT_TOKEN_TARGET, TOKEN "error",
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_introspect_token(&i_session, &j_result), I_OK);
  j_expected = json_loads("{\"active\":false}", JSON_DECODE_ANY, NULL);
  ck_assert_int_eq(1, json_equal(j_expected, j_result));
  i_clean_session(&i_session);
  json_decref(j_result);
  json_decref(j_expected);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_INTROSPECTION_ENDPOINT, "http://localhost:8080/introspect",
                                                  I_OPT_ACCESS_TOKEN, TOKEN "error",
                                                  I_OPT_TOKEN_TARGET, TOKEN,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_introspect_token(&i_session, NULL), I_ERROR_PARAM);
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

static Suite *iddawc_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Iddawc token introspection tests");
  tc_core = tcase_create("test_iddawc_introspection");
  tcase_add_test(tc_core, test_iddawc_introspection_invalid);
  tcase_add_test(tc_core, test_iddawc_introspection_valid);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc token introspection tests");
  s = iddawc_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  //y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
