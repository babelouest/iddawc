/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <iddawc.h>

#define USERINFO_NAME "Dave Lopper"
#define USERINFO_AUD "abcdxyz"
#define USERINFO_EMAIL "dev@iddawc.tld"
#define ACCESS_TOKEN "accessXyz1234"

static char userinfo_json[] = "{"\
  "\"name\":\"" USERINFO_NAME "\","\
  "\"aud\":\"" USERINFO_AUD "\","\
  "\"email\":\"" USERINFO_EMAIL "\""\
"}";

static char userinfo_char[] = USERINFO_NAME ";" USERINFO_AUD ";" USERINFO_EMAIL;

int callback_openid_userinfo_valid_json (const struct _u_request * request, struct _u_response * response, void * user_data) {
  if (0 == o_strcmp(u_map_get(request->map_header, "Authorization"), "Bearer " ACCESS_TOKEN)) {
    json_t * j_response = json_loads(userinfo_json, JSON_DECODE_ANY, NULL);
    ulfius_set_json_body_response(response, 200, j_response);
    json_decref(j_response);
  } else {
    response->status = 401;
  }
  return U_CALLBACK_CONTINUE;
}

int callback_openid_userinfo_valid_char (const struct _u_request * request, struct _u_response * response, void * user_data) {
  if (0 == o_strcmp(u_map_get(request->map_header, "Authorization"), "Bearer " ACCESS_TOKEN)) {
    ulfius_set_string_body_response(response, 200, userinfo_char);
  } else {
    response->status = 401;
  }
  return U_CALLBACK_CONTINUE;
}

int callback_openid_userinfo_valid_empty_result (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_CALLBACK_CONTINUE;
}

int callback_openid_userinfo_invalid_response (const struct _u_request * request, struct _u_response * response, void * user_data) {
  response->status = 401;
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_iddawc_userinfo_invalid_parameters)
{
  struct _i_session i_session;
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_load_userinfo(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_USERINFO_ENDPOINT, "http://localhost:8080/userinfo",
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_load_userinfo(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_userinfo_invalid_response)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_openid_userinfo_invalid_response, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_USERINFO_ENDPOINT, "http://localhost:8080/userinfo",
                                                    I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_load_userinfo(&i_session), I_ERROR_UNAUTHORIZED);
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_userinfo_response_unauthorized)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_openid_userinfo_valid_json, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_USERINFO_ENDPOINT, "http://localhost:8080/userinfo",
                                                    I_OPT_ACCESS_TOKEN, "error",
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_load_userinfo(&i_session), I_ERROR_UNAUTHORIZED);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_USERINFO), NULL);
  ck_assert_ptr_eq(i_session.j_userinfo, NULL);
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_userinfo_response_empty)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_openid_userinfo_valid_empty_result, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_USERINFO_ENDPOINT, "http://localhost:8080/userinfo",
                                                    I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_load_userinfo(&i_session), I_ERROR);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_USERINFO), NULL);
  ck_assert_ptr_eq(i_session.j_userinfo, NULL);
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_userinfo_response_char)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_openid_userinfo_valid_char, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_USERINFO_ENDPOINT, "http://localhost:8080/userinfo",
                                                    I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_load_userinfo(&i_session), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_USERINFO), userinfo_char);
  ck_assert_ptr_eq(i_session.j_userinfo, NULL);
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_userinfo_response_json)
{
  struct _i_session i_session;
  struct _u_instance instance;
  json_t * j_userinfo = json_loads(userinfo_json, JSON_DECODE_ANY, NULL);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_openid_userinfo_valid_json, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_USERINFO_ENDPOINT, "http://localhost:8080/userinfo",
                                                    I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_load_userinfo(&i_session), I_OK);
  ck_assert_int_eq(json_equal(i_session.j_userinfo, j_userinfo), 1);
  i_clean_session(&i_session);
  json_decref(j_userinfo);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

static Suite *iddawc_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Iddawc oauth2 flow tests");
  tc_core = tcase_create("test_iddawc_oauth2");
  tcase_add_test(tc_core, test_iddawc_userinfo_invalid_parameters);
  tcase_add_test(tc_core, test_iddawc_userinfo_invalid_response);
  tcase_add_test(tc_core, test_iddawc_userinfo_response_unauthorized);
  tcase_add_test(tc_core, test_iddawc_userinfo_response_empty);
  tcase_add_test(tc_core, test_iddawc_userinfo_response_char);
  tcase_add_test(tc_core, test_iddawc_userinfo_response_json);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc oidc openid-configuration loader tests");
  s = iddawc_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
