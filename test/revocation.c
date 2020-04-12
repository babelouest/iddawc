/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <jansson.h>
#include <check.h>
#include <yder.h>
#include <iddawc.h>

#define TOKEN "accessTokenXyz1234"

int callback_revoke (const struct _u_request * request, struct _u_response * response, void * user_data) {
  if (0 != o_strcmp("Bearer "TOKEN, u_map_get(request->map_header, "Authorization"))) {
    response->status = 403;
  }
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_iddawc_revocation_invalid)
{
  struct _i_session i_session;
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_revoke_token(&i_session), I_ERROR_PARAM);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REVOCATION_ENDPOINT, "http://localhost:8080/revoke"), I_OK);
  ck_assert_int_eq(i_revoke_token(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REVOCATION_ENDPOINT, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TOKEN_TARGET, TOKEN), I_OK);
  ck_assert_int_eq(i_revoke_token(&i_session), I_ERROR_PARAM);
  
  i_clean_session(&i_session);
  
}
END_TEST

START_TEST(test_iddawc_revocation_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/revoke", 0, &callback_revoke, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_REVOCATION_ENDPOINT, "http://localhost:8080/revoke",
                                                  I_OPT_ACCESS_TOKEN, TOKEN,
                                                  I_OPT_TOKEN_TARGET, TOKEN,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_revoke_token(&i_session), I_OK);
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_REVOCATION_ENDPOINT, "http://localhost:8080/revoke",
                                                  I_OPT_ACCESS_TOKEN, TOKEN,
                                                  I_OPT_TOKEN_TARGET, TOKEN "error",
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_revoke_token(&i_session), I_OK);
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_REVOCATION_ENDPOINT, "http://localhost:8080/revoke",
                                                  I_OPT_ACCESS_TOKEN, TOKEN "error",
                                                  I_OPT_TOKEN_TARGET, TOKEN,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_revoke_token(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

static Suite *iddawc_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Iddawc token revocation tests");
  tc_core = tcase_create("test_iddawc_revocation");
  tcase_add_test(tc_core, test_iddawc_revocation_invalid);
  tcase_add_test(tc_core, test_iddawc_revocation_valid);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc token revocation tests");
  s = iddawc_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  //y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
