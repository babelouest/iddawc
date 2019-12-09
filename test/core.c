/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <iddawc.h>

#define SCOPE1 "scope1"
#define SCOPE2 "scope2"
#define SCOPE_LIST "scope1 scope2"

START_TEST(test_iddawc_init_session)
{
  struct _i_session i_session;
  
  ck_assert_int_eq(i_init_session(NULL), I_ERROR_PARAM);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_set_option_response_type)
{
  struct _i_session i_session;

  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_int_option(&i_session, 0, 0), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_int_option(&i_session, I_OPT_NONE, 0), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_int_option(&i_session, I_OPT_ADDITIONAL_PARAMETER, 0), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_int_option(&i_session, I_OPT_CODE, 0), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_int_option(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_NONE), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_int_option(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE), I_OK);
  ck_assert_int_eq(i_set_int_option(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_TOKEN), I_OK);
  ck_assert_int_eq(i_set_int_option(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_ID_TOKEN), I_OK);
  ck_assert_int_eq(i_set_int_option(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_PASSWORD), I_OK);
  ck_assert_int_eq(i_set_int_option(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CLIENT_CREDENTIALS), I_OK);
  ck_assert_int_eq(i_set_int_option(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_REFRESH_TOKEN), I_OK);
  ck_assert_int_eq(i_set_int_option(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE|I_RESPONSE_TYPE_ID_TOKEN), I_OK);
  ck_assert_int_eq(i_set_int_option(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_ID_TOKEN), I_OK);
  ck_assert_int_eq(i_set_int_option(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE|I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_ID_TOKEN), I_OK);
  ck_assert_int_eq(i_set_int_option(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CLIENT_CREDENTIALS|I_RESPONSE_TYPE_ID_TOKEN), I_ERROR_PARAM);

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_set_option_scope)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);

  ck_assert_int_eq(i_set_str_option(&i_session, 0, NULL), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_option(&i_session, I_OPT_NONE, NULL), I_ERROR_PARAM);
  
  ck_assert_int_eq(i_set_str_option(&i_session, I_OPT_SCOPE_SET, NULL), I_OK);
  ck_assert_int_eq(i_set_str_option(&i_session, I_OPT_SCOPE_SET, SCOPE1), I_OK);
  ck_assert_int_eq(i_set_str_option(&i_session, I_OPT_SCOPE_SET, SCOPE2), I_OK);
  ck_assert_int_eq(i_set_str_option(&i_session, I_OPT_SCOPE_SET, SCOPE_LIST), I_OK);

  ck_assert_int_eq(i_set_str_option(&i_session, I_OPT_SCOPE_APPEND, NULL), I_OK);
  ck_assert_int_eq(i_set_str_option(&i_session, I_OPT_SCOPE_APPEND, SCOPE1), I_OK);
  ck_assert_int_eq(i_set_str_option(&i_session, I_OPT_SCOPE_APPEND, SCOPE2), I_OK);
  ck_assert_int_eq(i_set_str_option(&i_session, I_OPT_SCOPE_APPEND, SCOPE_LIST), I_OK);

  i_clean_session(&i_session);
}
END_TEST

static Suite *ulfius_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Iddawc core function tests");
	tc_core = tcase_create("test_iddawc_core");
	tcase_add_test(tc_core, test_iddawc_init_session);
	tcase_add_test(tc_core, test_iddawc_set_option_response_type);
	tcase_add_test(tc_core, test_iddawc_set_option_scope);
	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc core tests");
  s = ulfius_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  y_close_logs();
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
