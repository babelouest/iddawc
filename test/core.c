/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <iddawc.h>

#define SCOPE1 "scope1"
#define SCOPE2 "scope2"
#define SCOPE_LIST "scope1 scope2"
#define STATE "stateXyz1234"
#define NONCE "nonceXyz1234"
#define REDIRECT_URI "https://iddawc.tld"
#define REDIRECT_TO "https://iddawc.tld#access_token=plop"
#define CLIENT_ID "clientXyz1234"
#define CLIENT_SECRET "secretXyx1234"
#define ADDITIONAL_KEY "key"
#define ADDITIONAL_VALUE "value"
#define AUTH_ENDPOINT "https://isp.tld/auth"
#define TOKEN_ENDPOINT "https://isp.tld/token"
#define OPENID_CONFIG_ENDPOINT "https://isp.tld/.well-known/openid-configuration"
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

START_TEST(test_iddawc_init_session)
{
  struct _i_session i_session;
  
  ck_assert_int_eq(i_init_session(NULL), I_ERROR_PARAM);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_set_response_type)
{
  struct _i_session i_session;

  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_response_type(&i_session, I_RESPONSE_TYPE_NONE), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_response_type(&i_session, I_RESPONSE_TYPE_CODE), I_OK);
  ck_assert_int_eq(i_set_response_type(&i_session, I_RESPONSE_TYPE_TOKEN), I_OK);
  ck_assert_int_eq(i_set_response_type(&i_session, I_RESPONSE_TYPE_ID_TOKEN), I_OK);
  ck_assert_int_eq(i_set_response_type(&i_session, I_RESPONSE_TYPE_PASSWORD), I_OK);
  ck_assert_int_eq(i_set_response_type(&i_session, I_RESPONSE_TYPE_CLIENT_CREDENTIALS), I_OK);
  ck_assert_int_eq(i_set_response_type(&i_session, I_RESPONSE_TYPE_REFRESH_TOKEN), I_OK);
  ck_assert_int_eq(i_set_response_type(&i_session, I_RESPONSE_TYPE_CODE|I_RESPONSE_TYPE_ID_TOKEN), I_OK);
  ck_assert_int_eq(i_set_response_type(&i_session, I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_ID_TOKEN), I_OK);
  ck_assert_int_eq(i_set_response_type(&i_session, I_RESPONSE_TYPE_CODE|I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_ID_TOKEN), I_OK);
  ck_assert_int_eq(i_set_response_type(&i_session, I_RESPONSE_TYPE_CLIENT_CREDENTIALS|I_RESPONSE_TYPE_ID_TOKEN), I_ERROR_PARAM);

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_set_result)
{
  struct _i_session i_session;

  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_result(&i_session, I_ERROR_MEMORY), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_result(&i_session, I_OK), I_OK);
  ck_assert_int_eq(i_set_result(&i_session, I_ERROR), I_OK);
  ck_assert_int_eq(i_set_result(&i_session, I_ERROR_PARAM), I_OK);
  ck_assert_int_eq(i_set_result(&i_session, I_ERROR_UNAUTHORIZED), I_OK);
  ck_assert_int_eq(i_set_result(&i_session, I_ERROR_SERVER), I_OK);

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_set_parameter)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, 0, NULL), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_NONE, NULL), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_RESPONSE_TYPE, NULL), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ADDITIONAL_PARAMETER, NULL), I_ERROR_PARAM);
  
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_SCOPE, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_SCOPE, SCOPE1), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_SCOPE, SCOPE2), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_SCOPE, SCOPE_LIST), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_SCOPE_APPEND, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_SCOPE_APPEND, SCOPE1), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_SCOPE_APPEND, SCOPE2), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_SCOPE_APPEND, SCOPE_LIST), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_STATE, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_STATE, STATE), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_NONCE, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_NONCE, NONCE), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_REDIRECT_URI, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_REDIRECT_URI, REDIRECT_URI), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_REDIRECT_TO, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_REDIRECT_TO, REDIRECT_TO), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_CLIENT_ID, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_CLIENT_ID, CLIENT_ID), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_CLIENT_SECRET, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_CLIENT_SECRET, CLIENT_SECRET), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_AUTH_ENDPOINT, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_TOKEN_ENDPOINT, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_OPENID_CONFIG_ENDPOINT, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_OPENID_CONFIG_ENDPOINT, OPENID_CONFIG_ENDPOINT), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ACCESS_TOKEN_VALIDATION_ENDPOINT, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ACCESS_TOKEN_VALIDATION_ENDPOINT, ACCESS_TOKEN_VALIDATION_ENDPOINT), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ERROR, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ERROR, ERROR), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ERROR_DESCRIPTION, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ERROR_DESCRIPTION, ERROR_DESCRIPTION), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ERROR_URI, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ERROR_URI, ERROR_URI), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_CODE, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_CODE, CODE), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_REFRESH_TOKEN, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_REFRESH_TOKEN, REFRESH_TOKEN), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ACCESS_TOKEN, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ACCESS_TOKEN, ACCESS_TOKEN), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_TOKEN_TYPE, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_TOKEN_TYPE, TOKEN_TYPE), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ID_TOKEN, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ID_TOKEN, ID_TOKEN), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_GLEWLWYD_API_URL, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_GLEWLWYD_API_URL, GLEWLWYD_API_URL), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_GLEWLWYD_COOKIE_SESSION, NULL), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_GLEWLWYD_COOKIE_SESSION, GLEWLWYD_COOKIE_SESSION), I_OK);

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_set_flag_parameter)
{
  struct _i_session i_session;

  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_flag_parameter(&i_session, I_OPT_AUTH_METHOD, 666), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_flag_parameter(&i_session, I_OPT_AUTH_METHOD, I_AUTH_METHOD_GET), I_OK);
  ck_assert_int_eq(i_set_flag_parameter(&i_session, I_OPT_AUTH_METHOD, I_AUTH_METHOD_POST), I_OK);
  ck_assert_int_eq(i_set_flag_parameter(&i_session, I_OPT_EXPIRES_IN, EXPIRES_IN), I_OK);

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_get_parameter)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_STATE, STATE), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_STATE), STATE);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_NONCE, NONCE), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_NONCE), NONCE);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_SCOPE, SCOPE1), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_SCOPE), SCOPE1);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_SCOPE_APPEND, SCOPE2), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_SCOPE), SCOPE_LIST);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_REDIRECT_URI, REDIRECT_URI), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_REDIRECT_URI), REDIRECT_URI);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_REDIRECT_TO, REDIRECT_TO), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_REDIRECT_TO), REDIRECT_TO);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_CLIENT_ID, CLIENT_ID), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_CLIENT_ID), CLIENT_ID);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_AUTH_ENDPOINT), AUTH_ENDPOINT);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_CLIENT_SECRET, CLIENT_SECRET), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_CLIENT_SECRET), CLIENT_SECRET);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_TOKEN_ENDPOINT), TOKEN_ENDPOINT);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_OPENID_CONFIG_ENDPOINT, OPENID_CONFIG_ENDPOINT), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_OPENID_CONFIG_ENDPOINT), OPENID_CONFIG_ENDPOINT);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ACCESS_TOKEN_VALIDATION_ENDPOINT, ACCESS_TOKEN_VALIDATION_ENDPOINT), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_ACCESS_TOKEN_VALIDATION_ENDPOINT), ACCESS_TOKEN_VALIDATION_ENDPOINT);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ERROR, ERROR), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_ERROR), ERROR);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ERROR_DESCRIPTION, ERROR_DESCRIPTION), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), ERROR_DESCRIPTION);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ERROR_URI, ERROR_URI), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_ERROR_URI), ERROR_URI);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_CODE, CODE), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_CODE), CODE);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_REFRESH_TOKEN, REFRESH_TOKEN), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_REFRESH_TOKEN), REFRESH_TOKEN);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ACCESS_TOKEN, ACCESS_TOKEN), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_ACCESS_TOKEN), ACCESS_TOKEN);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_TOKEN_TYPE, TOKEN_TYPE), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_TOKEN_TYPE), TOKEN_TYPE);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ID_TOKEN, ID_TOKEN), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_ID_TOKEN), ID_TOKEN);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_GLEWLWYD_API_URL, GLEWLWYD_API_URL), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_GLEWLWYD_API_URL), GLEWLWYD_API_URL);

  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_GLEWLWYD_COOKIE_SESSION, GLEWLWYD_COOKIE_SESSION), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_GLEWLWYD_COOKIE_SESSION), GLEWLWYD_COOKIE_SESSION);

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_get_flag_parameter)
{
  struct _i_session i_session;

  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_flag_parameter(&i_session, I_OPT_AUTH_METHOD, I_AUTH_METHOD_GET), I_OK);
  ck_assert_int_eq(i_get_flag_parameter(&i_session, I_OPT_AUTH_METHOD), I_AUTH_METHOD_GET);
  ck_assert_int_eq(i_set_flag_parameter(&i_session, I_OPT_AUTH_METHOD, I_AUTH_METHOD_POST), I_OK);
  ck_assert_int_eq(i_get_flag_parameter(&i_session, I_OPT_AUTH_METHOD), I_AUTH_METHOD_POST);
  ck_assert_int_eq(i_set_flag_parameter(&i_session, I_OPT_EXPIRES_IN, EXPIRES_IN), I_OK);
  ck_assert_int_eq(i_get_flag_parameter(&i_session, I_OPT_EXPIRES_IN), EXPIRES_IN);

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_get_response_type)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_response_type(&i_session, I_RESPONSE_TYPE_CODE), I_OK);
  ck_assert_int_eq(i_get_response_type(&i_session), I_RESPONSE_TYPE_CODE);
  ck_assert_int_eq(i_set_response_type(&i_session, I_RESPONSE_TYPE_TOKEN), I_OK);
  ck_assert_int_eq(i_get_response_type(&i_session), I_RESPONSE_TYPE_TOKEN);
  ck_assert_int_eq(i_set_response_type(&i_session, I_RESPONSE_TYPE_ID_TOKEN), I_OK);
  ck_assert_int_eq(i_get_response_type(&i_session), I_RESPONSE_TYPE_ID_TOKEN);
  ck_assert_int_eq(i_set_response_type(&i_session, I_RESPONSE_TYPE_PASSWORD), I_OK);
  ck_assert_int_eq(i_get_response_type(&i_session), I_RESPONSE_TYPE_PASSWORD);
  ck_assert_int_eq(i_set_response_type(&i_session, I_RESPONSE_TYPE_CLIENT_CREDENTIALS), I_OK);
  ck_assert_int_eq(i_get_response_type(&i_session), I_RESPONSE_TYPE_CLIENT_CREDENTIALS);
  ck_assert_int_eq(i_set_response_type(&i_session, I_RESPONSE_TYPE_REFRESH_TOKEN), I_OK);
  ck_assert_int_eq(i_get_response_type(&i_session), I_RESPONSE_TYPE_REFRESH_TOKEN);
  ck_assert_int_eq(i_set_response_type(&i_session, I_RESPONSE_TYPE_CODE|I_RESPONSE_TYPE_ID_TOKEN), I_OK);
  ck_assert_int_eq(i_get_response_type(&i_session), I_RESPONSE_TYPE_CODE|I_RESPONSE_TYPE_ID_TOKEN);
  ck_assert_int_eq(i_set_response_type(&i_session, I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_ID_TOKEN), I_OK);
  ck_assert_int_eq(i_get_response_type(&i_session), I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_ID_TOKEN);
  ck_assert_int_eq(i_set_response_type(&i_session, I_RESPONSE_TYPE_CODE|I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_ID_TOKEN), I_OK);
  ck_assert_int_eq(i_get_response_type(&i_session), I_RESPONSE_TYPE_CODE|I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_ID_TOKEN);

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_get_result)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_result(&i_session, I_OK), I_OK);
  ck_assert_int_eq(i_get_result(&i_session), I_OK);
  ck_assert_int_eq(i_set_result(&i_session, I_ERROR), I_OK);
  ck_assert_int_eq(i_get_result(&i_session), I_ERROR);
  ck_assert_int_eq(i_set_result(&i_session, I_ERROR_PARAM), I_OK);
  ck_assert_int_eq(i_get_result(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_result(&i_session, I_ERROR_UNAUTHORIZED), I_OK);
  ck_assert_int_eq(i_get_result(&i_session), I_ERROR_UNAUTHORIZED);
  ck_assert_int_eq(i_set_result(&i_session, I_ERROR_SERVER), I_OK);
  ck_assert_int_eq(i_get_result(&i_session), I_ERROR_SERVER);

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_set_additional_parameter)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);

  ck_assert_int_eq(i_set_additional_parameter(&i_session, NULL, NULL), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_additional_parameter(&i_session, ADDITIONAL_KEY, NULL), I_OK);
  ck_assert_int_eq(i_set_additional_parameter(&i_session, NULL, ADDITIONAL_VALUE), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_additional_parameter(&i_session, ADDITIONAL_KEY, ADDITIONAL_VALUE), I_OK);

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_get_additional_parameter)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_additional_parameter(&i_session, ADDITIONAL_KEY, ADDITIONAL_VALUE), I_OK);
  ck_assert_str_eq(i_get_additional_parameter(&i_session, ADDITIONAL_KEY), ADDITIONAL_VALUE);
  ck_assert_int_eq(i_set_additional_parameter(&i_session, ADDITIONAL_KEY, NULL), I_OK);
  ck_assert_ptr_eq(i_get_additional_parameter(&i_session, ADDITIONAL_KEY), NULL);
  ck_assert_int_eq(i_set_additional_parameter(&i_session, ADDITIONAL_KEY, ADDITIONAL_VALUE ADDITIONAL_VALUE), I_OK);
  ck_assert_str_eq(i_get_additional_parameter(&i_session, ADDITIONAL_KEY), ADDITIONAL_VALUE ADDITIONAL_VALUE);
  ck_assert_int_eq(i_set_additional_parameter(&i_session, ADDITIONAL_KEY, NULL), I_OK);
  ck_assert_ptr_eq(i_get_additional_parameter(&i_session, ADDITIONAL_KEY), NULL);

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_parameter_list)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_parameter_list(&i_session, 666, "error", I_OPT_NONE), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_SCOPE_APPEND, "error", I_OPT_NONE), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_parameter(&i_session, I_OPT_STATE), NULL);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_NONE), I_OK);
  ck_assert_ptr_eq(i_get_parameter(&i_session, I_OPT_STATE), NULL);
  
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_STATE, STATE,
                                                  I_OPT_NONCE, NONCE,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_REDIRECT_TO, REDIRECT_TO,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_ADDITIONAL_PARAMETER, ADDITIONAL_KEY, ADDITIONAL_VALUE,
                                                  I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_OPENID_CONFIG_ENDPOINT, OPENID_CONFIG_ENDPOINT,
                                                  I_OPT_ACCESS_TOKEN_VALIDATION_ENDPOINT, ACCESS_TOKEN_VALIDATION_ENDPOINT,
                                                  I_OPT_RESULT, I_OK,
                                                  I_OPT_ERROR, ERROR,
                                                  I_OPT_ERROR_DESCRIPTION, ERROR_DESCRIPTION,
                                                  I_OPT_ERROR_URI, ERROR_URI,
                                                  I_OPT_CODE, CODE,
                                                  I_OPT_REFRESH_TOKEN, REFRESH_TOKEN,
                                                  I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                  I_OPT_TOKEN_TYPE, TOKEN_TYPE,
                                                  I_OPT_EXPIRES_IN, EXPIRES_IN,
                                                  I_OPT_ID_TOKEN, ID_TOKEN,
                                                  I_OPT_GLEWLWYD_API_URL, GLEWLWYD_API_URL,
                                                  I_OPT_GLEWLWYD_COOKIE_SESSION, GLEWLWYD_COOKIE_SESSION,
                                                  I_OPT_NONE), I_OK);
  
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_STATE), STATE);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_NONCE), NONCE);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_SCOPE), SCOPE_LIST);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_REDIRECT_URI), REDIRECT_URI);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_REDIRECT_TO), REDIRECT_TO);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_CLIENT_ID), CLIENT_ID);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_AUTH_ENDPOINT), AUTH_ENDPOINT);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_CLIENT_SECRET), CLIENT_SECRET);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_TOKEN_ENDPOINT), TOKEN_ENDPOINT);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_OPENID_CONFIG_ENDPOINT), OPENID_CONFIG_ENDPOINT);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_ACCESS_TOKEN_VALIDATION_ENDPOINT), ACCESS_TOKEN_VALIDATION_ENDPOINT);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_ERROR), ERROR);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), ERROR_DESCRIPTION);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_ERROR_URI), ERROR_URI);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_CODE), CODE);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_REFRESH_TOKEN), REFRESH_TOKEN);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_ACCESS_TOKEN), ACCESS_TOKEN);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_TOKEN_TYPE), TOKEN_TYPE);
  ck_assert_int_eq(i_get_flag_parameter(&i_session, I_OPT_EXPIRES_IN), EXPIRES_IN);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_ID_TOKEN), ID_TOKEN);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_GLEWLWYD_API_URL), GLEWLWYD_API_URL);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_GLEWLWYD_COOKIE_SESSION), GLEWLWYD_COOKIE_SESSION);

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
  tcase_add_test(tc_core, test_iddawc_set_response_type);
  tcase_add_test(tc_core, test_iddawc_set_result);
  tcase_add_test(tc_core, test_iddawc_set_parameter);
  tcase_add_test(tc_core, test_iddawc_set_flag_parameter);
  tcase_add_test(tc_core, test_iddawc_set_additional_parameter);
  tcase_add_test(tc_core, test_iddawc_get_parameter);
  tcase_add_test(tc_core, test_iddawc_get_flag_parameter);
  tcase_add_test(tc_core, test_iddawc_get_response_type);
  tcase_add_test(tc_core, test_iddawc_get_result);
  tcase_add_test(tc_core, test_iddawc_get_additional_parameter);
  tcase_add_test(tc_core, test_iddawc_parameter_list);
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
