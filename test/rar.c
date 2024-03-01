/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <jansson.h>
#include <check.h>
#include <yder.h>
#include <iddawc.h>

#define UNUSED(x) (void)(x)

#define PAR_ERROR "invalid_request"
#define PAR_ERROR_DESCRIPTION "invalid_request description"
#define PAR_ERROR_URI "https://as.tld/#error"
#define CLIENT_ID "client"
#define CLIENT_SECRET "client_secret"
#define CLIENT_REDIRECT "https://client.tld"
#define LOGIN_ENDPOINT "http://localhost:8080/login"
#define AUTH_ENDPOINT "http://localhost:8080/auth"
#define TOKEN_ENDPOINT "http://localhost:8080/token"
#define PUSHED_AUTH_REQ_ENDPOINT "http://localhost:8080/par"
#define CIBA_ENDPOINT "http://localhost:8080/ciba"
#define DEVICE_AUTHORIZATION_ENDPOINT "http://localhost:8080/device"
#define SCOPE "scope1 scope2"
#define RESOURCE_INDICATOR "https://resource.iddawc.tld/"
#define AUTH_DETAIL_TYPE1 "account_information"
#define AUTH_DETAIL_TYPE2 "payment_initiation"
#define AUTH_DETAIL_MINIMAL "{}"
#define AUTH_DETAIL_1 "{\"actions\":[\"list_accounts\",\"read_balances\",\"read_transactions\"],\"locations\":[\"https://example.com/accounts\"]}"
#define AUTH_DETAIL_2 "{\"actions\":[\"initiate\",\"status\",\"cancel\"],\"locations\":[\"https://example.com/payments\"],\"instructedAmount\":{\"currency\":\"EUR\",\"amount\":\"123.50\"},\"creditorName\":\"MerchantA\",\"creditorAccount\":{\"iban\":\"DE02100100109307118603\"},\"remittanceInformationUnstructured\":\"RefNumberMerchant\"}"
#define ACCESS_TOKEN "2YotnFZFEjr1zCsicMWpAA"
#define REFRESH_TOKEN "tGzv3JOkF0XG5Qx2TlKWIA"
#define EXPIRES_IN 3600
#define TOKEN_TYPE "bearer"
#define CIBA_AUTH_REQ_ID "CIBAAuthReqId123456789012345678901234567890"
#define CIBA_AUTH_REQ_EXPIRES_IN 145
#define CIBA_AUTH_REQ_INTERVAL 4
#define CIBA_LOGIN_HINT "{\"username\":\"ciba\"}"
#define CIBA_CLIENT_NOTIFICATION_TOKEN "CIBAClientNotificationToken123456789012345678901234567890"
#define REQUEST_URI "true"

#define ISSUER "https://glewlwyd.tld/"
#define USERINFO_ENDPOINT "http://localhost:8080/userinfo"
#define JWKS_URI "http://localhost:8080/jwks"
#define AUTH_METHOD_1 "client_secret_basic"
#define AUTH_METHOD_2 "client_secret_jwt"
#define ALG_VALUE_1 "RS512"
#define ALG_VALUE_2 "RS256"
#define SCOPE_1 "openid"
#define SCOPE_2 "g_profile"
#define RESP_TYPE_1 "code"
#define RESP_TYPE_2 "id_token"
#define RESP_TYPE_3 "token"
#define RESP_TYPE_4 "none"
#define RESP_TYPE_5 "refresh_token"
#define MODE_1 "query"
#define MODE_2 "fragment"
#define GRANT_TYPE_1 "authorization_code"
#define GRANT_TYPE_2 "implicit"
#define DISPLAY_1 "page"
#define DISPLAY_2 "popup"
#define DISPLAY_3 "touch"
#define DISPLAY_4 "wap"
#define CLAIM_TYPE "normal"
#define CLAIMS_PARAM_SUPPORTED "true"
#define CLAIMS_SUPPORTED "name"
#define DOC "https://glewlwyd.tld/docs"
#define LOCALE_1 "en"
#define LOCALE_2 "fr"
#define LOCALE_3 "nl"
#define REQUEST_PARAM "true"
#define REQUIRE_REQUEST_REGIS "false"
#define SUBJECT_TYPE "public"

const char openid_configuration_valid[] = "{\
  \"issuer\":\"" ISSUER "\",\
  \"authorization_endpoint\":\"" AUTH_ENDPOINT "\",\
  \"token_endpoint\":\"" TOKEN_ENDPOINT "\",\
  \"userinfo_endpoint\":\"" USERINFO_ENDPOINT "\",\
  \"jwks_uri\":\"" JWKS_URI "\",\
  \"token_endpoint_auth_methods_supported\":[\"" AUTH_METHOD_1 "\",\"" AUTH_METHOD_2 "\"],\
  \"id_token_signing_alg_values_supported\":[\"" ALG_VALUE_1 "\",\"" ALG_VALUE_2 "\"],\
  \"scopes_supported\":[\"" SCOPE_1 "\",\"" SCOPE_2 "\"],\
  \"response_types_supported\":[\"" RESP_TYPE_1 "\",\"" RESP_TYPE_2 "\",\"" RESP_TYPE_3 "\",\"" RESP_TYPE_1 " " RESP_TYPE_2 "\",\"" RESP_TYPE_3 " " RESP_TYPE_2 "\",\"" RESP_TYPE_1 " " RESP_TYPE_2" " RESP_TYPE_3 "\",\"" RESP_TYPE_4 "\",\"" RESP_TYPE_5 "\"],\
  \"response_modes_supported\":[\"" MODE_1 "\",\"" MODE_2 "\"],\
  \"grant_types_supported\":[\"" GRANT_TYPE_1 "\",\"" GRANT_TYPE_2 "\"],\
  \"display_values_supported\":[\"" DISPLAY_1 "\",\"" DISPLAY_2 "\",\"" DISPLAY_3 "\",\"" DISPLAY_4 "\"],\
  \"claim_types_supported\":[\"" CLAIM_TYPE "\"],\
  \"claims_parameter_supported\":" CLAIMS_PARAM_SUPPORTED ",\
  \"claims_supported\":[\"" CLAIMS_SUPPORTED "\"],\
  \"service_documentation\":\"" DOC "\",\
  \"ui_locales_supported\":[\"" LOCALE_1 "\",\"" LOCALE_2 "\",\"" LOCALE_3 "\"],\
  \"request_parameter_supported\":" REQUEST_PARAM ",\
  \"request_uri_parameter_supported\":" REQUEST_URI ",\
  \"require_request_uri_registration\":" REQUIRE_REQUEST_REGIS ",\
  \"subject_types_supported\":[\"" SUBJECT_TYPE "\"],\
  \"authorization_details_types_supported\":[\"" AUTH_DETAIL_TYPE1 "\",\"" AUTH_DETAIL_TYPE2 "\"]\
}";

int callback_auth_post (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_authorization_details = json_loads(u_map_get(request->map_post_body, "authorization_details"), JSON_DECODE_ANY, NULL), * j_element = NULL, * j_auth_detail1 = json_loads(AUTH_DETAIL_1, JSON_DECODE_ANY, NULL), * j_auth_detail2 = json_loads(AUTH_DETAIL_2, JSON_DECODE_ANY, NULL);
  size_t index = 0;
  int has_type1, has_type2;
  UNUSED(user_data);

  ck_assert_ptr_ne(NULL, j_authorization_details);
  has_type1 = 0;
  has_type2 = 0;
  json_array_foreach(j_authorization_details, index, j_element) {
    if (0 == o_strcmp(AUTH_DETAIL_TYPE1, json_string_value(json_object_get(j_element, "type")))) {
      has_type1 = 1;
      json_object_del(j_element, "type");
      ck_assert_int_eq(1, json_equal(j_element, j_auth_detail1));
    } else if (0 == o_strcmp(AUTH_DETAIL_TYPE2, json_string_value(json_object_get(j_element, "type")))) {
      has_type2 = 1;
      json_object_del(j_element, "type");
      ck_assert_int_eq(1, json_equal(j_element, j_auth_detail2));
    }
  }
  ck_assert_int_eq(1, has_type1);
  ck_assert_int_eq(1, has_type2);
  json_decref(j_authorization_details);
  json_decref(j_auth_detail1);
  json_decref(j_auth_detail2);
  
  ulfius_set_response_properties(response, U_OPT_STATUS, 302,
                                           U_OPT_HEADER_PARAMETER, "Location", LOGIN_ENDPOINT,
                                           U_OPT_NONE);
  return U_CALLBACK_CONTINUE;
}

int callback_auth_post_jwt (const struct _u_request * request, struct _u_response * response, void * user_data) {
  jwt_t * jwt = r_jwt_quick_parse(u_map_get(request->map_post_body, "request"), R_PARSE_NONE, 0);
  json_t * j_authorization_details,
         * j_element = NULL,
         * j_auth_detail1 = json_loads(AUTH_DETAIL_1, JSON_DECODE_ANY, NULL),
         * j_auth_detail2 = json_loads(AUTH_DETAIL_2, JSON_DECODE_ANY, NULL);
  size_t index = 0;
  int has_type1, has_type2;
  UNUSED(user_data);

  ck_assert_ptr_ne(NULL, jwt);
  ck_assert_ptr_ne(NULL, j_authorization_details = r_jwt_get_claim_json_t_value(jwt, "authorization_details"));
  has_type1 = 0;
  has_type2 = 0;
  json_array_foreach(j_authorization_details, index, j_element) {
    if (0 == o_strcmp(AUTH_DETAIL_TYPE1, json_string_value(json_object_get(j_element, "type")))) {
      has_type1 = 1;
      json_object_del(j_element, "type");
      ck_assert_int_eq(1, json_equal(j_element, j_auth_detail1));
    } else if (0 == o_strcmp(AUTH_DETAIL_TYPE2, json_string_value(json_object_get(j_element, "type")))) {
      has_type2 = 1;
      json_object_del(j_element, "type");
      ck_assert_int_eq(1, json_equal(j_element, j_auth_detail2));
    }
  }
  ck_assert_int_eq(1, has_type1);
  ck_assert_int_eq(1, has_type2);
  json_decref(j_authorization_details);
  json_decref(j_auth_detail1);
  json_decref(j_auth_detail2);
  r_jwt_free(jwt);
  
  ulfius_set_response_properties(response, U_OPT_STATUS, 302,
                                           U_OPT_HEADER_PARAMETER, "Location", LOGIN_ENDPOINT,
                                           U_OPT_NONE);
  return U_CALLBACK_CONTINUE;
}

int callback_device_token_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_authorization_details = json_loads(u_map_get(request->map_post_body, "authorization_details"), JSON_DECODE_ANY, NULL), * j_element = NULL, * j_auth_detail1 = json_loads(AUTH_DETAIL_1, JSON_DECODE_ANY, NULL), * j_auth_detail2 = json_loads(AUTH_DETAIL_2, JSON_DECODE_ANY, NULL);
  size_t index = 0;
  int has_type1, has_type2;
  UNUSED(user_data);

  ck_assert_ptr_ne(NULL, j_authorization_details);
  has_type1 = 0;
  has_type2 = 0;
  json_array_foreach(j_authorization_details, index, j_element) {
    if (0 == o_strcmp(AUTH_DETAIL_TYPE1, json_string_value(json_object_get(j_element, "type")))) {
      has_type1 = 1;
      json_object_del(j_element, "type");
      ck_assert_int_eq(1, json_equal(j_element, j_auth_detail1));
    } else if (0 == o_strcmp(AUTH_DETAIL_TYPE2, json_string_value(json_object_get(j_element, "type")))) {
      has_type2 = 1;
      json_object_del(j_element, "type");
      ck_assert_int_eq(1, json_equal(j_element, j_auth_detail2));
    }
  }
  ck_assert_int_eq(1, has_type1);
  ck_assert_int_eq(1, has_type2);
  json_decref(j_authorization_details);
  json_decref(j_auth_detail1);
  json_decref(j_auth_detail2);

  json_t * result = json_pack("{sssssiss}", 
                             "access_token", ACCESS_TOKEN,
                             "token_type", TOKEN_TYPE,
                             "expires_in", EXPIRES_IN,
                             "refresh_token", REFRESH_TOKEN);
  ulfius_set_json_body_response(response, 200, result);
  json_decref(result);
  return U_CALLBACK_CONTINUE;
}

int callback_ciba_login_hint_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_authorization_details = json_loads(u_map_get(request->map_post_body, "authorization_details"), JSON_DECODE_ANY, NULL), * j_element = NULL, * j_auth_detail1 = json_loads(AUTH_DETAIL_1, JSON_DECODE_ANY, NULL), * j_auth_detail2 = json_loads(AUTH_DETAIL_2, JSON_DECODE_ANY, NULL);
  size_t index = 0;
  int has_type1, has_type2;
  UNUSED(user_data);

  ck_assert_ptr_ne(NULL, j_authorization_details);
  has_type1 = 0;
  has_type2 = 0;
  json_array_foreach(j_authorization_details, index, j_element) {
    if (0 == o_strcmp(AUTH_DETAIL_TYPE1, json_string_value(json_object_get(j_element, "type")))) {
      has_type1 = 1;
      json_object_del(j_element, "type");
      ck_assert_int_eq(1, json_equal(j_element, j_auth_detail1));
    } else if (0 == o_strcmp(AUTH_DETAIL_TYPE2, json_string_value(json_object_get(j_element, "type")))) {
      has_type2 = 1;
      json_object_del(j_element, "type");
      ck_assert_int_eq(1, json_equal(j_element, j_auth_detail2));
    }
  }
  ck_assert_int_eq(1, has_type1);
  ck_assert_int_eq(1, has_type2);
  json_decref(j_authorization_details);
  json_decref(j_auth_detail1);
  json_decref(j_auth_detail2);

  json_t * j_response = json_pack("{sssisi}", "auth_req_id", CIBA_AUTH_REQ_ID, "expires_in", CIBA_AUTH_REQ_EXPIRES_IN, "interval", CIBA_AUTH_REQ_INTERVAL);
  ck_assert_str_eq(CIBA_LOGIN_HINT, u_map_get(request->map_post_body, "login_hint"));
  ulfius_set_json_body_response(response, 200, j_response);
  json_decref(j_response);
  return U_CALLBACK_CONTINUE;
}

int callback_par_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_authorization_details = json_loads(u_map_get(request->map_post_body, "authorization_details"), JSON_DECODE_ANY, NULL), * j_element = NULL, * j_auth_detail1 = json_loads(AUTH_DETAIL_1, JSON_DECODE_ANY, NULL), * j_auth_detail2 = json_loads(AUTH_DETAIL_2, JSON_DECODE_ANY, NULL);
  size_t index = 0;
  int has_type1, has_type2;
  UNUSED(user_data);

  ck_assert_ptr_ne(NULL, j_authorization_details);
  has_type1 = 0;
  has_type2 = 0;
  json_array_foreach(j_authorization_details, index, j_element) {
    if (0 == o_strcmp(AUTH_DETAIL_TYPE1, json_string_value(json_object_get(j_element, "type")))) {
      has_type1 = 1;
      json_object_del(j_element, "type");
      ck_assert_int_eq(1, json_equal(j_element, j_auth_detail1));
    } else if (0 == o_strcmp(AUTH_DETAIL_TYPE2, json_string_value(json_object_get(j_element, "type")))) {
      has_type2 = 1;
      json_object_del(j_element, "type");
      ck_assert_int_eq(1, json_equal(j_element, j_auth_detail2));
    }
  }
  ck_assert_int_eq(1, has_type1);
  ck_assert_int_eq(1, has_type2);
  json_decref(j_authorization_details);
  json_decref(j_auth_detail1);
  json_decref(j_auth_detail2);

  json_t * j_response = json_pack("{sssi}", "request_uri", REQUEST_URI, "expires_in", EXPIRES_IN);
  ulfius_set_json_body_response(response, 201, j_response);
  json_decref(j_response);
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_iddawc_rar_invalid_parameters)
{
  struct _i_session i_session;
  json_t * j_auth_detail = json_loads(AUTH_DETAIL_1, JSON_DECODE_ANY, NULL), * j_error = json_string("error");
  
  ck_assert_ptr_ne(NULL, j_auth_detail);
  ck_assert_ptr_ne(NULL, j_error);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_REDIRECT_URI, CLIENT_REDIRECT,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_RESOURCE_INDICATOR, RESOURCE_INDICATOR,
                                                    I_OPT_NONE), I_OK);

  // Test i_set_rich_authorization_request_str
  ck_assert_int_eq(i_set_rich_authorization_request_str(NULL, NULL, NULL), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, NULL, NULL), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, "error", "error"), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_rich_authorization_request_str(NULL, AUTH_DETAIL_TYPE1, AUTH_DETAIL_1), I_ERROR_PARAM);

  // Test i_set_rich_authorization_request_json_t
  ck_assert_int_eq(i_set_rich_authorization_request_json_t(NULL, NULL, NULL), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_rich_authorization_request_json_t(&i_session, NULL, NULL), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_rich_authorization_request_json_t(&i_session, "error", j_error), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_rich_authorization_request_json_t(NULL, AUTH_DETAIL_TYPE1, j_auth_detail), I_ERROR_PARAM);

  ck_assert_int_eq(i_set_rich_authorization_request_json_t(&i_session, AUTH_DETAIL_TYPE1, j_auth_detail), I_OK);

  // Test i_get_rich_authorization_request_json_t
  ck_assert_ptr_eq(NULL, i_get_rich_authorization_request_json_t(NULL, NULL));
  ck_assert_ptr_eq(NULL, i_get_rich_authorization_request_json_t(&i_session, NULL));
  ck_assert_ptr_eq(NULL, i_get_rich_authorization_request_json_t(NULL, "error"));
  ck_assert_ptr_eq(NULL, i_get_rich_authorization_request_json_t(&i_session, "error"));

  // Test i_get_rich_authorization_request_str
  ck_assert_ptr_eq(NULL, i_get_rich_authorization_request_str(NULL, NULL));
  ck_assert_ptr_eq(NULL, i_get_rich_authorization_request_str(&i_session, NULL));
  ck_assert_ptr_eq(NULL, i_get_rich_authorization_request_str(NULL, "error"));
  ck_assert_ptr_eq(NULL, i_get_rich_authorization_request_str(&i_session, "error"));

  // Test i_remove_rich_authorization_request
  ck_assert_int_eq(i_remove_rich_authorization_request(NULL, NULL), I_ERROR_PARAM);
  ck_assert_int_eq(i_remove_rich_authorization_request(&i_session, NULL), I_ERROR_PARAM);
  ck_assert_int_eq(i_remove_rich_authorization_request(NULL, "error"), I_ERROR_PARAM);

  json_decref(j_auth_detail);
  json_decref(j_error);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_rar_valid_parameters)
{
  struct _i_session i_session;
  json_t * j_auth_detail = json_loads(AUTH_DETAIL_1, JSON_DECODE_ANY, NULL), * j_auth_get;
  char * str_auth_detail;

  ck_assert_ptr_ne(NULL, j_auth_detail);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_REDIRECT_URI, CLIENT_REDIRECT,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_RESOURCE_INDICATOR, RESOURCE_INDICATOR,
                                                    I_OPT_NONE), I_OK);

  ck_assert_int_eq(i_set_rich_authorization_request_json_t(&i_session, AUTH_DETAIL_TYPE1, j_auth_detail), I_OK);
  ck_assert_ptr_ne(NULL, j_auth_get = i_get_rich_authorization_request_json_t(&i_session, AUTH_DETAIL_TYPE1));
  ck_assert_ptr_ne(NULL, str_auth_detail = i_get_rich_authorization_request_str(&i_session, AUTH_DETAIL_TYPE1));
  ck_assert_int_eq(1, json_equal(j_auth_get, j_auth_detail));
  json_decref(j_auth_get);

  ck_assert_ptr_ne(NULL, j_auth_get = json_loads(str_auth_detail, JSON_DECODE_ANY, NULL));
  ck_assert_int_eq(1, json_equal(j_auth_get, j_auth_detail));

  ck_assert_int_eq(i_remove_rich_authorization_request(&i_session, AUTH_DETAIL_TYPE1), I_OK);
  ck_assert_ptr_eq(NULL, i_get_rich_authorization_request_json_t(&i_session, AUTH_DETAIL_TYPE1));

  json_decref(j_auth_get);
  json_decref(j_auth_detail);
  o_free(str_auth_detail);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_rar_build_auth_get_invalid_config)
{
  struct _i_session i_session;
  json_t * j_config;

  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_ptr_ne(NULL, j_config = json_loads(openid_configuration_valid, JSON_DECODE_ANY, NULL));
  ck_assert_int_eq(i_set_server_configuration(&i_session, j_config), I_OK);
  json_decref(j_config);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_REDIRECT_URI, CLIENT_REDIRECT,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_RESOURCE_INDICATOR, RESOURCE_INDICATOR,
                                                    I_OPT_NONE), I_OK);

  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, "error", AUTH_DETAIL_1), I_OK);
  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, AUTH_DETAIL_TYPE2, AUTH_DETAIL_2), I_OK);
  ck_assert_int_eq(i_build_auth_url_get(&i_session), I_ERROR_PARAM);

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_rar_build_auth_get)
{
  struct _i_session i_session;
  json_t * j_auth_detail, * j_element = NULL, * j_auth_detail1 = json_loads(AUTH_DETAIL_1, JSON_DECODE_ANY, NULL), * j_auth_detail2 = json_loads(AUTH_DETAIL_2, JSON_DECODE_ANY, NULL);
  const char * redirect_to, * authorization_details;
  char * authorization_details_enc, * authorization_details_dec;
  int has_type1, has_type2;
  size_t index = 0;

  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_REDIRECT_URI, CLIENT_REDIRECT,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_RESOURCE_INDICATOR, RESOURCE_INDICATOR,
                                                    I_OPT_NONE), I_OK);

  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, AUTH_DETAIL_TYPE1, AUTH_DETAIL_1), I_OK);
  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, AUTH_DETAIL_TYPE2, AUTH_DETAIL_2), I_OK);
  ck_assert_int_eq(i_build_auth_url_get(&i_session), I_OK);
  ck_assert_ptr_ne(NULL, redirect_to = i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO));
  ck_assert_ptr_ne(NULL, authorization_details = o_strstr(redirect_to, "authorization_details="));
  if (o_strchr(authorization_details, '&')) {
    authorization_details_enc = o_strndup(authorization_details+o_strlen("authorization_details="), (o_strchr(authorization_details, '&')-authorization_details));
  } else {
    authorization_details_enc = o_strdup(authorization_details+o_strlen("authorization_details="));
  }
  ck_assert_ptr_ne(NULL, authorization_details_enc);
  ck_assert_ptr_ne(NULL, authorization_details_dec = ulfius_url_decode(authorization_details_enc));
  ck_assert_ptr_ne(NULL, j_auth_detail = json_loads(authorization_details_dec, JSON_DECODE_ANY, NULL));
  ck_assert_int_eq(2, json_array_size(j_auth_detail));
  has_type1 = 0;
  has_type2 = 0;
  json_array_foreach(j_auth_detail, index, j_element) {
    if (0 == o_strcmp(AUTH_DETAIL_TYPE1, json_string_value(json_object_get(j_element, "type")))) {
      has_type1 = 1;
      json_object_del(j_element, "type");
      ck_assert_int_eq(1, json_equal(j_element, j_auth_detail1));
    } else if (0 == o_strcmp(AUTH_DETAIL_TYPE2, json_string_value(json_object_get(j_element, "type")))) {
      has_type2 = 1;
      json_object_del(j_element, "type");
      ck_assert_int_eq(1, json_equal(j_element, j_auth_detail2));
    }
  }
  ck_assert_int_eq(1, has_type1);
  ck_assert_int_eq(1, has_type2);

  json_decref(j_auth_detail);
  json_decref(j_auth_detail1);
  json_decref(j_auth_detail2);
  o_free(authorization_details_enc);
  o_free(authorization_details_dec);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_rar_run_auth_post)
{
  struct _i_session i_session;
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/auth", 0, &callback_auth_post, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);

  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_AUTH_METHOD_POST,
                                                    I_OPT_REDIRECT_URI, CLIENT_REDIRECT,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_RESOURCE_INDICATOR, RESOURCE_INDICATOR,
                                                    I_OPT_NONE), I_OK);

  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, AUTH_DETAIL_TYPE1, AUTH_DETAIL_1), I_OK);
  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, AUTH_DETAIL_TYPE2, AUTH_DETAIL_2), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);

  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_rar_run_auth_post_jwt)
{
  struct _i_session i_session;
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/auth", 0, &callback_auth_post_jwt, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);

  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_AUTH_METHOD_POST|I_AUTH_METHOD_JWT_SIGN_SECRET,
                                                    I_OPT_REDIRECT_URI, CLIENT_REDIRECT,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_RESOURCE_INDICATOR, RESOURCE_INDICATOR,
                                                    I_OPT_CLIENT_SIGN_ALG, "HS256",
                                                    I_OPT_NONE), I_OK);

  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, AUTH_DETAIL_TYPE1, AUTH_DETAIL_1), I_OK);
  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, AUTH_DETAIL_TYPE2, AUTH_DETAIL_2), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);

  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_rar_run_device_auth)
{
  struct _i_session i_session;
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/device", 0, &callback_device_token_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);

  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_AUTH_METHOD_POST,
                                                    I_OPT_REDIRECT_URI, CLIENT_REDIRECT,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, DEVICE_AUTHORIZATION_ENDPOINT,
                                                    I_OPT_RESOURCE_INDICATOR, RESOURCE_INDICATOR,
                                                    I_OPT_NONE), I_OK);

  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, AUTH_DETAIL_TYPE1, AUTH_DETAIL_1), I_OK);
  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, AUTH_DETAIL_TYPE2, AUTH_DETAIL_2), I_OK);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_OK);

  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_rar_run_ciba_auth)
{
  struct _i_session i_session;
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/ciba", 0, &callback_ciba_login_hint_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);

  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_AUTH_METHOD_POST,
                                                    I_OPT_REDIRECT_URI, CLIENT_REDIRECT,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_CIBA_ENDPOINT, CIBA_ENDPOINT,
                                                    I_OPT_RESOURCE_INDICATOR, RESOURCE_INDICATOR,
                                                    I_OPT_CIBA_LOGIN_HINT, CIBA_LOGIN_HINT,
                                                    I_OPT_CIBA_MODE, I_CIBA_MODE_POLL,
                                                    I_OPT_CIBA_LOGIN_HINT_FORMAT, I_CIBA_LOGIN_HINT_FORMAT_JSON,
                                                    I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN, CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                    I_OPT_NONE), I_OK);

  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, AUTH_DETAIL_TYPE1, AUTH_DETAIL_1), I_OK);
  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, AUTH_DETAIL_TYPE2, AUTH_DETAIL_2), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_OK);

  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_rar_run_par_auth)
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
  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, AUTH_DETAIL_TYPE1, AUTH_DETAIL_1), I_OK);
  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, AUTH_DETAIL_TYPE2, AUTH_DETAIL_2), I_OK);
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

  s = suite_create("Iddawc rich authorization requests tests");
  tc_core = tcase_create("test_iddawc_rar");
  tcase_add_test(tc_core, test_iddawc_rar_invalid_parameters);
  tcase_add_test(tc_core, test_iddawc_rar_valid_parameters);
  tcase_add_test(tc_core, test_iddawc_rar_build_auth_get_invalid_config);
  tcase_add_test(tc_core, test_iddawc_rar_build_auth_get);
  tcase_add_test(tc_core, test_iddawc_rar_run_auth_post);
  tcase_add_test(tc_core, test_iddawc_rar_run_auth_post_jwt);
  tcase_add_test(tc_core, test_iddawc_rar_run_device_auth);
  tcase_add_test(tc_core, test_iddawc_rar_run_ciba_auth);
  tcase_add_test(tc_core, test_iddawc_rar_run_par_auth);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(void)
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc rich authrozation requests tests");
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
