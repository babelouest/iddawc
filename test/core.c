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
#define CODE "codeXyz1234"
#define REFRESH_TOKEN "refreshXyz1234"
#define ACCESS_TOKEN "accessXyz1234"
#define TOKEN_TYPE "typeXyz1234"
#define EXPIRES_IN 3600
#define EXPIRES_AT 7200
#define ID_TOKEN "idTokenXyz1234"
#define ERROR "errorXyz1234"
#define ERROR_DESCRIPTION "errorDescriptionXyz1234"
#define ERROR_URI "errorUriXyz1234"
#define USERNAME "dev"
#define USER_PASSWORD "password"
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
#define REQUEST_URI "true"
#define REQUIRE_REQUEST_REGIS "false"
#define SUBJECT_TYPE "public"
#define USERINFO "{\"aud\":\"abcd1234\",\"name\":\"Dave Lopper\"}"
#define SERVER_KID "server kid"
#define SERVER_ENC_ALG "RSA-OAEP"
#define SERVER_ENC "A128GCM"
#define CLIENT_KID "client kid"
#define CLIENT_SIGN_ALG "HS256"
#define CLIENT_ENC_ALG "RSA1_5"
#define CLIENT_ENC "A128CBC-HS256"
#define TOKEN_JTI "jtiXyz1234"
#define TOKEN_EXP 42
#define TOKEN_TARGET "targetXyz1234"
#define TOKEN_TARGET_TYPE_HINT "token_type"
#define REVOCATION_ENDPOINT "https://isp.tld/revocation"
#define INTROSPECTION_ENDPOINT "https://isp.tld/introspect"
#define REGISTRATION_ENDPOINT "https://isp.tld/register"
#define AUTH_REQUEST_1 "{\"locations\":[\"https://resource.tld/\"],\"actions\":[\"swing\"],\"sneak attack\":[\"dans\",\"la\",\"face\"]}"
#define AUTH_REQUEST_TYPE_1 "type1"
#define AUTH_REQUEST_FULL_1 "{\"type\":\""AUTH_REQUEST_TYPE_1"\",\"locations\":[\"https://resource.tld/\"],\"actions\":[\"swing\"],\"sneak attack\":[\"dans\",\"la\",\"face\"]}"
#define AUTH_REQUEST_2 "{\"locations\":[\"https://resource2.tld/\"],\"actions\":[\"rock\"],\"emerger\":[\"pierres\",\"brillantes\",\"robe\"]}"
#define AUTH_REQUEST_TYPE_2 "type2"
#define AUTH_REQUEST_FULL_2 "{\"type\":\""AUTH_REQUEST_TYPE_2"\",\"locations\":[\"https://resource2.tld/\"],\"actions\":[\"rock\"],\"emerger\":[\"pierres\",\"brillantes\",\"robe\"]}"
#define DEVICE_AUTHORIZATION_ENDPOINT "https://isp.tld/device"
#define DEVICE_AUTH_CODE "deviceCode1234"
#define DEVICE_AUTH_USER_CODE "deviceUserCode1234"
#define DEVICE_AUTH_VERIFICATION_URI "https://isp.tld/deviceUserAuth"
#define DEVICE_AUTH_VERIFICATION_URI_COMPLETE "https://isp.tld/deviceUserAuth?code=deviceUserCode1234"
#define DEVICE_AUTH_EXPIRES_IN 90
#define DEVICE_AUTH_INTERVAL 5
#define END_SESSION_ENDPOINT "https://isp.tld/end_session"
#define CHECK_SESSION_IRAME "https://isp.tld/check_session"
#define PUSHED_AUTH_REQ_ENDPOINT "https://isp.tld/par"
#define PUSHED_AUTH_REQ_REQUIRED 1
#define PUSHED_AUTH_REQ_EXPIRES_IN 90
#define PUSHED_AUTH_REQ_URI "parURI1234"
#define USE_DPOP 1
#define DPOP_KID "dpop kid"
#define DPOP_SIGN_ALG "RS256"
#define DECRYPT_CODE 1
#define DECRYPT_REFRESH_TOKEN 1
#define DECRYPT_ACCESS_TOKEN 1
#define TLS_KEY_FILE "client.key"
#define TLS_CERT_FILE "client.pem"
#define REMOTE_CERT_FLAG 42

const char jwks_pubkey_ecdsa_str[] = "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                    "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}]}";

/**
 * json_t * json_search(json_t * haystack, json_t * needle)
 * jansson library addon
 * Look for an occurence of needle within haystack
 * If needle is present in haystack, return the reference to the json_t * that is equal to needle
 * If needle is not found, return NULL
 */
static json_t * json_search(json_t * haystack, json_t * needle) {
  json_t * value1 = NULL, * value2 = NULL;
  size_t index = 0;
  const char * key = NULL;

  if (!haystack || !needle)
    return NULL;

  if (haystack == needle)
    return haystack;

  // If both haystack and needle are the same type, test them
  if (json_typeof(haystack) == json_typeof(needle) && !json_is_object(haystack))
    if (json_equal(haystack, needle))
      return haystack;

  // If they are not equals, test json_search in haystack elements recursively if it's an array or an object
  if (json_is_array(haystack)) {
    json_array_foreach(haystack, index, value1) {
      if (json_equal(value1, needle)) {
        return value1;
      } else {
        value2 = json_search(value1, needle);
        if (value2 != NULL) {
          return value2;
        }
      }
    }
  } else if (json_is_object(haystack) && json_is_object(needle)) {
    int same = 1;
    json_object_foreach(needle, key, value1) {
      value2 = json_object_get(haystack, key);
      if (!json_equal(value1, value2)) {
        same = 0;
      }
    }
    if (same) {
      return haystack;
    }
  } else if (json_is_object(haystack)) {
    json_object_foreach(haystack, key, value1) {
      if (json_equal(value1, needle)) {
        return value1;
      } else {
        value2 = json_search(value1, needle);
        if (value2 != NULL) {
          return value2;
        }
      }
    }
  }
  return NULL;
}

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
  \"subject_types_supported\":[\"" SUBJECT_TYPE "\"]\
}";
const char openid_configuration_invalid_issuer[] = "{\
  \"issuer\":42,\
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
  \"subject_types_supported\":[\"" SUBJECT_TYPE "\"]\
}";

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
  ck_assert_int_eq(i_set_response_type(&i_session, I_RESPONSE_TYPE_NONE), I_OK);
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

START_TEST(test_iddawc_set_str_parameter)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, 0, NULL), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONE, NULL), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_RESPONSE_TYPE, NULL), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ADDITIONAL_PARAMETER, NULL), I_ERROR_PARAM);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_SCOPE, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_SCOPE, SCOPE1), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_SCOPE, SCOPE2), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_SCOPE, SCOPE_LIST), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_SCOPE_APPEND, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_SCOPE_APPEND, SCOPE1), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_SCOPE_APPEND, SCOPE2), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_SCOPE_APPEND, SCOPE_LIST), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_STATE, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_STATE, STATE), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REDIRECT_URI, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REDIRECT_URI, REDIRECT_URI), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REDIRECT_TO, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REDIRECT_TO, REDIRECT_TO), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_ID, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_ID, CLIENT_ID), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SECRET, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SECRET, CLIENT_SECRET), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_AUTH_ENDPOINT, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TOKEN_ENDPOINT, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_OPENID_CONFIG_ENDPOINT, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_OPENID_CONFIG_ENDPOINT, OPENID_CONFIG_ENDPOINT), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_USERINFO_ENDPOINT, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_USERINFO_ENDPOINT, USERINFO_ENDPOINT), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ERROR, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ERROR, ERROR), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION, ERROR_DESCRIPTION), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ERROR_URI, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ERROR_URI, ERROR_URI), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CODE, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CODE, CODE), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REFRESH_TOKEN, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REFRESH_TOKEN, REFRESH_TOKEN), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, ACCESS_TOKEN), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TOKEN_TYPE, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TOKEN_TYPE, TOKEN_TYPE), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, ID_TOKEN), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_USERNAME, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_USERNAME, USERNAME), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_USER_PASSWORD, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_USER_PASSWORD, USER_PASSWORD), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_USERINFO, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_USERINFO, USERINFO), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_OPENID_CONFIG, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_OPENID_CONFIG, openid_configuration_valid), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_OPENID_CONFIG, openid_configuration_invalid_issuer), I_ERROR);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_SERVER_KID, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_SERVER_KID, SERVER_KID), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_SERVER_ENC_ALG, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_SERVER_ENC_ALG, SERVER_ENC_ALG), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_SERVER_ENC, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_SERVER_ENC, SERVER_ENC), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_KID, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_KID, CLIENT_KID), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SIGN_ALG, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SIGN_ALG, CLIENT_SIGN_ALG), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_ENC_ALG, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_ENC_ALG, CLIENT_ENC_ALG), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_ENC, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_ENC, CLIENT_ENC), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TOKEN_JTI, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TOKEN_JTI, TOKEN_JTI), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TOKEN_TARGET, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TOKEN_TARGET, TOKEN_TARGET), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TOKEN_TARGET_TYPE_HINT, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TOKEN_TARGET_TYPE_HINT, TOKEN_TARGET_TYPE_HINT), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REVOCATION_ENDPOINT, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REVOCATION_ENDPOINT, REVOCATION_ENDPOINT), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_INTROSPECTION_ENDPOINT, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_INTROSPECTION_ENDPOINT, INTROSPECTION_ENDPOINT), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REGISTRATION_ENDPOINT, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REGISTRATION_ENDPOINT, REGISTRATION_ENDPOINT), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, DEVICE_AUTHORIZATION_ENDPOINT), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_DEVICE_AUTH_CODE, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_DEVICE_AUTH_CODE, DEVICE_AUTH_CODE), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_DEVICE_AUTH_USER_CODE, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_DEVICE_AUTH_USER_CODE, DEVICE_AUTH_USER_CODE), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI, DEVICE_AUTH_VERIFICATION_URI), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE, DEVICE_AUTH_VERIFICATION_URI_COMPLETE), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_END_SESSION_ENDPOINT, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_END_SESSION_ENDPOINT, END_SESSION_ENDPOINT), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CHECK_SESSION_IRAME, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CHECK_SESSION_IRAME, CHECK_SESSION_IRAME), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_ENDPOINT, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_ENDPOINT, PUSHED_AUTH_REQ_ENDPOINT), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_URI, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_URI, PUSHED_AUTH_REQ_URI), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_DPOP_KID, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_DPOP_KID, DPOP_KID), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_DPOP_SIGN_ALG, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_DPOP_SIGN_ALG, DPOP_SIGN_ALG), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TLS_KEY_FILE, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TLS_KEY_FILE, TLS_KEY_FILE), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TLS_CERT_FILE, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TLS_CERT_FILE, TLS_CERT_FILE), I_OK);

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_set_int_parameter)
{
  struct _i_session i_session;

  ck_assert_int_eq(i_init_session(&i_session), I_OK);

  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_AUTH_METHOD, I_AUTH_METHOD_GET), I_OK);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_AUTH_METHOD, I_AUTH_METHOD_POST), I_OK);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_AUTH_METHOD, I_AUTH_METHOD_POST|I_AUTH_METHOD_JWT_SIGN_SECRET), I_OK);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_AUTH_METHOD, I_AUTH_METHOD_GET|I_AUTH_METHOD_JWT_ENCRYPT_PUBKEY), I_OK);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_TOKEN_METHOD, I_TOKEN_AUTH_METHOD_SECRET_POST), I_OK);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_OPENID_CONFIG_STRICT, I_STRICT_NO), I_OK);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_EXPIRES_IN, EXPIRES_IN), I_OK);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_EXPIRES_AT, EXPIRES_AT), I_OK);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_NONCE_GENERATE, 32), I_OK);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_STATE_GENERATE, 32), I_OK);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_TOKEN_JTI_GENERATE, 32), I_OK);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_TOKEN_EXP, TOKEN_EXP), I_OK);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_DEVICE_AUTH_EXPIRES_IN, DEVICE_AUTH_EXPIRES_IN), I_OK);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_DEVICE_AUTH_INTERVAL, DEVICE_AUTH_INTERVAL), I_OK);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_REQUIRED, PUSHED_AUTH_REQ_REQUIRED), I_OK);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN, PUSHED_AUTH_REQ_EXPIRES_IN), I_OK);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_USE_DPOP, USE_DPOP), I_OK);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_DECRYPT_CODE, DECRYPT_CODE), I_OK);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_DECRYPT_REFRESH_TOKEN, DECRYPT_REFRESH_TOKEN), I_OK);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_DECRYPT_ACCESS_TOKEN, DECRYPT_ACCESS_TOKEN), I_OK);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_REMOTE_CERT_FLAG, REMOTE_CERT_FLAG), I_OK);

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_get_str_parameter)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_STATE, STATE), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_STATE), STATE);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_NONCE), NONCE);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_SCOPE, SCOPE1), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_SCOPE), SCOPE1);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_SCOPE_APPEND, SCOPE2), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_SCOPE), SCOPE_LIST);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REDIRECT_URI, REDIRECT_URI), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REDIRECT_URI), REDIRECT_URI);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REDIRECT_TO, REDIRECT_TO), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO), REDIRECT_TO);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_ID, CLIENT_ID), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CLIENT_ID), CLIENT_ID);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_AUTH_ENDPOINT), AUTH_ENDPOINT);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SECRET, CLIENT_SECRET), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CLIENT_SECRET), CLIENT_SECRET);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_ENDPOINT), TOKEN_ENDPOINT);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_OPENID_CONFIG_ENDPOINT, OPENID_CONFIG_ENDPOINT), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_OPENID_CONFIG_ENDPOINT), OPENID_CONFIG_ENDPOINT);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_USERINFO_ENDPOINT, USERINFO_ENDPOINT), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_USERINFO_ENDPOINT), USERINFO_ENDPOINT);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ERROR, ERROR), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), ERROR);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION, ERROR_DESCRIPTION), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), ERROR_DESCRIPTION);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ERROR_URI, ERROR_URI), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), ERROR_URI);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CODE, CODE), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CODE), CODE);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REFRESH_TOKEN, REFRESH_TOKEN), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), REFRESH_TOKEN);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, ACCESS_TOKEN), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), ACCESS_TOKEN);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TOKEN_TYPE, TOKEN_TYPE), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), TOKEN_TYPE);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, ID_TOKEN), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), ID_TOKEN);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_USERNAME, USERNAME), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_USERNAME), USERNAME);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_USER_PASSWORD, USER_PASSWORD), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_USER_PASSWORD), USER_PASSWORD);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ISSUER), ISSUER);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_USERINFO, USERINFO), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_USERINFO), USERINFO);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_SERVER_KID, SERVER_KID), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_SERVER_KID), SERVER_KID);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_SERVER_ENC_ALG, SERVER_ENC_ALG), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_SERVER_ENC_ALG), SERVER_ENC_ALG);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_SERVER_ENC, SERVER_ENC), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_SERVER_ENC), SERVER_ENC);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_KID, CLIENT_KID), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CLIENT_KID), CLIENT_KID);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SIGN_ALG, CLIENT_SIGN_ALG), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CLIENT_SIGN_ALG), CLIENT_SIGN_ALG);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_ENC_ALG, CLIENT_ENC_ALG), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CLIENT_ENC_ALG), CLIENT_ENC_ALG);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_ENC, CLIENT_ENC), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CLIENT_ENC), CLIENT_ENC);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TOKEN_JTI, TOKEN_JTI), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_JTI), TOKEN_JTI);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TOKEN_TARGET, TOKEN_TARGET), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TARGET), TOKEN_TARGET);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TOKEN_TARGET_TYPE_HINT, TOKEN_TARGET_TYPE_HINT), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TARGET_TYPE_HINT), TOKEN_TARGET_TYPE_HINT);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REVOCATION_ENDPOINT, REVOCATION_ENDPOINT), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REVOCATION_ENDPOINT), REVOCATION_ENDPOINT);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_INTROSPECTION_ENDPOINT, INTROSPECTION_ENDPOINT), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_INTROSPECTION_ENDPOINT), INTROSPECTION_ENDPOINT);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REGISTRATION_ENDPOINT, REGISTRATION_ENDPOINT), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REGISTRATION_ENDPOINT), REGISTRATION_ENDPOINT);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, DEVICE_AUTHORIZATION_ENDPOINT), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTHORIZATION_ENDPOINT), DEVICE_AUTHORIZATION_ENDPOINT);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_DEVICE_AUTH_CODE, DEVICE_AUTH_CODE), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_CODE), DEVICE_AUTH_CODE);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_DEVICE_AUTH_USER_CODE, DEVICE_AUTH_USER_CODE), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_USER_CODE), DEVICE_AUTH_USER_CODE);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI, DEVICE_AUTH_VERIFICATION_URI), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI), DEVICE_AUTH_VERIFICATION_URI);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE, DEVICE_AUTH_VERIFICATION_URI_COMPLETE), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE), DEVICE_AUTH_VERIFICATION_URI_COMPLETE);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_END_SESSION_ENDPOINT, END_SESSION_ENDPOINT), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_END_SESSION_ENDPOINT), END_SESSION_ENDPOINT);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CHECK_SESSION_IRAME, CHECK_SESSION_IRAME), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CHECK_SESSION_IRAME), CHECK_SESSION_IRAME);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_ENDPOINT, PUSHED_AUTH_REQ_ENDPOINT), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_ENDPOINT), PUSHED_AUTH_REQ_ENDPOINT);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_URI, PUSHED_AUTH_REQ_URI), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_URI), PUSHED_AUTH_REQ_URI);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_DPOP_KID, DPOP_KID), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_DPOP_KID), DPOP_KID);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_DPOP_SIGN_ALG, DPOP_SIGN_ALG), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_DPOP_SIGN_ALG), DPOP_SIGN_ALG);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TLS_KEY_FILE, TLS_KEY_FILE), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TLS_KEY_FILE), TLS_KEY_FILE);

  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TLS_CERT_FILE, TLS_CERT_FILE), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TLS_CERT_FILE), TLS_CERT_FILE);

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_get_int_parameter)
{
  struct _i_session i_session;

  ck_assert_int_eq(i_init_session(&i_session), I_OK);

  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_AUTH_METHOD, I_AUTH_METHOD_GET), I_OK);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_AUTH_METHOD), I_AUTH_METHOD_GET);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_AUTH_METHOD, I_AUTH_METHOD_POST|I_AUTH_METHOD_JWT_SIGN_SECRET), I_OK);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_AUTH_METHOD), I_AUTH_METHOD_POST|I_AUTH_METHOD_JWT_SIGN_SECRET);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_AUTH_METHOD, I_AUTH_METHOD_GET|I_AUTH_METHOD_JWT_ENCRYPT_PUBKEY), I_OK);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_AUTH_METHOD), I_AUTH_METHOD_GET|I_AUTH_METHOD_JWT_ENCRYPT_PUBKEY);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_AUTH_METHOD, I_AUTH_METHOD_POST), I_OK);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_AUTH_METHOD), I_AUTH_METHOD_POST);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_TOKEN_METHOD, I_TOKEN_AUTH_METHOD_SECRET_POST), I_OK);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_TOKEN_METHOD), I_TOKEN_AUTH_METHOD_SECRET_POST);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_EXPIRES_IN, EXPIRES_IN), I_OK);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), EXPIRES_IN);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_EXPIRES_AT, EXPIRES_AT), I_OK);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_AT), EXPIRES_AT);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_OPENID_CONFIG_STRICT, I_STRICT_NO), I_OK);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_OPENID_CONFIG_STRICT), I_STRICT_NO);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_NONCE_GENERATE, 32), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_NONCE), NULL);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_STATE_GENERATE, 32), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_STATE), NULL);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_TOKEN_JTI_GENERATE, 32), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_TOKEN_JTI), NULL);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_TOKEN_EXP, TOKEN_EXP), I_OK);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_TOKEN_EXP), TOKEN_EXP);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_DEVICE_AUTH_EXPIRES_IN, DEVICE_AUTH_EXPIRES_IN), I_OK);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_EXPIRES_IN), DEVICE_AUTH_EXPIRES_IN);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_DEVICE_AUTH_INTERVAL, DEVICE_AUTH_INTERVAL), I_OK);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_INTERVAL), DEVICE_AUTH_INTERVAL);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_REQUIRED, PUSHED_AUTH_REQ_REQUIRED), I_OK);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_REQUIRED), PUSHED_AUTH_REQ_REQUIRED);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN, PUSHED_AUTH_REQ_EXPIRES_IN), I_OK);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN), PUSHED_AUTH_REQ_EXPIRES_IN);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_USE_DPOP, USE_DPOP), I_OK);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_USE_DPOP), USE_DPOP);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_DECRYPT_CODE, DECRYPT_CODE), I_OK);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_DECRYPT_CODE), DECRYPT_CODE);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_DECRYPT_REFRESH_TOKEN, DECRYPT_REFRESH_TOKEN), I_OK);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_DECRYPT_REFRESH_TOKEN), DECRYPT_REFRESH_TOKEN);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_DECRYPT_ACCESS_TOKEN, DECRYPT_ACCESS_TOKEN), I_OK);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_DECRYPT_ACCESS_TOKEN), DECRYPT_ACCESS_TOKEN);
  ck_assert_int_eq(i_set_int_parameter(&i_session, I_OPT_REMOTE_CERT_FLAG, REMOTE_CERT_FLAG), I_OK);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_REMOTE_CERT_FLAG), REMOTE_CERT_FLAG);

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

START_TEST(test_iddawc_set_additional_response)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);

  ck_assert_int_eq(i_set_additional_response(&i_session, NULL, NULL), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_additional_response(&i_session, ADDITIONAL_KEY, NULL), I_OK);
  ck_assert_int_eq(i_set_additional_response(&i_session, NULL, ADDITIONAL_VALUE), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_additional_response(&i_session, ADDITIONAL_KEY, ADDITIONAL_VALUE), I_OK);

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_get_additional_response)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);

  ck_assert_int_eq(i_set_additional_response(&i_session, ADDITIONAL_KEY, ADDITIONAL_VALUE), I_OK);
  ck_assert_str_eq(i_get_additional_response(&i_session, ADDITIONAL_KEY), ADDITIONAL_VALUE);
  ck_assert_int_eq(i_set_additional_response(&i_session, ADDITIONAL_KEY, NULL), I_OK);
  ck_assert_ptr_eq(i_get_additional_response(&i_session, ADDITIONAL_KEY), NULL);
  ck_assert_int_eq(i_set_additional_response(&i_session, ADDITIONAL_KEY, ADDITIONAL_VALUE ADDITIONAL_VALUE), I_OK);
  ck_assert_str_eq(i_get_additional_response(&i_session, ADDITIONAL_KEY), ADDITIONAL_VALUE ADDITIONAL_VALUE);
  ck_assert_int_eq(i_set_additional_response(&i_session, ADDITIONAL_KEY, NULL), I_OK);
  ck_assert_ptr_eq(i_get_additional_response(&i_session, ADDITIONAL_KEY), NULL);

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_rich_authorization_request)
{
  char * str_rar, * str_rar_2;
  json_t * j_rar, * j_rar_2;
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);

  ck_assert_ptr_eq(i_get_rich_authorization_request_str(&i_session, AUTH_REQUEST_TYPE_1), NULL);

  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, AUTH_REQUEST_TYPE_1, AUTH_REQUEST_1), I_OK);
  ck_assert_ptr_ne(str_rar = i_get_rich_authorization_request_str(&i_session, AUTH_REQUEST_TYPE_1), NULL);
  j_rar = json_loads(str_rar, JSON_DECODE_ANY, NULL);
  j_rar_2 = json_loads(AUTH_REQUEST_FULL_1, JSON_DECODE_ANY, NULL);
  ck_assert_int_eq(1, json_equal(j_rar, j_rar_2));
  json_decref(j_rar);
  json_decref(j_rar_2);

  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, AUTH_REQUEST_TYPE_2, AUTH_REQUEST_2), I_OK);
  ck_assert_ptr_ne(str_rar_2 = i_get_rich_authorization_request_str(&i_session, AUTH_REQUEST_TYPE_2), NULL);
  ck_assert_str_ne(str_rar_2, str_rar);
  j_rar = json_loads(str_rar_2, JSON_DECODE_ANY, NULL);
  j_rar_2 = json_loads(AUTH_REQUEST_FULL_2, JSON_DECODE_ANY, NULL);
  ck_assert_int_eq(1, json_equal(j_rar, j_rar_2));
  json_decref(j_rar);
  json_decref(j_rar_2);
  o_free(str_rar);
  o_free(str_rar_2);
  str_rar = NULL;

  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, AUTH_REQUEST_TYPE_1, AUTH_REQUEST_2), I_OK);
  ck_assert_ptr_ne(str_rar = i_get_rich_authorization_request_str(&i_session, AUTH_REQUEST_TYPE_1), NULL);
  j_rar = json_loads(str_rar, JSON_DECODE_ANY, NULL);
  j_rar_2 = json_loads(AUTH_REQUEST_FULL_2, JSON_DECODE_ANY, NULL);
  json_object_set_new(j_rar_2, "type", json_string(AUTH_REQUEST_TYPE_1));
  ck_assert_int_eq(1, json_equal(j_rar, j_rar_2));
  json_decref(j_rar);
  json_decref(j_rar_2);
  o_free(str_rar);

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_parameter_list)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);

  ck_assert_int_eq(i_set_parameter_list(&i_session, 666, "error", I_OPT_NONE), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_SCOPE_APPEND, "error", I_OPT_NONE), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_STATE), NULL);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_NONE), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_STATE), NULL);

  ck_assert_int_eq(i_set_parameter_list(NULL, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                              I_OPT_SCOPE, SCOPE_LIST,
                                              I_OPT_STATE, STATE,
                                              I_OPT_NONE), I_ERROR_PARAM);

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
                                                  I_OPT_USERINFO_ENDPOINT, USERINFO_ENDPOINT,
                                                  I_OPT_RESULT, I_OK,
                                                  I_OPT_ERROR, ERROR,
                                                  I_OPT_ERROR_DESCRIPTION, ERROR_DESCRIPTION,
                                                  I_OPT_ERROR_URI, ERROR_URI,
                                                  I_OPT_CODE, CODE,
                                                  I_OPT_REFRESH_TOKEN, REFRESH_TOKEN,
                                                  I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                  I_OPT_TOKEN_TYPE, TOKEN_TYPE,
                                                  I_OPT_EXPIRES_IN, EXPIRES_IN,
                                                  I_OPT_EXPIRES_AT, EXPIRES_AT,
                                                  I_OPT_ID_TOKEN, ID_TOKEN,
                                                  I_OPT_USERNAME, USERNAME,
                                                  I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                  I_OPT_ADDITIONAL_PARAMETER, ADDITIONAL_KEY, ADDITIONAL_VALUE,
                                                  I_OPT_ADDITIONAL_RESPONSE, ADDITIONAL_KEY, ADDITIONAL_VALUE,
                                                  I_OPT_CLIENT_KID, CLIENT_KID,
                                                  I_OPT_SERVER_KID, SERVER_KID,
                                                  I_OPT_SERVER_ENC_ALG, SERVER_ENC_ALG,
                                                  I_OPT_SERVER_ENC, SERVER_ENC,
                                                  I_OPT_CLIENT_SIGN_ALG, CLIENT_SIGN_ALG,
                                                  I_OPT_CLIENT_ENC_ALG, CLIENT_ENC_ALG,
                                                  I_OPT_CLIENT_ENC, CLIENT_ENC,
                                                  I_OPT_TOKEN_JTI, TOKEN_JTI,
                                                  I_OPT_TOKEN_TARGET, TOKEN_TARGET,
                                                  I_OPT_TOKEN_TARGET_TYPE_HINT, TOKEN_TARGET_TYPE_HINT,
                                                  I_OPT_REVOCATION_ENDPOINT, REVOCATION_ENDPOINT,
                                                  I_OPT_INTROSPECTION_ENDPOINT, INTROSPECTION_ENDPOINT,
                                                  I_OPT_REGISTRATION_ENDPOINT, REGISTRATION_ENDPOINT,
                                                  I_OPT_USE_DPOP, USE_DPOP,
                                                  I_OPT_DPOP_KID, DPOP_KID,
                                                  I_OPT_DPOP_SIGN_ALG, DPOP_SIGN_ALG,
                                                  I_OPT_DECRYPT_CODE, DECRYPT_CODE,
                                                  I_OPT_DECRYPT_REFRESH_TOKEN, DECRYPT_REFRESH_TOKEN,
                                                  I_OPT_DECRYPT_ACCESS_TOKEN, DECRYPT_ACCESS_TOKEN,
                                                  I_OPT_TLS_KEY_FILE, TLS_KEY_FILE,
                                                  I_OPT_TLS_CERT_FILE, TLS_CERT_FILE,
                                                  I_OPT_REMOTE_CERT_FLAG, REMOTE_CERT_FLAG,
                                                  I_OPT_NONE), I_OK);

  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_STATE), STATE);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_NONCE), NONCE);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_SCOPE), SCOPE_LIST);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REDIRECT_URI), REDIRECT_URI);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO), REDIRECT_TO);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CLIENT_ID), CLIENT_ID);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_AUTH_ENDPOINT), AUTH_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CLIENT_SECRET), CLIENT_SECRET);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_ENDPOINT), TOKEN_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_OPENID_CONFIG_ENDPOINT), OPENID_CONFIG_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_USERINFO_ENDPOINT), USERINFO_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), ERROR);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), ERROR_DESCRIPTION);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), ERROR_URI);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CODE), CODE);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), REFRESH_TOKEN);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), ACCESS_TOKEN);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), TOKEN_TYPE);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), EXPIRES_IN);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_AT), EXPIRES_AT);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), ID_TOKEN);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_USERNAME), USERNAME);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_USER_PASSWORD), USER_PASSWORD);
  ck_assert_int_eq(i_set_additional_parameter(&i_session, ADDITIONAL_KEY, ADDITIONAL_VALUE ADDITIONAL_VALUE), I_OK);
  ck_assert_int_eq(i_set_additional_response(&i_session, ADDITIONAL_KEY, ADDITIONAL_VALUE ADDITIONAL_VALUE), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_SERVER_KID), SERVER_KID);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_SERVER_ENC_ALG), SERVER_ENC_ALG);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_SERVER_ENC), SERVER_ENC);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CLIENT_KID), CLIENT_KID);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CLIENT_SIGN_ALG), CLIENT_SIGN_ALG);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CLIENT_ENC_ALG), CLIENT_ENC_ALG);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_JTI), TOKEN_JTI);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CLIENT_ENC), CLIENT_ENC);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TARGET), TOKEN_TARGET);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TARGET_TYPE_HINT), TOKEN_TARGET_TYPE_HINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REVOCATION_ENDPOINT), REVOCATION_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_INTROSPECTION_ENDPOINT), INTROSPECTION_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REGISTRATION_ENDPOINT), REGISTRATION_ENDPOINT);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_USE_DPOP), USE_DPOP);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_DPOP_KID), DPOP_KID);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_DPOP_SIGN_ALG), DPOP_SIGN_ALG);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_DECRYPT_CODE), DECRYPT_CODE);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_DECRYPT_REFRESH_TOKEN), DECRYPT_REFRESH_TOKEN);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_DECRYPT_ACCESS_TOKEN), DECRYPT_ACCESS_TOKEN);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TLS_KEY_FILE), TLS_KEY_FILE);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TLS_CERT_FILE), TLS_CERT_FILE);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_REMOTE_CERT_FLAG), REMOTE_CERT_FLAG);

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_export_json_t)
{
  struct _i_session i_session;
  json_t * j_export, * j_additional = json_pack("{ss}", ADDITIONAL_KEY, ADDITIONAL_VALUE), * j_additional_empty = json_object(), * jwks_empty = json_pack("{s[]}", "keys"), * j_config = json_loads(openid_configuration_valid, JSON_DECODE_ANY, NULL), * j_auth_request = json_loads(AUTH_REQUEST_1, JSON_DECODE_ANY, NULL);
  json_object_set_new(j_auth_request, "type", json_string(AUTH_REQUEST_TYPE_1));

  ck_assert_int_eq(i_init_session(&i_session), I_OK);

  j_export = i_export_session_json_t(&i_session);
  ck_assert_ptr_ne(j_export, NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "response_type")), I_RESPONSE_TYPE_NONE);
  ck_assert_ptr_eq(json_object_get(j_export, "scope"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "nonce"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "state"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "redirect_uri"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "redirect_to"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "client_id"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "client_secret"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "username"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "user_password"), NULL);
  ck_assert_int_eq(json_equal(json_object_get(j_export, "additional_parameters"), j_additional_empty), 1);
  ck_assert_int_eq(json_equal(json_object_get(j_export, "additional_response"), j_additional_empty), 1);
  ck_assert_ptr_eq(json_object_get(j_export, "authorization_endpoint"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "token_endpoint"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "openid_config_endpoint"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "userinfo_endpoint"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "result")), 0);
  ck_assert_ptr_eq(json_object_get(j_export, "error"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "error_description"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "error_uri"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "code"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "refresh_token"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "access_token"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "token_type"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "expires_in")), 0);
  ck_assert_ptr_eq(json_object_get(j_export, "id_token"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "id_token_payload"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "auth_method")), I_AUTH_METHOD_GET);
  ck_assert_int_eq(json_equal(json_object_get(j_export, "server_jwks"), jwks_empty), 1);
  ck_assert_int_eq(json_equal(json_object_get(j_export, "client_jwks"), jwks_empty), 1);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "x5u_flags")), 0);
  ck_assert_ptr_eq(json_object_get(j_export, "openid_config"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "openid_config_strict")), I_STRICT_NO);
  ck_assert_ptr_eq(json_object_get(j_export, "issuer"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "userinfo"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "server-kid"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "server-sig-alg"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "server-enc-alg"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "client-kid"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "sig-alg"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "enc-alg"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "enc"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "token_jti"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "token_target"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "token_target_type_hint"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "revocation_endpoint"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "introspection_endpoint"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "registration_endpoint"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "token_exp")), 600);
  ck_assert_int_ne(json_is_array(json_object_get(j_export, "authorization_details")), 0);
  ck_assert_int_eq(json_array_size(json_object_get(j_export, "authorization_details")), 0);
  ck_assert_ptr_eq(json_object_get(j_export, "device_authorization_endpoint"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "device_auth_code"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "device_auth_user_code"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "device_auth_verifucation_uri"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "device_auth_verifucation_uri_complete"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "end_session_endpoint"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "check_session_iframe"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "device_auth_expires_in")), 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "device_auth_interval")), 0);
  ck_assert_ptr_eq(json_object_get(j_export, "pushed_authorization_request_endpoint"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "require_pushed_authorization_requests")), 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "pushed_authorization_request_expires_in")), 0);
  ck_assert_ptr_eq(json_object_get(j_export, "pushed_authorization_request_uri"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "use_dpop")), 0);
  ck_assert_ptr_eq(json_object_get(j_export, "dpop_kid"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "dpop-sig-alg"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "decrypt_code")), 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "decrypt_refresh_token")), 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "decrypt_access_token")), 0);
  ck_assert_ptr_eq(json_object_get(j_export, "key_file"), NULL);
  ck_assert_ptr_eq(json_object_get(j_export, "cert_file"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "remote_cert_flag")), I_REMOTE_HOST_VERIFY_PEER|I_REMOTE_HOST_VERIFY_HOSTNAME|I_REMOTE_PROXY_VERIFY_PEER|I_REMOTE_PROXY_VERIFY_HOSTNAME);
  json_decref(j_export);

  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE|I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_ID_TOKEN,
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
                                                    I_OPT_USERINFO_ENDPOINT, USERINFO_ENDPOINT,
                                                    I_OPT_RESULT, I_ERROR_UNAUTHORIZED,
                                                    I_OPT_ERROR, ERROR,
                                                    I_OPT_ERROR_DESCRIPTION, ERROR_DESCRIPTION,
                                                    I_OPT_ERROR_URI, ERROR_URI,
                                                    I_OPT_CODE, CODE,
                                                    I_OPT_REFRESH_TOKEN, REFRESH_TOKEN,
                                                    I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_TOKEN_TYPE, TOKEN_TYPE,
                                                    I_OPT_EXPIRES_IN, EXPIRES_IN,
                                                    I_OPT_EXPIRES_AT, EXPIRES_AT,
                                                    I_OPT_ID_TOKEN, ID_TOKEN,
                                                    I_OPT_USERNAME, USERNAME,
                                                    I_OPT_AUTH_METHOD, I_AUTH_METHOD_GET,
                                                    I_OPT_TOKEN_METHOD, I_TOKEN_AUTH_METHOD_SECRET_POST,
                                                    I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                    I_OPT_ADDITIONAL_RESPONSE, ADDITIONAL_KEY, ADDITIONAL_VALUE,
                                                    I_OPT_X5U_FLAGS, R_FLAG_IGNORE_SERVER_CERTIFICATE|R_FLAG_FOLLOW_REDIRECT,
                                                    I_OPT_OPENID_CONFIG, openid_configuration_valid,
                                                    I_OPT_OPENID_CONFIG_STRICT, I_STRICT_NO,
                                                    I_OPT_ISSUER, ISSUER,
                                                    I_OPT_USERINFO, USERINFO,
                                                    I_OPT_CLIENT_KID, CLIENT_KID,
                                                    I_OPT_SERVER_ENC_ALG, SERVER_ENC_ALG,
                                                    I_OPT_SERVER_ENC, SERVER_ENC,
                                                    I_OPT_SERVER_KID, SERVER_KID,
                                                    I_OPT_CLIENT_SIGN_ALG, CLIENT_SIGN_ALG,
                                                    I_OPT_CLIENT_ENC_ALG, CLIENT_ENC_ALG,
                                                    I_OPT_CLIENT_ENC, CLIENT_ENC,
                                                    I_OPT_TOKEN_JTI, TOKEN_JTI,
                                                    I_OPT_TOKEN_EXP, TOKEN_EXP,
                                                    I_OPT_TOKEN_TARGET, TOKEN_TARGET,
                                                    I_OPT_TOKEN_TARGET_TYPE_HINT, TOKEN_TARGET_TYPE_HINT,
                                                    I_OPT_REVOCATION_ENDPOINT, REVOCATION_ENDPOINT,
                                                    I_OPT_INTROSPECTION_ENDPOINT, INTROSPECTION_ENDPOINT,
                                                    I_OPT_REGISTRATION_ENDPOINT, REGISTRATION_ENDPOINT,
                                                    I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, DEVICE_AUTHORIZATION_ENDPOINT,
                                                    I_OPT_DEVICE_AUTH_CODE, DEVICE_AUTH_CODE,
                                                    I_OPT_DEVICE_AUTH_USER_CODE, DEVICE_AUTH_USER_CODE,
                                                    I_OPT_DEVICE_AUTH_VERIFICATION_URI, DEVICE_AUTH_VERIFICATION_URI,
                                                    I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE, DEVICE_AUTH_VERIFICATION_URI_COMPLETE,
                                                    I_OPT_DEVICE_AUTH_EXPIRES_IN, DEVICE_AUTH_EXPIRES_IN,
                                                    I_OPT_DEVICE_AUTH_INTERVAL, DEVICE_AUTH_INTERVAL,
                                                    I_OPT_END_SESSION_ENDPOINT, END_SESSION_ENDPOINT,
                                                    I_OPT_CHECK_SESSION_IRAME, CHECK_SESSION_IRAME,
                                                    I_OPT_PUSHED_AUTH_REQ_ENDPOINT, PUSHED_AUTH_REQ_ENDPOINT,
                                                    I_OPT_PUSHED_AUTH_REQ_REQUIRED, PUSHED_AUTH_REQ_REQUIRED,
                                                    I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN, PUSHED_AUTH_REQ_EXPIRES_IN,
                                                    I_OPT_PUSHED_AUTH_REQ_URI, PUSHED_AUTH_REQ_URI,
                                                    I_OPT_USE_DPOP, USE_DPOP,
                                                    I_OPT_DPOP_KID, DPOP_KID,
                                                    I_OPT_DPOP_SIGN_ALG, DPOP_SIGN_ALG,
                                                    I_OPT_DECRYPT_CODE, DECRYPT_CODE,
                                                    I_OPT_DECRYPT_REFRESH_TOKEN, DECRYPT_REFRESH_TOKEN,
                                                    I_OPT_DECRYPT_ACCESS_TOKEN, DECRYPT_ACCESS_TOKEN,
                                                    I_OPT_TLS_KEY_FILE, TLS_KEY_FILE,
                                                    I_OPT_TLS_CERT_FILE, TLS_CERT_FILE,
                                                    I_OPT_REMOTE_CERT_FLAG, REMOTE_CERT_FLAG,
                                                    I_OPT_NONE), I_OK);
  i_session.id_token_payload = json_pack("{ss}", "aud", "payload");
  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, AUTH_REQUEST_TYPE_1, AUTH_REQUEST_1), I_OK);

  j_export = i_export_session_json_t(&i_session);
  ck_assert_ptr_ne(j_export, NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "response_type")), I_RESPONSE_TYPE_CODE|I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_ID_TOKEN);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "scope")), SCOPE_LIST);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "nonce")), NONCE);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "state")), STATE);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "redirect_uri")), REDIRECT_URI);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "redirect_to")), REDIRECT_TO);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "client_id")), CLIENT_ID);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "client_secret")), CLIENT_SECRET);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "username")), USERNAME);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "user_password")), USER_PASSWORD);
  ck_assert_int_eq(json_equal(json_object_get(j_export, "additional_parameters"), j_additional), 1);
  ck_assert_int_eq(json_equal(json_object_get(j_export, "additional_response"), j_additional), 1);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "authorization_endpoint")), AUTH_ENDPOINT);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "token_endpoint")), TOKEN_ENDPOINT);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "openid_config_endpoint")), OPENID_CONFIG_ENDPOINT);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "userinfo_endpoint")), USERINFO_ENDPOINT);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "result")), I_ERROR_UNAUTHORIZED);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "error")), ERROR);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "error_description")), ERROR_DESCRIPTION);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "error_uri")), ERROR_URI);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "code")), CODE);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "refresh_token")), REFRESH_TOKEN);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "access_token")), ACCESS_TOKEN);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "token_type")), TOKEN_TYPE);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "expires_in")), EXPIRES_IN);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "expires_at")), EXPIRES_AT);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "id_token")), ID_TOKEN);
  ck_assert_int_eq(json_equal(json_object_get(j_export, "id_token_payload"), i_session.id_token_payload), 1);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "auth_method")), I_AUTH_METHOD_GET);
  ck_assert_int_eq(json_equal(json_object_get(j_export, "server_jwks"), i_session.server_jwks), 1);
  ck_assert_int_eq(json_equal(json_object_get(j_export, "client_jwks"), i_session.client_jwks), 1);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "x5u_flags")), R_FLAG_IGNORE_SERVER_CERTIFICATE|R_FLAG_FOLLOW_REDIRECT);
  ck_assert_int_eq(json_equal(json_object_get(j_export, "openid_config"), j_config), 1);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "openid_config_strict")), I_STRICT_NO);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "issuer")), ISSUER);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "userinfo")), USERINFO);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "server-kid")), SERVER_KID);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "server-enc-alg")), SERVER_ENC_ALG);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "server-enc")), SERVER_ENC);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "client-kid")), CLIENT_KID);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "sig-alg")), CLIENT_SIGN_ALG);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "enc-alg")), CLIENT_ENC_ALG);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "enc")), CLIENT_ENC);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "token_jti")), TOKEN_JTI);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "token_exp")), TOKEN_EXP);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "token_target")), TOKEN_TARGET);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "token_target_type_hint")), TOKEN_TARGET_TYPE_HINT);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "revocation_endpoint")), REVOCATION_ENDPOINT);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "introspection_endpoint")), INTROSPECTION_ENDPOINT);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "registration_endpoint")), REGISTRATION_ENDPOINT);
  ck_assert_ptr_ne(NULL, json_search(json_object_get(j_export, "authorization_details"), j_auth_request));
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "device_authorization_endpoint")), DEVICE_AUTHORIZATION_ENDPOINT);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "device_auth_code")), DEVICE_AUTH_CODE);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "device_auth_user_code")), DEVICE_AUTH_USER_CODE);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "device_auth_verifucation_uri")), DEVICE_AUTH_VERIFICATION_URI);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "device_auth_verifucation_uri_complete")), DEVICE_AUTH_VERIFICATION_URI_COMPLETE);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "device_auth_expires_in")), DEVICE_AUTH_EXPIRES_IN);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "device_auth_interval")), DEVICE_AUTH_INTERVAL);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "end_session_endpoint")), END_SESSION_ENDPOINT);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "check_session_iframe")), CHECK_SESSION_IRAME);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "pushed_authorization_request_endpoint")), PUSHED_AUTH_REQ_ENDPOINT);
  ck_assert_ptr_eq(json_object_get(j_export, "require_pushed_authorization_requests"), json_true());
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "pushed_authorization_request_expires_in")), PUSHED_AUTH_REQ_EXPIRES_IN);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "pushed_authorization_request_uri")), PUSHED_AUTH_REQ_URI);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "use_dpop")), USE_DPOP);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "dpop_kid")), DPOP_KID);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "dpop-sig-alg")), DPOP_SIGN_ALG);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "decrypt_code")), DECRYPT_CODE);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "decrypt_refresh_token")), DECRYPT_REFRESH_TOKEN);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "decrypt_access_token")), DECRYPT_ACCESS_TOKEN);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "key_file")), TLS_KEY_FILE);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "cert_file")), TLS_CERT_FILE);
  ck_assert_int_eq(json_integer_value(json_object_get(j_export, "remote_cert_flag")), REMOTE_CERT_FLAG);
  json_decref(j_export);

  json_decref(j_additional);
  json_decref(j_additional_empty);
  json_decref(jwks_empty);
  json_decref(j_config);
  json_decref(j_auth_request);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_import_json_t)
{
  struct _i_session i_session, i_session_import;
  json_t * j_export = NULL, * j_config = json_loads(openid_configuration_valid, JSON_DECODE_ANY, NULL), * j_userinfo = json_loads(USERINFO, JSON_DECODE_ANY, NULL), * jwks = NULL, * j_auth_request = json_loads(AUTH_REQUEST_1, JSON_DECODE_ANY, NULL);
  json_object_set_new(j_auth_request, "type", json_string(AUTH_REQUEST_TYPE_1));

  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_init_session(&i_session_import), I_OK);

  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE|I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_ID_TOKEN,
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
                                                    I_OPT_USERINFO_ENDPOINT, USERINFO_ENDPOINT,
                                                    I_OPT_RESULT, I_ERROR_UNAUTHORIZED,
                                                    I_OPT_ERROR, ERROR,
                                                    I_OPT_ERROR_DESCRIPTION, ERROR_DESCRIPTION,
                                                    I_OPT_ERROR_URI, ERROR_URI,
                                                    I_OPT_CODE, CODE,
                                                    I_OPT_REFRESH_TOKEN, REFRESH_TOKEN,
                                                    I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_TOKEN_TYPE, TOKEN_TYPE,
                                                    I_OPT_EXPIRES_IN, EXPIRES_IN,
                                                    I_OPT_EXPIRES_AT, EXPIRES_AT,
                                                    I_OPT_ID_TOKEN, ID_TOKEN,
                                                    I_OPT_USERNAME, USERNAME,
                                                    I_OPT_AUTH_METHOD, I_AUTH_METHOD_GET,
                                                    I_OPT_TOKEN_METHOD, I_TOKEN_AUTH_METHOD_SECRET_POST,
                                                    I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                    I_OPT_ADDITIONAL_RESPONSE, ADDITIONAL_KEY, ADDITIONAL_VALUE,
                                                    I_OPT_X5U_FLAGS, R_FLAG_IGNORE_SERVER_CERTIFICATE|R_FLAG_FOLLOW_REDIRECT,
                                                    I_OPT_OPENID_CONFIG, openid_configuration_valid,
                                                    I_OPT_OPENID_CONFIG_STRICT, I_STRICT_NO,
                                                    I_OPT_ISSUER, ISSUER,
                                                    I_OPT_USERINFO, USERINFO,
                                                    I_OPT_CLIENT_KID, CLIENT_KID,
                                                    I_OPT_SERVER_KID, SERVER_KID,
                                                    I_OPT_SERVER_ENC_ALG, SERVER_ENC_ALG,
                                                    I_OPT_SERVER_ENC, SERVER_ENC,
                                                    I_OPT_CLIENT_SIGN_ALG, CLIENT_SIGN_ALG,
                                                    I_OPT_CLIENT_ENC_ALG, CLIENT_ENC_ALG,
                                                    I_OPT_CLIENT_ENC, CLIENT_ENC,
                                                    I_OPT_TOKEN_JTI, TOKEN_JTI,
                                                    I_OPT_TOKEN_EXP, TOKEN_EXP,
                                                    I_OPT_TOKEN_TARGET, TOKEN_TARGET,
                                                    I_OPT_TOKEN_TARGET_TYPE_HINT, TOKEN_TARGET_TYPE_HINT,
                                                    I_OPT_REVOCATION_ENDPOINT, REVOCATION_ENDPOINT,
                                                    I_OPT_INTROSPECTION_ENDPOINT, INTROSPECTION_ENDPOINT,
                                                    I_OPT_REGISTRATION_ENDPOINT, REGISTRATION_ENDPOINT,
                                                    I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, DEVICE_AUTHORIZATION_ENDPOINT,
                                                    I_OPT_DEVICE_AUTH_CODE, DEVICE_AUTH_CODE,
                                                    I_OPT_DEVICE_AUTH_USER_CODE, DEVICE_AUTH_USER_CODE,
                                                    I_OPT_DEVICE_AUTH_VERIFICATION_URI, DEVICE_AUTH_VERIFICATION_URI,
                                                    I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE, DEVICE_AUTH_VERIFICATION_URI_COMPLETE,
                                                    I_OPT_DEVICE_AUTH_EXPIRES_IN, DEVICE_AUTH_EXPIRES_IN,
                                                    I_OPT_DEVICE_AUTH_INTERVAL, DEVICE_AUTH_INTERVAL,
                                                    I_OPT_END_SESSION_ENDPOINT, END_SESSION_ENDPOINT,
                                                    I_OPT_CHECK_SESSION_IRAME, CHECK_SESSION_IRAME,
                                                    I_OPT_PUSHED_AUTH_REQ_ENDPOINT, PUSHED_AUTH_REQ_ENDPOINT,
                                                    I_OPT_PUSHED_AUTH_REQ_REQUIRED, PUSHED_AUTH_REQ_REQUIRED,
                                                    I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN, PUSHED_AUTH_REQ_EXPIRES_IN,
                                                    I_OPT_PUSHED_AUTH_REQ_URI, PUSHED_AUTH_REQ_URI,
                                                    I_OPT_USE_DPOP, USE_DPOP,
                                                    I_OPT_DPOP_KID, DPOP_KID,
                                                    I_OPT_DPOP_SIGN_ALG, DPOP_SIGN_ALG,
                                                    I_OPT_DECRYPT_CODE, DECRYPT_CODE,
                                                    I_OPT_DECRYPT_REFRESH_TOKEN, DECRYPT_REFRESH_TOKEN,
                                                    I_OPT_DECRYPT_ACCESS_TOKEN, DECRYPT_ACCESS_TOKEN,
                                                    I_OPT_TLS_KEY_FILE, TLS_KEY_FILE,
                                                    I_OPT_TLS_CERT_FILE, TLS_CERT_FILE,
                                                    I_OPT_REMOTE_CERT_FLAG, REMOTE_CERT_FLAG,
                                                    I_OPT_NONE), I_OK);
  i_session.id_token_payload = json_pack("{ss}", "aud", "payload");
  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, AUTH_REQUEST_TYPE_1, AUTH_REQUEST_1), I_OK);
  ck_assert_int_eq(r_jwks_import_from_str(i_session.server_jwks, jwks_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_str(i_session.client_jwks, jwks_pubkey_ecdsa_str), RHN_OK);

  j_export = i_export_session_json_t(&i_session);
  ck_assert_ptr_ne(j_export, NULL);
  ck_assert_int_eq(i_import_session_json_t(&i_session_import, j_export), I_OK);
  ck_assert_int_eq(i_get_response_type(&i_session_import), I_RESPONSE_TYPE_CODE|I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_ID_TOKEN);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_SCOPE), SCOPE_LIST);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_NONCE), NONCE);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_STATE), STATE);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_REDIRECT_URI), REDIRECT_URI);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_REDIRECT_TO), REDIRECT_TO);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_CLIENT_ID), CLIENT_ID);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_CLIENT_SECRET), CLIENT_SECRET);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_USERNAME), USERNAME);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_USER_PASSWORD), USER_PASSWORD);
  ck_assert_str_eq(i_get_additional_parameter(&i_session_import, ADDITIONAL_KEY), ADDITIONAL_VALUE);
  ck_assert_str_eq(i_get_additional_response(&i_session_import, ADDITIONAL_KEY), ADDITIONAL_VALUE);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_AUTH_ENDPOINT), AUTH_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_TOKEN_ENDPOINT), TOKEN_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_OPENID_CONFIG_ENDPOINT), OPENID_CONFIG_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_USERINFO_ENDPOINT), USERINFO_ENDPOINT);
  ck_assert_int_eq(i_get_int_parameter(&i_session_import, I_OPT_RESULT), I_ERROR_UNAUTHORIZED);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_ERROR), ERROR);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_ERROR_DESCRIPTION), ERROR_DESCRIPTION);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_ERROR_URI), ERROR_URI);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_CODE), CODE);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_REFRESH_TOKEN), REFRESH_TOKEN);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_ACCESS_TOKEN), ACCESS_TOKEN);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_TOKEN_TYPE), TOKEN_TYPE);
  ck_assert_int_eq(i_get_int_parameter(&i_session_import, I_OPT_EXPIRES_IN), EXPIRES_IN);
  ck_assert_int_eq(i_get_int_parameter(&i_session_import, I_OPT_EXPIRES_AT), EXPIRES_AT);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_ID_TOKEN), ID_TOKEN);
  ck_assert_int_eq(json_equal(i_session_import.id_token_payload, i_session.id_token_payload), 1);
  ck_assert_int_eq(i_get_int_parameter(&i_session_import, I_OPT_AUTH_METHOD), I_AUTH_METHOD_GET);
  ck_assert_int_eq(i_get_int_parameter(&i_session_import, I_OPT_TOKEN_METHOD), I_TOKEN_AUTH_METHOD_SECRET_POST);
  ck_assert_int_eq(json_equal(i_session_import.server_jwks, i_session.server_jwks), 1);
  ck_assert_int_eq(i_get_int_parameter(&i_session_import, I_OPT_X5U_FLAGS), R_FLAG_IGNORE_SERVER_CERTIFICATE|R_FLAG_FOLLOW_REDIRECT);
  ck_assert_int_eq(json_equal(i_session_import.openid_config, j_config), 1);
  ck_assert_int_eq(i_get_int_parameter(&i_session_import, I_OPT_OPENID_CONFIG_STRICT), I_STRICT_NO);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_ISSUER), ISSUER);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_USERINFO), USERINFO);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_SERVER_KID), SERVER_KID);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_SERVER_ENC_ALG), SERVER_ENC_ALG);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_SERVER_ENC), SERVER_ENC);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CLIENT_KID), CLIENT_KID);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CLIENT_SIGN_ALG), CLIENT_SIGN_ALG);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CLIENT_ENC_ALG), CLIENT_ENC_ALG);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CLIENT_ENC), CLIENT_ENC);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_JTI), TOKEN_JTI);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_TOKEN_EXP), TOKEN_EXP);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TARGET), TOKEN_TARGET);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TARGET_TYPE_HINT), TOKEN_TARGET_TYPE_HINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REVOCATION_ENDPOINT), REVOCATION_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_INTROSPECTION_ENDPOINT), INTROSPECTION_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REGISTRATION_ENDPOINT), REGISTRATION_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTHORIZATION_ENDPOINT), DEVICE_AUTHORIZATION_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_CODE), DEVICE_AUTH_CODE);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_USER_CODE), DEVICE_AUTH_USER_CODE);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI), DEVICE_AUTH_VERIFICATION_URI);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE), DEVICE_AUTH_VERIFICATION_URI_COMPLETE);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_EXPIRES_IN), DEVICE_AUTH_EXPIRES_IN);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_INTERVAL), DEVICE_AUTH_INTERVAL);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_END_SESSION_ENDPOINT), END_SESSION_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CHECK_SESSION_IRAME), CHECK_SESSION_IRAME);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_ENDPOINT), PUSHED_AUTH_REQ_ENDPOINT);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_REQUIRED), PUSHED_AUTH_REQ_REQUIRED);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN), PUSHED_AUTH_REQ_EXPIRES_IN);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_URI), PUSHED_AUTH_REQ_URI);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_USE_DPOP), USE_DPOP);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_DPOP_KID), DPOP_KID);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_DPOP_SIGN_ALG), DPOP_SIGN_ALG);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_DECRYPT_CODE), DECRYPT_CODE);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_DECRYPT_REFRESH_TOKEN), DECRYPT_REFRESH_TOKEN);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_DECRYPT_ACCESS_TOKEN), DECRYPT_ACCESS_TOKEN);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TLS_KEY_FILE), TLS_KEY_FILE);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TLS_CERT_FILE), TLS_CERT_FILE);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_REMOTE_CERT_FLAG), REMOTE_CERT_FLAG);
  ck_assert_int_eq(json_equal(i_session_import.j_userinfo, j_userinfo), 1);
  ck_assert_int_eq(r_jwks_size(i_session.server_jwks), 1);
  ck_assert_int_eq(r_jwks_size(i_session.client_jwks), 1);
  json_decref(j_export);

  json_decref(j_config);
  json_decref(j_userinfo);
  json_decref(jwks);
  json_decref(j_auth_request);
  i_clean_session(&i_session);
  i_clean_session(&i_session_import);
}
END_TEST

START_TEST(test_iddawc_export_str)
{
  struct _i_session i_session;
  json_t * j_additional = json_pack("{ss}", ADDITIONAL_KEY, ADDITIONAL_VALUE), * j_additional_empty = json_object(), * j_config = json_loads(openid_configuration_valid, JSON_DECODE_ANY, NULL);
  char * str_export;

  ck_assert_int_eq(i_init_session(&i_session), I_OK);

  str_export = i_export_session_str(&i_session);
  ck_assert_str_eq(str_export, "{\"response_type\":0,\"additional_parameters\":{},\"additional_response\":{},\"result\":0,\"expires_in\":0,\"expires_at\":0,\"auth_method\":1,\"token_method\":0,\"server_jwks\":{\"keys\":[]},\"x5u_flags\":0,\"openid_config_strict\":0,\"token_exp\":600,\"authorization_details\":[],\"device_auth_expires_in\":0,\"device_auth_interval\":0,\"require_pushed_authorization_requests\":false,\"pushed_authorization_request_expires_in\":0,\"use_dpop\":0,\"decrypt_code\":0,\"decrypt_refresh_token\":0,\"decrypt_access_token\":0,\"client_jwks\":{\"keys\":[]},\"remote_cert_flag\":4369}");
  o_free(str_export);

  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE|I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_ID_TOKEN,
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
                                                    I_OPT_USERINFO_ENDPOINT, USERINFO_ENDPOINT,
                                                    I_OPT_RESULT, I_ERROR_UNAUTHORIZED,
                                                    I_OPT_ERROR, ERROR,
                                                    I_OPT_ERROR_DESCRIPTION, ERROR_DESCRIPTION,
                                                    I_OPT_ERROR_URI, ERROR_URI,
                                                    I_OPT_CODE, CODE,
                                                    I_OPT_REFRESH_TOKEN, REFRESH_TOKEN,
                                                    I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_TOKEN_TYPE, TOKEN_TYPE,
                                                    I_OPT_EXPIRES_IN, EXPIRES_IN,
                                                    I_OPT_EXPIRES_AT, EXPIRES_AT,
                                                    I_OPT_ID_TOKEN, ID_TOKEN,
                                                    I_OPT_USERNAME, USERNAME,
                                                    I_OPT_AUTH_METHOD, I_AUTH_METHOD_GET,
                                                    I_OPT_TOKEN_METHOD, I_TOKEN_AUTH_METHOD_SECRET_POST,
                                                    I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                    I_OPT_ADDITIONAL_RESPONSE, ADDITIONAL_KEY, ADDITIONAL_VALUE,
                                                    I_OPT_X5U_FLAGS, R_FLAG_IGNORE_SERVER_CERTIFICATE|R_FLAG_FOLLOW_REDIRECT,
                                                    I_OPT_OPENID_CONFIG, openid_configuration_valid,
                                                    I_OPT_OPENID_CONFIG_STRICT, I_STRICT_NO,
                                                    I_OPT_ISSUER, ISSUER,
                                                    I_OPT_USERINFO, USERINFO,
                                                    I_OPT_ISSUER, ISSUER,
                                                    I_OPT_USERINFO, USERINFO,
                                                    I_OPT_CLIENT_SIGN_ALG, CLIENT_SIGN_ALG,
                                                    I_OPT_CLIENT_ENC_ALG, CLIENT_ENC_ALG,
                                                    I_OPT_CLIENT_ENC, CLIENT_ENC,
                                                    I_OPT_TOKEN_JTI, TOKEN_JTI,
                                                    I_OPT_TOKEN_EXP, TOKEN_EXP,
                                                    I_OPT_TOKEN_TARGET, TOKEN_TARGET,
                                                    I_OPT_TOKEN_TARGET_TYPE_HINT, TOKEN_TARGET_TYPE_HINT,
                                                    I_OPT_REVOCATION_ENDPOINT, REVOCATION_ENDPOINT,
                                                    I_OPT_INTROSPECTION_ENDPOINT, INTROSPECTION_ENDPOINT,
                                                    I_OPT_REGISTRATION_ENDPOINT, REGISTRATION_ENDPOINT,
                                                    I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, DEVICE_AUTHORIZATION_ENDPOINT,
                                                    I_OPT_DEVICE_AUTH_CODE, DEVICE_AUTH_CODE,
                                                    I_OPT_DEVICE_AUTH_USER_CODE, DEVICE_AUTH_USER_CODE,
                                                    I_OPT_DEVICE_AUTH_VERIFICATION_URI, DEVICE_AUTH_VERIFICATION_URI,
                                                    I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE, DEVICE_AUTH_VERIFICATION_URI_COMPLETE,
                                                    I_OPT_DEVICE_AUTH_EXPIRES_IN, DEVICE_AUTH_EXPIRES_IN,
                                                    I_OPT_DEVICE_AUTH_INTERVAL, DEVICE_AUTH_INTERVAL,
                                                    I_OPT_END_SESSION_ENDPOINT, END_SESSION_ENDPOINT,
                                                    I_OPT_CHECK_SESSION_IRAME, CHECK_SESSION_IRAME,
                                                    I_OPT_PUSHED_AUTH_REQ_ENDPOINT, PUSHED_AUTH_REQ_ENDPOINT,
                                                    I_OPT_PUSHED_AUTH_REQ_REQUIRED, PUSHED_AUTH_REQ_REQUIRED,
                                                    I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN, PUSHED_AUTH_REQ_EXPIRES_IN,
                                                    I_OPT_PUSHED_AUTH_REQ_URI, PUSHED_AUTH_REQ_URI,
                                                    I_OPT_USE_DPOP, USE_DPOP,
                                                    I_OPT_DPOP_KID, DPOP_KID,
                                                    I_OPT_DPOP_SIGN_ALG, DPOP_SIGN_ALG,
                                                    I_OPT_DECRYPT_CODE, DECRYPT_CODE,
                                                    I_OPT_DECRYPT_REFRESH_TOKEN, DECRYPT_REFRESH_TOKEN,
                                                    I_OPT_DECRYPT_ACCESS_TOKEN, DECRYPT_ACCESS_TOKEN,
                                                    I_OPT_TLS_KEY_FILE, TLS_KEY_FILE,
                                                    I_OPT_TLS_CERT_FILE, TLS_CERT_FILE,
                                                    I_OPT_REMOTE_CERT_FLAG, REMOTE_CERT_FLAG,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwks_import_from_str(i_session.server_jwks, jwks_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_str(i_session.client_jwks, jwks_pubkey_ecdsa_str), RHN_OK);
  i_session.id_token_payload = json_pack("{ss}", "aud", "payload");
  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, AUTH_REQUEST_TYPE_1, AUTH_REQUEST_1), I_OK);

  ck_assert_ptr_ne(str_export = i_export_session_str(&i_session), NULL);
  o_free(str_export);

  json_decref(j_additional);
  json_decref(j_additional_empty);
  json_decref(j_config);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_import_str)
{
  struct _i_session i_session, i_session_import;
  json_t * j_config = json_loads(openid_configuration_valid, JSON_DECODE_ANY, NULL), * j_userinfo = json_loads(USERINFO, JSON_DECODE_ANY, NULL), * jwks = NULL;
  char * str_import, * str_rar;

  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_init_session(&i_session_import), I_OK);

  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE|I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_ID_TOKEN,
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
                                                    I_OPT_USERINFO_ENDPOINT, USERINFO_ENDPOINT,
                                                    I_OPT_RESULT, I_ERROR_UNAUTHORIZED,
                                                    I_OPT_ERROR, ERROR,
                                                    I_OPT_ERROR_DESCRIPTION, ERROR_DESCRIPTION,
                                                    I_OPT_ERROR_URI, ERROR_URI,
                                                    I_OPT_CODE, CODE,
                                                    I_OPT_REFRESH_TOKEN, REFRESH_TOKEN,
                                                    I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_TOKEN_TYPE, TOKEN_TYPE,
                                                    I_OPT_EXPIRES_IN, EXPIRES_IN,
                                                    I_OPT_EXPIRES_AT, EXPIRES_AT,
                                                    I_OPT_ID_TOKEN, ID_TOKEN,
                                                    I_OPT_USERNAME, USERNAME,
                                                    I_OPT_AUTH_METHOD, I_AUTH_METHOD_GET,
                                                    I_OPT_TOKEN_METHOD, I_TOKEN_AUTH_METHOD_SECRET_POST,
                                                    I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                    I_OPT_ADDITIONAL_RESPONSE, ADDITIONAL_KEY, ADDITIONAL_VALUE,
                                                    I_OPT_X5U_FLAGS, R_FLAG_IGNORE_SERVER_CERTIFICATE|R_FLAG_FOLLOW_REDIRECT,
                                                    I_OPT_OPENID_CONFIG, openid_configuration_valid,
                                                    I_OPT_OPENID_CONFIG_STRICT, I_STRICT_NO,
                                                    I_OPT_ISSUER, ISSUER,
                                                    I_OPT_USERINFO, USERINFO,
                                                    I_OPT_ISSUER, ISSUER,
                                                    I_OPT_USERINFO, USERINFO,
                                                    I_OPT_CLIENT_KID, CLIENT_KID,
                                                    I_OPT_SERVER_KID, SERVER_KID,
                                                    I_OPT_CLIENT_SIGN_ALG, CLIENT_SIGN_ALG,
                                                    I_OPT_CLIENT_ENC_ALG, CLIENT_ENC_ALG,
                                                    I_OPT_CLIENT_ENC, CLIENT_ENC,
                                                    I_OPT_TOKEN_JTI, TOKEN_JTI,
                                                    I_OPT_TOKEN_EXP, TOKEN_EXP,
                                                    I_OPT_TOKEN_TARGET, TOKEN_TARGET,
                                                    I_OPT_TOKEN_TARGET_TYPE_HINT, TOKEN_TARGET_TYPE_HINT,
                                                    I_OPT_REVOCATION_ENDPOINT, REVOCATION_ENDPOINT,
                                                    I_OPT_INTROSPECTION_ENDPOINT, INTROSPECTION_ENDPOINT,
                                                    I_OPT_REGISTRATION_ENDPOINT, REGISTRATION_ENDPOINT,
                                                    I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, DEVICE_AUTHORIZATION_ENDPOINT,
                                                    I_OPT_DEVICE_AUTH_CODE, DEVICE_AUTH_CODE,
                                                    I_OPT_DEVICE_AUTH_USER_CODE, DEVICE_AUTH_USER_CODE,
                                                    I_OPT_DEVICE_AUTH_VERIFICATION_URI, DEVICE_AUTH_VERIFICATION_URI,
                                                    I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE, DEVICE_AUTH_VERIFICATION_URI_COMPLETE,
                                                    I_OPT_DEVICE_AUTH_EXPIRES_IN, DEVICE_AUTH_EXPIRES_IN,
                                                    I_OPT_DEVICE_AUTH_INTERVAL, DEVICE_AUTH_INTERVAL,
                                                    I_OPT_END_SESSION_ENDPOINT, END_SESSION_ENDPOINT,
                                                    I_OPT_CHECK_SESSION_IRAME, CHECK_SESSION_IRAME,
                                                    I_OPT_PUSHED_AUTH_REQ_ENDPOINT, PUSHED_AUTH_REQ_ENDPOINT,
                                                    I_OPT_PUSHED_AUTH_REQ_REQUIRED, PUSHED_AUTH_REQ_REQUIRED,
                                                    I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN, PUSHED_AUTH_REQ_EXPIRES_IN,
                                                    I_OPT_PUSHED_AUTH_REQ_URI, PUSHED_AUTH_REQ_URI,
                                                    I_OPT_USE_DPOP, USE_DPOP,
                                                    I_OPT_DPOP_KID, DPOP_KID,
                                                    I_OPT_DPOP_SIGN_ALG, DPOP_SIGN_ALG,
                                                    I_OPT_DECRYPT_CODE, DECRYPT_CODE,
                                                    I_OPT_DECRYPT_REFRESH_TOKEN, DECRYPT_REFRESH_TOKEN,
                                                    I_OPT_DECRYPT_ACCESS_TOKEN, DECRYPT_ACCESS_TOKEN,
                                                    I_OPT_TLS_KEY_FILE, TLS_KEY_FILE,
                                                    I_OPT_TLS_CERT_FILE, TLS_CERT_FILE,
                                                    I_OPT_REMOTE_CERT_FLAG, REMOTE_CERT_FLAG,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwks_import_from_str(i_session.server_jwks, jwks_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_str(i_session.client_jwks, jwks_pubkey_ecdsa_str), RHN_OK);
  i_session.id_token_payload = json_pack("{ss}", "aud", "payload");
  ck_assert_int_eq(i_set_rich_authorization_request_str(&i_session, AUTH_REQUEST_TYPE_1, AUTH_REQUEST_1), I_OK);

  str_import = i_export_session_str(&i_session);
  ck_assert_ptr_ne(str_import, NULL);
  ck_assert_int_eq(i_import_session_str(&i_session_import, str_import), I_OK);
  ck_assert_int_eq(i_get_response_type(&i_session_import), I_RESPONSE_TYPE_CODE|I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_ID_TOKEN);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_SCOPE), SCOPE_LIST);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_NONCE), NONCE);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_STATE), STATE);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_REDIRECT_URI), REDIRECT_URI);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_REDIRECT_TO), REDIRECT_TO);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_CLIENT_ID), CLIENT_ID);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_CLIENT_SECRET), CLIENT_SECRET);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_USERNAME), USERNAME);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_USER_PASSWORD), USER_PASSWORD);
  ck_assert_str_eq(i_get_additional_parameter(&i_session_import, ADDITIONAL_KEY), ADDITIONAL_VALUE);
  ck_assert_str_eq(i_get_additional_response(&i_session_import, ADDITIONAL_KEY), ADDITIONAL_VALUE);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_AUTH_ENDPOINT), AUTH_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_TOKEN_ENDPOINT), TOKEN_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_OPENID_CONFIG_ENDPOINT), OPENID_CONFIG_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_USERINFO_ENDPOINT), USERINFO_ENDPOINT);
  ck_assert_int_eq(i_get_int_parameter(&i_session_import, I_OPT_RESULT), I_ERROR_UNAUTHORIZED);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_ERROR), ERROR);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_ERROR_DESCRIPTION), ERROR_DESCRIPTION);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_ERROR_URI), ERROR_URI);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_CODE), CODE);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_REFRESH_TOKEN), REFRESH_TOKEN);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_ACCESS_TOKEN), ACCESS_TOKEN);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_TOKEN_TYPE), TOKEN_TYPE);
  ck_assert_int_eq(i_get_int_parameter(&i_session_import, I_OPT_EXPIRES_IN), EXPIRES_IN);
  ck_assert_int_eq(i_get_int_parameter(&i_session_import, I_OPT_EXPIRES_AT), EXPIRES_AT);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_ID_TOKEN), ID_TOKEN);
  ck_assert_int_eq(json_equal(i_session_import.id_token_payload, i_session.id_token_payload), 1);
  ck_assert_int_eq(i_get_int_parameter(&i_session_import, I_OPT_AUTH_METHOD), I_AUTH_METHOD_GET);
  ck_assert_int_eq(i_get_int_parameter(&i_session_import, I_OPT_TOKEN_METHOD), I_TOKEN_AUTH_METHOD_SECRET_POST);
  ck_assert_int_eq(json_equal(i_session_import.server_jwks, i_session.server_jwks), 1);
  ck_assert_int_eq(i_get_int_parameter(&i_session_import, I_OPT_X5U_FLAGS), R_FLAG_IGNORE_SERVER_CERTIFICATE|R_FLAG_FOLLOW_REDIRECT);
  ck_assert_int_eq(json_equal(i_session_import.openid_config, j_config), 1);
  ck_assert_int_eq(i_get_int_parameter(&i_session_import, I_OPT_OPENID_CONFIG_STRICT), I_STRICT_NO);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_ISSUER), ISSUER);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_USERINFO), USERINFO);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_SERVER_KID), SERVER_KID);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_CLIENT_KID), CLIENT_KID);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_CLIENT_SIGN_ALG), CLIENT_SIGN_ALG);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_CLIENT_ENC_ALG), CLIENT_ENC_ALG);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_CLIENT_ENC), CLIENT_ENC);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_TOKEN_JTI), TOKEN_JTI);
  ck_assert_int_eq(i_get_int_parameter(&i_session_import, I_OPT_TOKEN_EXP), TOKEN_EXP);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_TOKEN_TARGET), TOKEN_TARGET);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_TOKEN_TARGET_TYPE_HINT), TOKEN_TARGET_TYPE_HINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_REVOCATION_ENDPOINT), REVOCATION_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_INTROSPECTION_ENDPOINT), INTROSPECTION_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_REGISTRATION_ENDPOINT), REGISTRATION_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_DEVICE_AUTHORIZATION_ENDPOINT), DEVICE_AUTHORIZATION_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_DEVICE_AUTH_CODE), DEVICE_AUTH_CODE);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_DEVICE_AUTH_USER_CODE), DEVICE_AUTH_USER_CODE);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_DEVICE_AUTH_VERIFICATION_URI), DEVICE_AUTH_VERIFICATION_URI);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE), DEVICE_AUTH_VERIFICATION_URI_COMPLETE);
  ck_assert_int_eq(i_get_int_parameter(&i_session_import, I_OPT_DEVICE_AUTH_EXPIRES_IN), DEVICE_AUTH_EXPIRES_IN);
  ck_assert_int_eq(i_get_int_parameter(&i_session_import, I_OPT_DEVICE_AUTH_INTERVAL), DEVICE_AUTH_INTERVAL);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_END_SESSION_ENDPOINT), END_SESSION_ENDPOINT);
  ck_assert_str_eq(i_get_str_parameter(&i_session_import, I_OPT_CHECK_SESSION_IRAME), CHECK_SESSION_IRAME);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_ENDPOINT), PUSHED_AUTH_REQ_ENDPOINT);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_REQUIRED), PUSHED_AUTH_REQ_REQUIRED);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN), PUSHED_AUTH_REQ_EXPIRES_IN);
  ck_assert_ptr_ne(NULL, str_rar = i_get_rich_authorization_request_str(&i_session_import, AUTH_REQUEST_TYPE_1));
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_PUSHED_AUTH_REQ_URI), PUSHED_AUTH_REQ_URI);
  ck_assert_int_eq(json_equal(i_session_import.j_userinfo, j_userinfo), 1);
  ck_assert_int_eq(i_get_int_parameter(&i_session_import, I_OPT_USE_DPOP), USE_DPOP);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_DPOP_KID), DPOP_KID);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_DPOP_SIGN_ALG), DPOP_SIGN_ALG);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_DECRYPT_CODE), DECRYPT_CODE);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_DECRYPT_REFRESH_TOKEN), DECRYPT_REFRESH_TOKEN);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_DECRYPT_ACCESS_TOKEN), DECRYPT_ACCESS_TOKEN);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TLS_KEY_FILE), TLS_KEY_FILE);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TLS_CERT_FILE), TLS_CERT_FILE);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_REMOTE_CERT_FLAG), REMOTE_CERT_FLAG);
  ck_assert_int_eq(r_jwks_size(i_session.server_jwks), 1);
  ck_assert_int_eq(r_jwks_size(i_session.client_jwks), 1);
  o_free(str_import);
  o_free(str_rar);

  json_decref(j_config);
  json_decref(j_userinfo);
  json_decref(jwks);
  i_clean_session(&i_session);
  i_clean_session(&i_session_import);
}
END_TEST

static Suite *iddawc_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Iddawc core function tests");
  tc_core = tcase_create("test_iddawc_core");
  tcase_add_test(tc_core, test_iddawc_init_session);
  tcase_add_test(tc_core, test_iddawc_set_response_type);
  tcase_add_test(tc_core, test_iddawc_set_result);
  tcase_add_test(tc_core, test_iddawc_set_str_parameter);
  tcase_add_test(tc_core, test_iddawc_set_int_parameter);
  tcase_add_test(tc_core, test_iddawc_set_additional_parameter);
  tcase_add_test(tc_core, test_iddawc_set_additional_response);
  tcase_add_test(tc_core, test_iddawc_get_str_parameter);
  tcase_add_test(tc_core, test_iddawc_get_int_parameter);
  tcase_add_test(tc_core, test_iddawc_get_response_type);
  tcase_add_test(tc_core, test_iddawc_get_result);
  tcase_add_test(tc_core, test_iddawc_get_additional_parameter);
  tcase_add_test(tc_core, test_iddawc_get_additional_response);
  tcase_add_test(tc_core, test_iddawc_rich_authorization_request);
  tcase_add_test(tc_core, test_iddawc_parameter_list);
  tcase_add_test(tc_core, test_iddawc_export_json_t);
  tcase_add_test(tc_core, test_iddawc_import_json_t);
  tcase_add_test(tc_core, test_iddawc_export_str);
  tcase_add_test(tc_core, test_iddawc_import_str);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc core tests");
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
