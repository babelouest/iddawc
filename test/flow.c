/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <rhonabwy.h>
#include <iddawc.h>

#define SCOPE_LIST "openid g_profile"
#define STATE "stateXyz1234"
#define REDIRECT_URI "https://iddawc.tld"
#define REDIRECT_ACCESS_TOKEN "https://iddawc.tld#access_token="
#define REDIRECT_CODE "https://iddawc.tld?code="
#define REDIRECT_ID_TOKEN "https://iddawc.tld#id_token=%s"
#define REDIRECT_EXTERNAL_AUTH "https://glewlwyd.tld/login.html"
#define CLIENT_ID "clientXyz1234"
#define CLIENT_SECRET "secretXyx1234"
#define AUTH_ENDPOINT "http://localhost:8080/auth"
#define TOKEN_ENDPOINT "http://localhost:8080/token"
#define USERINFO_ENDPOINT "http://localhost:8080/userinfo"
#define CODE "codeXyz1234"
#define REFRESH_TOKEN "refreshXyz1234"
#define ACCESS_TOKEN "accessXyz1234"
#define TOKEN_TYPE "typeXyz1234"
#define EXPIRES_IN 3600
#define ID_TOKEN "idTokenXyz1234"

#define USERINFO_NAME "Dave Lopper"
#define USERINFO_AUD "abcdxyz"
#define USERINFO_EMAIL "dev@iddawc.tld"

#define ISSUER "https://glewlwyd.tld/"
#define JWKS_URI "http://localhost:8080/jwks"
#define AUTH_METHOD_1 "client_secret_basic"
#define AUTH_METHOD_2 "client_secret_jwt"
#define ALG_VALUE_1 "RS512"
#define ALG_VALUE_2 "RS256"
#define SCOPE_1 "openid"
#define SCOPE_2 "g_profile"
#define RESP_TYPE_1 "code"
#define RESP_TYPE_2 "token"
#define RESP_TYPE_3 "id_token"
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

const char id_token_pattern[] =
"{\"amr\":[\"password\"],\"aud\":\"%s\",\"auth_time\":%lld"
",\"azp\":\"%s\",\"exp\":%lld,\"iat\":%lld,\"iss\":\"%s\""
",\"nonce\":\"abc1234\",\"sub\":\"wRNaPT1UBIw4Cl9eo3yOzoH"
"7vE81Phfu\"}";
#define EXPIRES_IN 3600

const char code[] = "codeXyz1234";
const char c_hash[] = "xTrH4sIDT1DIDKEmAfED1g";

const char access_token[] =  "accessXyz1234";
const char at_hash[] =  "2f8ZKzK8O7SAUkTpR29Z_w";

static char userinfo_json[] = "{"\
  "\"name\":\"" USERINFO_NAME "\","\
  "\"aud\":\"" USERINFO_AUD "\","\
  "\"email\":\"" USERINFO_EMAIL "\""\
"}";

const char openid_configuration_valid[] = "{\
  \"issuer\":\"" ISSUER "\",\
  \"authorization_endpoint\":\"" AUTH_ENDPOINT "\",\
  \"token_endpoint\":\"" TOKEN_ENDPOINT "\",\
  \"userinfo_endpoint\":\"" USERINFO_ENDPOINT "\",\
  \"jwks_uri\":\"" JWKS_URI "\",\
  \"token_endpoint_auth_methods_supported\":[\"" AUTH_METHOD_1 "\",\"" AUTH_METHOD_2 "\"],\
  \"id_token_signing_alg_values_supported\":[\"" ALG_VALUE_1 "\",\"" ALG_VALUE_2 "\"],\
  \"scopes_supported\":[\"" SCOPE_1 "\",\"" SCOPE_2 "\"],\
  \"response_types_supported\":[\"" RESP_TYPE_1 "\",\"" RESP_TYPE_2 "\",\"" RESP_TYPE_3 "\",\"" RESP_TYPE_1 " " RESP_TYPE_2 "\",\"" RESP_TYPE_2 " " RESP_TYPE_3 "\",\"" RESP_TYPE_1 " " RESP_TYPE_2" " RESP_TYPE_3 "\",\"" RESP_TYPE_4 "\",\"" RESP_TYPE_5 "\"],\
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

const char public_key[] = 
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\n"
"vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\n"
"aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\n"
"tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\n"
"e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\n"
"V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\n"
"MwIDAQAB\n"
"-----END PUBLIC KEY-----\n";

const unsigned char private_key[] =
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw\n"
"kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr\n"
"m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi\n"
"NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV\n"
"3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2\n"
"QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs\n"
"kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go\n"
"amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM\n"
"+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9\n"
"D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC\n"
"0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y\n"
"lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+\n"
"hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp\n"
"bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X\n"
"+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B\n"
"BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC\n"
"2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx\n"
"QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz\n"
"5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9\n"
"Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0\n"
"NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j\n"
"8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma\n"
"3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K\n"
"y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB\n"
"jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=\n"
"-----END RSA PRIVATE KEY-----\n";

int callback_oauth2_redirect_external_auth (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * redirect = msprintf(REDIRECT_EXTERNAL_AUTH "?redirect_uri=%s&state=%s", u_map_get(request->map_url, "redirect_uri"), u_map_get(request->map_url, "state"));
  u_map_put(response->map_header, "Location", redirect);
  response->status = 302;
  o_free(redirect);
  return U_CALLBACK_CONTINUE;
}

int callback_userinfo_valid_json (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_response = json_loads(userinfo_json, JSON_DECODE_ANY, NULL);
  ulfius_set_json_body_response(response, 200, j_response);
  json_decref(j_response);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_token_code_ok (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * result = json_pack("{sssssiss}", 
                             "access_token", ACCESS_TOKEN,
                             "token_type", "bearer",
                             "expires_in", 3600,
                             "refresh_token", REFRESH_TOKEN);
  ulfius_set_json_body_response(response, 200, result);
  json_decref(result);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_token_code_id_token_ok (const struct _u_request * request, struct _u_response * response, void * user_data) {
  jwt_t * jwt;
  jwk_t * jwk;
  char * grants = NULL, * jwt_str;
  time_t now;
  json_t * result;
  
  r_jwt_init(&jwt);
  r_jwk_init(&jwk);
  time(&now);
  r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key));
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  r_jwt_set_full_claims_json_str(jwt, grants);
  r_jwt_set_claim_str_value(jwt, "at_hash", at_hash);
  r_jwt_set_claim_str_value(jwt, "c_hash", c_hash);
  r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256);
  jwt_str = r_jwt_serialize_signed(jwt, jwk, 0);
  
  result = json_pack("{sssssissss}", 
                     "access_token", ACCESS_TOKEN,
                     "token_type", "bearer",
                     "expires_in", 3600,
                     "refresh_token", REFRESH_TOKEN,
                     "id_token", jwt_str);
  ulfius_set_json_body_response(response, 200, result);

  json_decref(result);
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  r_jwk_free(jwk);
  return U_CALLBACK_CONTINUE;
}

int callback_openid_configuration_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_response = json_loads(openid_configuration_valid, JSON_DECODE_ANY, NULL);
  ulfius_set_json_body_response(response, 200, j_response);
  json_decref(j_response);
  return U_CALLBACK_CONTINUE;
}

int callback_openid_jwks_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  jwk_t * jwk;
  jwks_t * jwks;
  json_t * j_response;
  
  r_jwk_init(&jwk);
  r_jwks_init(&jwks);
  r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (unsigned char *)public_key, o_strlen(public_key));
  r_jwks_append_jwk(jwks, jwk);
  j_response = r_jwks_export_to_json_t(jwks);
  ulfius_set_json_body_response(response, 200, j_response);
  
  r_jwk_free(jwk);
  r_jwks_free(jwks);
  json_decref(j_response);
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_iddawc_token_flow)
{
  struct _i_session i_session;
  struct _u_instance instance;
  json_t * j_userinfo = json_loads(userinfo_json, JSON_DECODE_ANY, NULL);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/auth", 0, &callback_oauth2_redirect_external_auth, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_userinfo_valid_json, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_TOKEN,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_USERINFO_ENDPOINT, USERINFO_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  
  // First step: get redirection to login page
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO), REDIRECT_EXTERNAL_AUTH "?redirect_uri=" REDIRECT_URI "&state=" STATE);
  
  // Then the user has loggined in the external application, gets redirected with a result, we parse the result
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REDIRECT_TO, REDIRECT_ACCESS_TOKEN ACCESS_TOKEN "&state=" STATE "&token_type=bearer"), I_OK);
  ck_assert_int_eq(i_parse_redirect_to(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  
  // And finally we load user info using the access token
  ck_assert_int_eq(i_load_userinfo(&i_session), I_OK);
  ck_assert_int_eq(json_equal(i_session.j_userinfo, j_userinfo), 1);
  
  json_decref(j_userinfo);
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_code_flow)
{
  struct _i_session i_session;
  struct _u_instance instance;
  json_t * j_userinfo = json_loads(userinfo_json, JSON_DECODE_ANY, NULL);
  
  // First step: get redirection to login page
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/auth", 0, &callback_oauth2_redirect_external_auth, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_userinfo_valid_json, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_code_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_USERINFO_ENDPOINT, USERINFO_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO), REDIRECT_EXTERNAL_AUTH "?redirect_uri=" REDIRECT_URI "&state=" STATE);
  
  // Then the user has loggined in the external application, gets redirected with a result, we parse the result
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REDIRECT_TO, REDIRECT_CODE CODE "&state=" STATE), I_OK);
  ck_assert_int_eq(i_parse_redirect_to(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  
  // Run the token request, get the refresh and access tokens
  ck_assert_int_eq(i_run_token_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), "bearer");
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 3600);
  
  // And finally we load user info using the access token
  ck_assert_int_eq(i_load_userinfo(&i_session), I_OK);
  ck_assert_int_eq(json_equal(i_session.j_userinfo, j_userinfo), 1);
  
  json_decref(j_userinfo);
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_oidc_token_id_token_flow)
{
  struct _i_session i_session;
  struct _u_instance instance;
  json_t * j_userinfo = json_loads(userinfo_json, JSON_DECODE_ANY, NULL);
  jwt_t * jwt;
  jwk_t * jwk;
  char * grants = NULL, * jwt_str;
  time_t now;
  char * redirect_to;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "at_hash", at_hash), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  redirect_to = msprintf(REDIRECT_ID_TOKEN "&access_token=" ACCESS_TOKEN "&state=" STATE "&token_type=bearer", jwt_str);

  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/.well-known/openid-configuration", 0, &callback_openid_configuration_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/jwks", 0, &callback_openid_jwks_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/auth", 0, &callback_oauth2_redirect_external_auth, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_userinfo_valid_json, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_ID_TOKEN,
                                                    I_OPT_OPENID_CONFIG_ENDPOINT, "http://localhost:8080/.well-known/openid-configuration",
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_load_openid_config(&i_session), I_OK);
  
  // First step: get redirection to login page
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO), REDIRECT_EXTERNAL_AUTH "?redirect_uri=" REDIRECT_URI "&state=" STATE);
  
  // Then the user has loggined in the external application, gets redirected with a result, we parse the result
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REDIRECT_TO, redirect_to), I_OK);
  ck_assert_int_eq(i_parse_redirect_to(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), NULL);
  ck_assert_int_eq(i_verify_id_token(&i_session), I_OK);
  
  // And finally we load user info using the access token
  ck_assert_int_eq(i_load_userinfo(&i_session), I_OK);
  ck_assert_int_eq(json_equal(i_session.j_userinfo, j_userinfo), 1);
  
  json_decref(j_userinfo);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  i_clean_session(&i_session);
  o_free(redirect_to);
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  r_jwk_free(jwk);
}
END_TEST

START_TEST(test_iddawc_oidc_code_flow)
{
  struct _i_session i_session;
  struct _u_instance instance;
  json_t * j_userinfo = json_loads(userinfo_json, JSON_DECODE_ANY, NULL);

  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/.well-known/openid-configuration", 0, &callback_openid_configuration_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/jwks", 0, &callback_openid_jwks_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/auth", 0, &callback_oauth2_redirect_external_auth, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_code_id_token_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_userinfo_valid_json, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_OPENID_CONFIG_ENDPOINT, "http://localhost:8080/.well-known/openid-configuration",
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_load_openid_config(&i_session), I_OK);
  
  // First step: get redirection to login page
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO), REDIRECT_EXTERNAL_AUTH "?redirect_uri=" REDIRECT_URI "&state=" STATE);
  
  // Then the user has loggined in the external application, gets redirected with a result, we parse the result
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REDIRECT_TO, REDIRECT_CODE CODE "&state=" STATE), I_OK);
  ck_assert_int_eq(i_parse_redirect_to(&i_session), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), NULL);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  
  // Run the token request, get the refresh and access tokens
  ck_assert_int_eq(i_run_token_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), "bearer");
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 3600);
  
  // And finally we load user info using the access token
  ck_assert_int_eq(i_load_userinfo(&i_session), I_OK);
  ck_assert_int_eq(json_equal(i_session.j_userinfo, j_userinfo), 1);
  
  json_decref(j_userinfo);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_oidc_token_id_token_code_flow)
{
  struct _i_session i_session;
  struct _u_instance instance;
  json_t * j_userinfo = json_loads(userinfo_json, JSON_DECODE_ANY, NULL);
  jwt_t * jwt;
  jwk_t * jwk;
  char * grants = NULL, * jwt_str;
  time_t now;
  char * redirect_to;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "at_hash", at_hash), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "c_hash", c_hash), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  redirect_to = msprintf(REDIRECT_ID_TOKEN "&access_token=" ACCESS_TOKEN "&code=" CODE "&state=" STATE "&token_type=bearer", jwt_str);

  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/.well-known/openid-configuration", 0, &callback_openid_configuration_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/jwks", 0, &callback_openid_jwks_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/auth", 0, &callback_oauth2_redirect_external_auth, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_code_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_userinfo_valid_json, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_ID_TOKEN|I_RESPONSE_TYPE_CODE,
                                                    I_OPT_OPENID_CONFIG_ENDPOINT, "http://localhost:8080/.well-known/openid-configuration",
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_load_openid_config(&i_session), I_OK);
  
  // First step: get redirection to login page
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO), REDIRECT_EXTERNAL_AUTH "?redirect_uri=" REDIRECT_URI "&state=" STATE);
  
  // Then the user has loggined in the external application, gets redirected with a result, we parse the result
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REDIRECT_TO, redirect_to), I_OK);
  ck_assert_int_eq(i_parse_redirect_to(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), NULL);
  
  // Run the token request, get the refresh and access tokens
  ck_assert_int_eq(i_run_token_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), "bearer");
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 3600);
  
  // And finally we load user info using the access token
  ck_assert_int_eq(i_load_userinfo(&i_session), I_OK);
  ck_assert_int_eq(json_equal(i_session.j_userinfo, j_userinfo), 1);
  
  json_decref(j_userinfo);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  i_clean_session(&i_session);
  o_free(redirect_to);
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  r_jwk_free(jwk);
}
END_TEST

static Suite *iddawc_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Iddawc flow function tests");
  tc_core = tcase_create("test_iddawc_flow");
  tcase_add_test(tc_core, test_iddawc_token_flow);
  tcase_add_test(tc_core, test_iddawc_code_flow);
  tcase_add_test(tc_core, test_iddawc_oidc_token_id_token_flow);
  tcase_add_test(tc_core, test_iddawc_oidc_code_flow);
  tcase_add_test(tc_core, test_iddawc_oidc_token_id_token_code_flow);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc oauth complete flow tests");
  s = iddawc_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  //y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
