/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <iddawc.h>

#define SCOPE_LIST "openid g_profile"
#define STATE "stateXyz1234"
#define REDIRECT_URI "https://iddawc.tld"
#define REDIRECT_ACCESS_TOKEN "https://iddawc.tld#access_token="
#define REDIRECT_CODE "https://iddawc.tld?code="
#define REDIRECT_ID_TOKEN "https://iddawc.tld#id_token=%s"
#define REDIRECT_EXTERNAL_AUTH "https://iddawc.tld/login.html"
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
  \"token_endpoint_auth_signing_alg_values_supported\":[\"" ALG_VALUE_1 "\",\"" ALG_VALUE_2 "\"],\
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

const char id_token_valid_sig_no_hash[] = 
"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbXIiOlsicGFzc3dvcmQiXSw"
"iYXVkIjoiY2xpZW50MV9pZCIsImF1dGhfdGltZSI6MTU3ODIzMTExNywiYXpwIjo"
"iY2xpZW50MV9pZCIsImV4cCI6MTU3ODIzNDcyMSwiaWF0IjoxNTc4MjMxMTIxLCJ"
"pc3MiOiJodHRwczovL2dsZXdsd3lkLnRsZCIsIm5vbmNlIjoiYWJjMTIzNCIsInN"
"1YiI6IndSTmFQVDFVQkl3NENsOWVvM3lPem9IN3ZFODFQaGZ1In0.JDaE508TDbC"
"jJLRGV2V0zHxuH3mFxmkJdV8S-jLfe7NrP9MW84i1IoCcGV-Z9dm3Jo1u4TkBHcx"
"kOd1b7VdhHy1SxNdEmZ0As8NHUL4K6sH1Dxlj4JQEDhJTkbyvofsopHOB3WVML3V"
"Og-qc5vk3Q4i0vJlSZUa4KOseUf-uzAlkjIVsb09zdD75_OopKU5nSHepvopx4Tw"
"3QKOPaWfd875KKU5f-VrusQ02O5mn2YEn0ile7fo1yf6_7VXRQG5BHM1fTW97kvY"
"3E4JL3kZVnTsqFqgHW3JrB-33qxSIVsvW52nT4faiLxwkGeZIqMaObxHSp6Us_5t"
"CPq-f2pyq5w";
const char id_token_valid_sig_c_hash[] = 
"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbXIiOlsicGFzc3dvcmQiXSw"
"iY19oYXNoIjoieFRySDRzSURUMURJREtFbUFmRUQxZyIsImF1ZCI6ImNsaWVudDF"
"faWQiLCJhdXRoX3RpbWUiOjE1NzgyMzExMTcsImF6cCI6ImNsaWVudDFfaWQiLCJ"
"leHAiOjE1NzgyMzQ3MjEsImlhdCI6MTU3ODIzMTEyMSwiaXNzIjoiaHR0cHM6Ly9"
"nbGV3bHd5ZC50bGQiLCJub25jZSI6ImFiYzEyMzQiLCJzdWIiOiJ3Uk5hUFQxVUJ"
"JdzRDbDllbzN5T3pvSDd2RTgxUGhmdSJ9.jyp-YusI9IwsrlPgOgsspD5i3A7Nqc"
"MgFgeJ2kxQM6FRb5xvA6MZ5ayc6yOplYKCm0PD9KJRMEOWKx_tUKEt7MQIVZ-q95"
"AYQ3cNxjHdEzOY3MVMkPO8oj0OYJYpcTXRWgiqsnoFSqWLSXyZWmondW5PwvJNl8"
"P6eSsFswXe8a_t2LBz0TJDy34l9rCWwAbvLIV48D0wqkR_n4AiovmFwjd0Vk4dqv"
"5fUEAfd9Th8MaZfcKG4cwq962Msyp6rXXrAHKLbk-MfhUaqXkahHmJtIE904EDnl"
"cWVL1IcnNgwjEeDK9_aaxI_6PlnvzfPYDY0zcMt0sB8Lu4Yt7HF2GN0Q";
const char id_token_valid_sig_at_hash[] = 
"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbXIiOlsicGFzc3dvcmQiXSw"
"iYXRfaGFzaCI6IjJmOFpLeks4TzdTQVVrVHBSMjlaX3ciLCJhdWQiOiJjbGllbnQ"
"xX2lkIiwiYXV0aF90aW1lIjoxNTc4MjMxMTE3LCJhenAiOiJjbGllbnQxX2lkIiw"
"iZXhwIjoxNTc4MjM0NzIxLCJpYXQiOjE1NzgyMzExMjEsImlzcyI6Imh0dHBzOi8"
"vZ2xld2x3eWQudGxkIiwibm9uY2UiOiJhYmMxMjM0Iiwic3ViIjoid1JOYVBUMVV"
"CSXc0Q2w5ZW8zeU96b0g3dkU4MVBoZnUifQ.cgf3Y5hOSlBz4IzPUlt_Z5I2Sbix"
"uvwcKOqN-EykgZlof_8Jyr6ZctTciiqx6zP785pSjslnqvTQR7W_D22g-01RUUsT"
"K5vunXbP0Z2Pe5HX_q2uUJ2chw91DAUzwZRcyM3HPI39_PdmyttpcZIpPLi7YEqW"
"IsaORdWUrghy8B_6ZJ7FhhJmAHyxu28xCVN3dsVXG5SIam2kpo84qVSb23ZaYtjj"
"P8V1kMZEIJpo_IGCmFZalzi2OfPnRctFMM7rUGWlu1i6d5d3vqdZf9oi1mNQKwtZ"
"o3c9v3CJyhc6V3S2-2BT6GIp10zFWr-hB9a95D4rKA_sp2suvRY7nw1aAA";
const char id_token_valid_sig_c_hash_at_hash[] = 
"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbXIiOlsicGFzc3dvcmQiXSw"
"iY19oYXNoIjoieFRySDRzSURUMURJREtFbUFmRUQxZyIsImF0X2hhc2giOiIyZjh"
"aS3pLOE83U0FVa1RwUjI5Wl93IiwiYXVkIjoiY2xpZW50MV9pZCIsImF1dGhfdGl"
"tZSI6MTU3ODIzMTExNywiYXpwIjoiY2xpZW50MV9pZCIsImV4cCI6MTU3ODIzNDc"
"yMSwiaWF0IjoxNTc4MjMxMTIxLCJpc3MiOiJodHRwczovL2dsZXdsd3lkLnRsZCI"
"sIm5vbmNlIjoiYWJjMTIzNCIsInN1YiI6IndSTmFQVDFVQkl3NENsOWVvM3lPem9"
"IN3ZFODFQaGZ1In0.AO-81_CMVPGh7NidjKFqacXpIAc22P6lWQZ3MrbBllIvRFa"
"VJ_WQVRCkfS_RDTI6LaZ8ZanJ1ZbZmzR1WRU140Guuj8MNfK4BemqXgC0qsMQ6ib"
"YNuM1nAwi35WOXT9AtAWUXJTH1f-7gAZErU-CmJwlctd7O5AhNpqW3ktdwq-GqE0"
"AjXSVNpFd6jTFVGbyW0Z-qyglbDLtbTZuhry7eLXmZyOMcl6dDR8Ux29JriuSDO4"
"D2VlSTQJmadPhm2_Pwp6ViLLd4JfmYHYzXjfI1xoaw3TV6hasLVf8Q8uAI9UWVYL"
"6cUjP73Mfy8K89jnbZRjFAX25KzWhXRQCIKk42A";

int callback_oauth2_redirect_external_auth (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * redirect = msprintf(REDIRECT_EXTERNAL_AUTH "?redirect_uri=%s&state=%s", u_map_get(request->map_url, "redirect_url"), u_map_get(request->map_url, "state"));
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
  
  r_init_jwk(&jwk);
  r_init_jwks(&jwks);
  r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (unsigned char *)public_key, o_strlen(public_key));
  r_jwks_append_jwk(jwks, jwk);
  j_response = r_jwks_export_to_json_t(jwks);
  ulfius_set_json_body_response(response, 200, j_response);
  
  r_free_jwk(jwk);
  r_free_jwks(jwks);
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
  ck_assert_ptr_eq(i_get_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  
  // First step: get redirection to login page
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_ptr_eq(i_get_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_REDIRECT_TO), REDIRECT_EXTERNAL_AUTH "?redirect_uri=" REDIRECT_URI "&state=" STATE);
  
  // Then the user has loggined in the external application, gets redirected with a result, we parse the result
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_REDIRECT_TO, REDIRECT_ACCESS_TOKEN ACCESS_TOKEN "&state=" STATE "&token_type=bearer"), I_OK);
  ck_assert_int_eq(i_parse_redirect_to(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  
  // And finally we load user info using the access token
  ck_assert_int_eq(i_load_userinfo(&i_session), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_USERINFO), userinfo_json);
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
  ck_assert_ptr_eq(i_get_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_ptr_eq(i_get_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_REDIRECT_TO), REDIRECT_EXTERNAL_AUTH "?redirect_uri=" REDIRECT_URI "&state=" STATE);
  
  // Then the user has loggined in the external application, gets redirected with a result, we parse the result
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_REDIRECT_TO, REDIRECT_CODE CODE "&state=" STATE), I_OK);
  ck_assert_int_eq(i_parse_redirect_to(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_parameter(&i_session, I_OPT_CODE), NULL);
  
  // Run the token request, get the refresh and access tokens
  ck_assert_int_eq(i_run_token_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_ne(i_get_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_TOKEN_TYPE), "bearer");
  ck_assert_int_eq(i_get_flag_parameter(&i_session, I_OPT_EXPIRES_IN), 3600);
  
  // And finally we load user info using the access token
  ck_assert_int_eq(i_load_userinfo(&i_session), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_USERINFO), userinfo_json);
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
  char * redirect_to = msprintf(REDIRECT_ID_TOKEN "&access_token=" ACCESS_TOKEN "&state=" STATE "&token_type=bearer", id_token_valid_sig_at_hash);

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
  ck_assert_ptr_eq(i_get_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_REDIRECT_TO), REDIRECT_EXTERNAL_AUTH "?redirect_uri=" REDIRECT_URI "&state=" STATE);
  
  // Then the user has loggined in the external application, gets redirected with a result, we parse the result
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_REDIRECT_TO, redirect_to), I_OK);
  ck_assert_int_eq(i_parse_redirect_to(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_ne(i_get_parameter(&i_session, I_OPT_ID_TOKEN), NULL);
  ck_assert_int_eq(i_verify_id_token(&i_session, I_HAS_ACCESS_TOKEN), I_OK);
  
  // And finally we load user info using the access token
  ck_assert_int_eq(i_load_userinfo(&i_session), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_USERINFO), userinfo_json);
  
  json_decref(j_userinfo);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  i_clean_session(&i_session);
  o_free(redirect_to);
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
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc oauth complete flow tests");
  s = iddawc_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
