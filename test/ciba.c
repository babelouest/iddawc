/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <jansson.h>
#include <check.h>
#include <yder.h>
#include <iddawc.h>
#include <rhonabwy.h>

#define CIBA_ERROR "invalid_request"
#define CIBA_ERROR_DESCRIPTION "invalid_request description"
#define CIBA_ERROR_URI "https://as.tld/#error"
#define CLIENT_ID "client"
#define CLIENT_SECRET "client_secret"
#define CLIENT_REDIRECT "https://client.tld"
#define TOKEN_ENDPOINT "http://localhost:8080/token"
#define SCOPE "scope1 scope2"
#define CIBA_ENDPOINT "http://localhost:8080/ciba"
#define CIBA_USER_CODE "CIBAUserCode"
#define CIBA_LOGIN_HINT "{\"username\":\"ciba\"}"
#define CIBA_ID_TOKEN_HINT "thisismyidtoken...dealwithit"
#define CIBA_LOGIN_HINT_KID "ciba kid"
#define CIBA_BINDING_MESSAGE "CIBABindingMessage"
#define CIBA_CLIENT_NOTIFICATION_TOKEN "CIBAClientNotificationToken123456789012345678901234567890"
#define CIBA_AUTH_REQ_ID "CIBAAuthReqId123456789012345678901234567890"
#define CIBA_CLIENT_NOTIFICATION_ENDPOINT "https://iddawc.tld/cb"
#define CIBA_AUTH_REQ_EXPIRES_IN 145
#define CIBA_AUTH_REQ_INTERVAL 4
#define REFRESH_TOKEN "refreshXyz1234"
#define ACCESS_TOKEN "accessXyz1234"
#define ERROR_AUTH_PENDING "authorization_pending"
#define ERROR_SLOW_DOWN "slow_down"
#define ERROR_EXPIRED_TOKEN "expired_token"
#define ERROR_ACCESS_DENIED "access_denied"

int callback_ciba_login_hint_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_response = json_pack("{sssisi}", "auth_req_id", CIBA_AUTH_REQ_ID, "expires_in", CIBA_AUTH_REQ_EXPIRES_IN, "interval", CIBA_AUTH_REQ_INTERVAL);
  ck_assert_str_eq(CIBA_LOGIN_HINT, u_map_get(request->map_post_body, "login_hint"));
  ulfius_set_json_body_response(response, 200, j_response);
  json_decref(j_response);
  return U_CALLBACK_CONTINUE;
}

int callback_ciba_id_token_hint_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_response = json_pack("{sssisi}", "auth_req_id", CIBA_AUTH_REQ_ID, "expires_in", CIBA_AUTH_REQ_EXPIRES_IN, "interval", CIBA_AUTH_REQ_INTERVAL);
  ck_assert_str_eq(CIBA_ID_TOKEN_HINT, u_map_get(request->map_post_body, "id_token_hint"));
  ulfius_set_json_body_response(response, 200, j_response);
  json_decref(j_response);
  return U_CALLBACK_CONTINUE;
}

int callback_ciba_login_hint_token_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  jwt_t * jwt = NULL;
  ck_assert_ptr_ne(NULL, jwt = r_jwt_quick_parse(u_map_get(request->map_post_body, "login_hint_token"), R_PARSE_NONE, 0));
  json_t * j_response = json_pack("{sssisi}", "auth_req_id", CIBA_AUTH_REQ_ID, "expires_in", CIBA_AUTH_REQ_EXPIRES_IN, "interval", CIBA_AUTH_REQ_INTERVAL);
  ulfius_set_json_body_response(response, 200, j_response);
  json_decref(j_response);
  r_jwt_free(jwt);
  return U_CALLBACK_CONTINUE;
}

int callback_ciba_token_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  ck_assert_str_eq("urn:openid:params:grant-type:ciba", u_map_get(request->map_post_body, "grant_type"));
  ck_assert_str_eq(CIBA_AUTH_REQ_ID, u_map_get(request->map_post_body, "auth_req_id"));
  json_t * result = json_pack("{sssssiss}", 
                             "access_token", ACCESS_TOKEN,
                             "token_type", "bearer",
                             "expires_in", 3600,
                             "refresh_token", REFRESH_TOKEN);
  ulfius_set_json_body_response(response, 200, result);
  json_decref(result);
  return U_CALLBACK_CONTINUE;
}

int callback_ciba_token_auth_pending (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * result = json_pack("{ss}", "error", ERROR_AUTH_PENDING);
  ulfius_set_json_body_response(response, 400, result);
  json_decref(result);
  return U_CALLBACK_CONTINUE;
}

int callback_ciba_token_slow_down (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * result = json_pack("{ss}", "error", ERROR_SLOW_DOWN);
  ulfius_set_json_body_response(response, 400, result);
  json_decref(result);
  return U_CALLBACK_CONTINUE;
}

int callback_ciba_token_expired_token (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * result = json_pack("{ss}", "error", ERROR_EXPIRED_TOKEN);
  ulfius_set_json_body_response(response, 400, result);
  json_decref(result);
  return U_CALLBACK_CONTINUE;
}

int callback_ciba_token_access_denied (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * result = json_pack("{ss}", "error", ERROR_ACCESS_DENIED);
  ulfius_set_json_body_response(response, 400, result);
  json_decref(result);
  return U_CALLBACK_CONTINUE;
}

int callback_ciba_invalid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_error = json_pack("{ssssss}", "error", CIBA_ERROR, "error_description", CIBA_ERROR_DESCRIPTION, "error_uri", CIBA_ERROR_URI);
  ulfius_set_json_body_response(response, 400, j_error);
  json_decref(j_error);
  return U_CALLBACK_CONTINUE;
}

int callback_ciba_unauthorized (const struct _u_request * request, struct _u_response * response, void * user_data) {
  response->status = 403;
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_iddawc_ciba_invalid_parameters)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/ciba", 0, &callback_ciba_invalid, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/ciba_403", 0, &callback_ciba_unauthorized, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN, CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_CIBA_LOGIN_HINT, CIBA_LOGIN_HINT,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_CIBA_LOGIN_HINT, CIBA_LOGIN_HINT,
                                                    I_OPT_CIBA_LOGIN_HINT_FORMAT, I_CIBA_LOGIN_HINT_FORMAT_JSON,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_CIBA_MODE, I_CIBA_MODE_POLL,
                                                    I_OPT_CIBA_LOGIN_HINT, CIBA_LOGIN_HINT,
                                                    I_OPT_CIBA_LOGIN_HINT_FORMAT, I_CIBA_LOGIN_HINT_FORMAT_JSON,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_CIBA_MODE, I_CIBA_MODE_POLL,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_CIBA_ENDPOINT, CIBA_ENDPOINT,
                                                    I_OPT_CIBA_LOGIN_HINT, CIBA_LOGIN_HINT,
                                                    I_OPT_CIBA_LOGIN_HINT_FORMAT, I_CIBA_LOGIN_HINT_FORMAT_JSON,
                                                    I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN, CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_ERROR_PARAM);
  ck_assert_str_eq(CIBA_ERROR, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_str_eq(CIBA_ERROR_DESCRIPTION, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_str_eq(CIBA_ERROR_URI, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_REDIRECT_URI, CLIENT_REDIRECT,
                                                    I_OPT_CIBA_MODE, I_CIBA_MODE_POLL,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_CIBA_ENDPOINT, CIBA_ENDPOINT "_403",
                                                    I_OPT_CIBA_LOGIN_HINT, CIBA_LOGIN_HINT,
                                                    I_OPT_CIBA_LOGIN_HINT_FORMAT, I_CIBA_LOGIN_HINT_FORMAT_JSON,
                                                    I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN, CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_ERROR_UNAUTHORIZED);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_ciba_login_hint_valid)
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
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_CIBA_ENDPOINT, CIBA_ENDPOINT,
                                                    I_OPT_CIBA_LOGIN_HINT, CIBA_LOGIN_HINT,
                                                    I_OPT_CIBA_MODE, I_CIBA_MODE_POLL,
                                                    I_OPT_CIBA_LOGIN_HINT_FORMAT, I_CIBA_LOGIN_HINT_FORMAT_JSON,
                                                    I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN, CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_OK);
  ck_assert_str_eq(CIBA_AUTH_REQ_ID, i_get_str_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_ID));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_EXPIRES_IN));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_INTERVAL));
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_ciba_login_hint_token_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/ciba", 0, &callback_ciba_login_hint_token_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_CLIENT_SIGN_ALG, "HS256",
                                                    I_OPT_TOKEN_JTI_GENERATE, 16,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_CIBA_ENDPOINT, CIBA_ENDPOINT,
                                                    I_OPT_TOKEN_METHOD, I_TOKEN_AUTH_METHOD_JWT_SIGN_SECRET,
                                                    I_OPT_CIBA_LOGIN_HINT, CIBA_LOGIN_HINT,
                                                    I_OPT_CIBA_MODE, I_CIBA_MODE_POLL,
                                                    I_OPT_CIBA_LOGIN_HINT_FORMAT, I_CIBA_LOGIN_HINT_FORMAT_JWT,
                                                    I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN, CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_OK);
  ck_assert_str_eq(CIBA_AUTH_REQ_ID, i_get_str_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_ID));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_EXPIRES_IN));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_INTERVAL));
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_ciba_id_token_hint_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/ciba", 0, &callback_ciba_id_token_hint_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_CIBA_ENDPOINT, CIBA_ENDPOINT,
                                                    I_OPT_CIBA_LOGIN_HINT, CIBA_ID_TOKEN_HINT,
                                                    I_OPT_CIBA_MODE, I_CIBA_MODE_POLL,
                                                    I_OPT_CIBA_LOGIN_HINT_FORMAT, I_CIBA_LOGIN_HINT_FORMAT_ID_TOKEN,
                                                    I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN, CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_OK);
  ck_assert_str_eq(CIBA_AUTH_REQ_ID, i_get_str_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_ID));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_EXPIRES_IN));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_INTERVAL));
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_ciba_token_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/ciba", 0, &callback_ciba_login_hint_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_ciba_token_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_CIBA_ENDPOINT, CIBA_ENDPOINT,
                                                    I_OPT_CIBA_LOGIN_HINT, CIBA_LOGIN_HINT,
                                                    I_OPT_CIBA_MODE, I_CIBA_MODE_POLL,
                                                    I_OPT_CIBA_LOGIN_HINT_FORMAT, I_CIBA_LOGIN_HINT_FORMAT_JSON,
                                                    I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN, CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_OK);
  ck_assert_str_eq(CIBA_AUTH_REQ_ID, i_get_str_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_ID));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_EXPIRES_IN));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_INTERVAL));

  ck_assert_int_eq(i_run_token_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), "bearer");
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 3600);

  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_ciba_token_auth_pending)
{
  struct _i_session i_session;
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/ciba", 0, &callback_ciba_login_hint_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_ciba_token_auth_pending, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_CIBA_ENDPOINT, CIBA_ENDPOINT,
                                                    I_OPT_CIBA_LOGIN_HINT, CIBA_LOGIN_HINT,
                                                    I_OPT_CIBA_MODE, I_CIBA_MODE_POLL,
                                                    I_OPT_CIBA_LOGIN_HINT_FORMAT, I_CIBA_LOGIN_HINT_FORMAT_JSON,
                                                    I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN, CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_OK);
  ck_assert_str_eq(CIBA_AUTH_REQ_ID, i_get_str_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_ID));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_EXPIRES_IN));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_INTERVAL));

  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), ERROR_AUTH_PENDING);

  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_ciba_token_slow_down)
{
  struct _i_session i_session;
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/ciba", 0, &callback_ciba_login_hint_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_ciba_token_slow_down, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_CIBA_ENDPOINT, CIBA_ENDPOINT,
                                                    I_OPT_CIBA_LOGIN_HINT, CIBA_LOGIN_HINT,
                                                    I_OPT_CIBA_MODE, I_CIBA_MODE_POLL,
                                                    I_OPT_CIBA_LOGIN_HINT_FORMAT, I_CIBA_LOGIN_HINT_FORMAT_JSON,
                                                    I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN, CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_OK);
  ck_assert_str_eq(CIBA_AUTH_REQ_ID, i_get_str_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_ID));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_EXPIRES_IN));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_INTERVAL));

  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), ERROR_SLOW_DOWN);

  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_ciba_token_expired_token)
{
  struct _i_session i_session;
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/ciba", 0, &callback_ciba_login_hint_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_ciba_token_expired_token, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_CIBA_ENDPOINT, CIBA_ENDPOINT,
                                                    I_OPT_CIBA_LOGIN_HINT, CIBA_LOGIN_HINT,
                                                    I_OPT_CIBA_MODE, I_CIBA_MODE_POLL,
                                                    I_OPT_CIBA_LOGIN_HINT_FORMAT, I_CIBA_LOGIN_HINT_FORMAT_JSON,
                                                    I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN, CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_OK);
  ck_assert_str_eq(CIBA_AUTH_REQ_ID, i_get_str_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_ID));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_EXPIRES_IN));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_INTERVAL));

  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), ERROR_EXPIRED_TOKEN);

  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_ciba_token_access_denied)
{
  struct _i_session i_session;
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/ciba", 0, &callback_ciba_login_hint_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_ciba_token_access_denied, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_CIBA_ENDPOINT, CIBA_ENDPOINT,
                                                    I_OPT_CIBA_LOGIN_HINT, CIBA_LOGIN_HINT,
                                                    I_OPT_CIBA_MODE, I_CIBA_MODE_POLL,
                                                    I_OPT_CIBA_LOGIN_HINT_FORMAT, I_CIBA_LOGIN_HINT_FORMAT_JSON,
                                                    I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN, CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_OK);
  ck_assert_str_eq(CIBA_AUTH_REQ_ID, i_get_str_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_ID));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_EXPIRES_IN));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_INTERVAL));

  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), ERROR_ACCESS_DENIED);

  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

static Suite *iddawc_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Iddawc ciba requests tests");
  tc_core = tcase_create("test_iddawc_ciba");
  tcase_add_test(tc_core, test_iddawc_ciba_invalid_parameters);
  tcase_add_test(tc_core, test_iddawc_ciba_login_hint_valid);
  tcase_add_test(tc_core, test_iddawc_ciba_login_hint_token_valid);
  tcase_add_test(tc_core, test_iddawc_ciba_id_token_hint_valid);
  tcase_add_test(tc_core, test_iddawc_ciba_token_valid);
  tcase_add_test(tc_core, test_iddawc_ciba_token_auth_pending);
  tcase_add_test(tc_core, test_iddawc_ciba_token_slow_down);
  tcase_add_test(tc_core, test_iddawc_ciba_token_expired_token);
  tcase_add_test(tc_core, test_iddawc_ciba_token_access_denied);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc Client-Initiated Backchannel Authentication Flow tests");
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
