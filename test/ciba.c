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
#define CLIENT_SECRET_ERROR "client_secret error"
#define CLIENT_REDIRECT "https://client.tld"
#define TOKEN_ENDPOINT "http://localhost:8080/token"
#define SCOPE "scope1 scope2"
#define CIBA_ENDPOINT "http://localhost:8080/ciba"
#define CIBA_USER_CODE "CIBAUserCode"
#define CIBA_LOGIN_HINT "{\"username\":\"ciba\"}"
#define CIBA_ID_TOKEN_HINT "thisismyidtoken...dealwithit"
#define CIBA_LOGIN_HINT_KID "ciba kid"
#define CIBA_BINDING_MESSAGE "CIBABindingMessage"
#define CIBA_REQUESTED_EXPIRY 99
#define CIBA_REQUESTED_EXPIRY_str "99"
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

const char jwk_privkey_str[] = "{\"kty\":\"RSA\",\"n\":\"ANgV1GxZbGBMIqqX5QsNrQQnPLk8UpkqH_60EuaHsI8YnUkPmPVXJ_4z_ziqZizvvjp_RhhXX2DnHEQuYwI-SZaBlK1VJiiWH9EXrUeazcpEryFUR0I5iBROcgRJfHSvRvC7D83-xg9xC-NGVvIQ2llduYzmaK8rfuiHWlGqow3O2m5os9NTortdQf7BeTniStDokFvZy-I4i24UFkemoNPWZ9MCN0WTea8n_TQmq9sVHGQtLIFqfblLxbSz_7m4g7_o3WfqlwXkVmCIu1wdzAjZV5BspBGrL0ed5Whpk9-bX69nUDvpcMAaPhuRwZ43e9koVRbVwXCNkne98VAs0_U\",\"e\":\"AQAB\",\"d\":\"AKOVsyDreb5VJRFcuIrrqYWxZqkc37MQTvR1wrE_HAzYp4n-AuAJQT-Sga6WYY-3V53VaG1ZB93GWIHNVCsImJEWPEYUZjTnoeKbOBUzPoPYB3UF5oReJYSp9msEbvGvF9d65fYe4DYkcMl4IK5Uz9hDugrPC4VBOmwyu8-DjLkP8OH-N2-KhJvX_kLKgivfzD3KOp6wryLnKuZYn8N4E6rCiNSfKMgoM60bSHRNi0QHYB2jwqMU5T5EzdpD3Tu_ow6a-sXrW6SG1dtbuStck9hFcQ-QtRCeWoM5pFN8cKOsWBZd1unq-X3gMlCjdXUBUW7BYP44lpYsg1v9l_Ww64E\",\"p\":\"ANmlFUVM-836aC-wK-DekE3s3gl7GZ-9Qca8iKnaIeMszgyaLYkkbYNPpjjsiQHc37IG3axCaywK40PZqODzovL5PnUpwfNrnlMaI042rNaf8q1L4kvaBTkbO9Wbj0sTLMPt1frLQKBRsNDsYamRcL1SwvTC4aI7cgZBrNIBdPiR\",\"q\":\"AP4qYxRNGaI3aeZh5hgKPSGW82X8Ai2MzIKjzSDYmKGcD9HPRV0dAUmDCvqyjwCD6tL9iMtZKPz7VK66-KvV1n91WLMDtRzWs_eFFyDY7BYw47o6IQoZ2RxBT3-7WLhlFflaEner8k23zpGOjZbyzt0SIWRAYR0zlb7LrS_X4fcl\",\"qi\":\"fnlvhYXAn6V0X6gmlwooZUWo9bR7ObChNhrUzMVDOReUVOrzOhlzGhBW1TEFBBr8k44ZWBCTeVEQh--LFHwVvCgEjDBxfjUPUMkeyKZzLhpIUB_cFBAgI7Fyy0yuPpY0mS1PfMt5Y4b6g_JvdBWZZ8VhTcCVG7qDqoH_IJMXPNg\",\"dp\":\"EAsiQUSGf02JJpLG-UGOw5_FUk-XuPW7honZTSP-QX_JBJbM6oIb7IUPjLyq8M82Uio9ZvhSbCG1VQgTcdmj1mNXHk3gtS_msNuJZLeVEBEkU2_3k33TyrzeMUXRT0hvkVXT4zPeZLMA5LW4EUbeV6ZlJqPC_DGDm0B2G9jtpXE\",\"dq\":\"AMTictPUEcpOILO9HG985vPxKeTTfaBpVDbSymDqR_nQmZSOeg3yHQAkCco_rXTZu3rruR7El3K5AlVEMsNxp3IepbIuagrH6qsPpuXkA6YBAzdMNjHL6hnwIbQxnT1h2M7KzklzogRAIT0x706CEmq_06wEDvZ-8j3VKvhHxBwd\",\"kid\":\"1\"}";
const char jwk_pubkey_str[] = "{\"kty\":\"RSA\",\"n\":\"ANgV1GxZbGBMIqqX5QsNrQQnPLk8UpkqH_60EuaHsI8YnUkPmPVXJ_4z_ziqZizvvjp_RhhXX2DnHEQuYwI-SZaBlK1VJiiWH9EXrUeazcpEryFUR0I5iBROcgRJfHSvRvC7D83-xg9xC-NGVvIQ2llduYzmaK8rfuiHWlGqow3O2m5os9NTortdQf7BeTniStDokFvZy-I4i24UFkemoNPWZ9MCN0WTea8n_TQmq9sVHGQtLIFqfblLxbSz_7m4g7_o3WfqlwXkVmCIu1wdzAjZV5BspBGrL0ed5Whpk9-bX69nUDvpcMAaPhuRwZ43e9koVRbVwXCNkne98VAs0_U\",\"e\":\"AQAB\",\"kid\":\"1\"}";

const char jwk_pubkey_str_2[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                   "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                   "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                   ",\"e\":\"AQAB\",\"alg\":\"RSA1_5\",\"kid\":\"2\"}";
const char jwk_privkey_str_2[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
                                    "XjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHz"\
                                    "u6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKg"\
                                    "w\",\"e\":\"AQAB\",\"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2v"\
                                    "v7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk"\
                                    "5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoA"\
                                    "C8Q\",\"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7"\
                                    "XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3v"\
                                    "obLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelx"\
                                    "k\",\"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA7"\
                                    "7Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA"\
                                    "6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cg"\
                                    "k\",\"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_m"\
                                    "HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RSA1_5\",\"kid\":\"2\"}";

int callback_ciba_login_hint_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_response = json_pack("{sssisi}", "auth_req_id", CIBA_AUTH_REQ_ID, "expires_in", CIBA_AUTH_REQ_EXPIRES_IN, "interval", CIBA_AUTH_REQ_INTERVAL);
  ck_assert_str_eq(CIBA_LOGIN_HINT, u_map_get(request->map_post_body, "login_hint"));
  ck_assert_str_eq(CIBA_REQUESTED_EXPIRY_str, u_map_get(request->map_post_body, "requested_expiry"));
  ck_assert_str_eq(CIBA_BINDING_MESSAGE, u_map_get(request->map_post_body, "binding_message"));
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

int callback_ciba_jwt_auth_code_ok (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_response = json_pack("{sssisi}", "auth_req_id", CIBA_AUTH_REQ_ID, "expires_in", CIBA_AUTH_REQ_EXPIRES_IN, "interval", CIBA_AUTH_REQ_INTERVAL);
  
  if (0 == o_strcmp(u_map_get(request->map_post_body, "client_assertion_type"), "urn:ietf:params:oauth:client-assertion-type:jwt-bearer") && o_strlen(u_map_get(request->map_post_body, "client_assertion"))) {
    jwt_t * jwt;
    jwk_t * jwk;
    r_jwt_init(&jwt);
    r_jwk_init(&jwk);
    r_jwt_parse(jwt, u_map_get(request->map_post_body, "client_assertion"), 0);
    if (r_jwt_get_sign_alg(jwt) == R_JWA_ALG_HS256) {
      r_jwk_import_from_symmetric_key(jwk, (const unsigned char *)CLIENT_SECRET, o_strlen(CLIENT_SECRET));
      if (r_jwt_verify_signature(jwt, jwk, 0) == RHN_OK) {
        ck_assert_str_eq(CIBA_LOGIN_HINT, u_map_get(request->map_post_body, "login_hint"));
        ulfius_set_json_body_response(response, 200, j_response);
      } else {
        json_t * error = json_pack("{ssssss}", 
                                   "error", "invalid_client",
                                   "error_description", "invalid_client description",
                                   "error_uri", "invalid_client uri");
        ulfius_set_json_body_response(response, 400, error);
        json_decref(error);
      }
    } else {
      r_jwk_import_from_json_str(jwk, jwk_pubkey_str);
      if (r_jwt_verify_signature(jwt, jwk, 0) == RHN_OK) {
        ck_assert_str_eq(CIBA_LOGIN_HINT, u_map_get(request->map_post_body, "login_hint"));
        ulfius_set_json_body_response(response, 200, j_response);
      } else {
        json_t * error = json_pack("{ssssss}", 
                                   "error", "invalid_client",
                                   "error_description", "invalid_client description",
                                   "error_uri", "invalid_client uri");
        ulfius_set_json_body_response(response, 400, error);
        json_decref(error);
      }
    }
    r_jwt_free(jwt);
    r_jwk_free(jwk);
  } else {
    json_t * error = json_pack("{ssssss}", 
                               "error", "invalid_client",
                               "error_description", "invalid_client description",
                               "error_uri", "invalid_client uri");
    ulfius_set_json_body_response(response, 400, error);
    json_decref(error);
  }
  json_decref(j_response);
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
                                                    I_OPT_CIBA_BINDING_MESSAGE, CIBA_BINDING_MESSAGE,
                                                    I_OPT_CIBA_REQUESTED_EXPIRY, CIBA_REQUESTED_EXPIRY,
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
                                                    I_OPT_CIBA_BINDING_MESSAGE, CIBA_BINDING_MESSAGE,
                                                    I_OPT_CIBA_REQUESTED_EXPIRY, CIBA_REQUESTED_EXPIRY,
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
                                                    I_OPT_CIBA_BINDING_MESSAGE, CIBA_BINDING_MESSAGE,
                                                    I_OPT_CIBA_REQUESTED_EXPIRY, CIBA_REQUESTED_EXPIRY,
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

START_TEST(test_iddawc_ciba_jwt_auth_secret_ok)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/ciba", 0, &callback_ciba_jwt_auth_code_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_TOKEN_METHOD, I_TOKEN_AUTH_METHOD_JWT_SIGN_SECRET,
                                                    I_OPT_TOKEN_JTI_GENERATE, 32,
                                                    I_OPT_CLIENT_SIGN_ALG, "HS256",
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_CIBA_ENDPOINT, CIBA_ENDPOINT,
                                                    I_OPT_CIBA_MODE, I_CIBA_MODE_POLL,
                                                    I_OPT_CIBA_LOGIN_HINT, CIBA_LOGIN_HINT,
                                                    I_OPT_CIBA_LOGIN_HINT_FORMAT, I_CIBA_LOGIN_HINT_FORMAT_JSON,
                                                    I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN, CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                    I_OPT_CIBA_BINDING_MESSAGE, CIBA_BINDING_MESSAGE,
                                                    I_OPT_CIBA_REQUESTED_EXPIRY, CIBA_REQUESTED_EXPIRY,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_OK);
  ck_assert_str_eq(CIBA_AUTH_REQ_ID, i_get_str_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_ID));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_EXPIRES_IN));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_INTERVAL));
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SECRET, CLIENT_SECRET_ERROR), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_ERROR_PARAM);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_ciba_jwt_auth_secret_signing_alg_ok)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/ciba", 0, &callback_ciba_jwt_auth_code_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_TOKEN_METHOD, I_TOKEN_AUTH_METHOD_JWT_SIGN_SECRET,
                                                    I_OPT_TOKEN_JTI_GENERATE, 32,
                                                    I_OPT_TOKEN_ENDPOINT_SIGNING_ALG, "HS256",
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_CIBA_ENDPOINT, CIBA_ENDPOINT,
                                                    I_OPT_CIBA_MODE, I_CIBA_MODE_POLL,
                                                    I_OPT_CIBA_LOGIN_HINT, CIBA_LOGIN_HINT,
                                                    I_OPT_CIBA_LOGIN_HINT_FORMAT, I_CIBA_LOGIN_HINT_FORMAT_JSON,
                                                    I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN, CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                    I_OPT_CIBA_BINDING_MESSAGE, CIBA_BINDING_MESSAGE,
                                                    I_OPT_CIBA_REQUESTED_EXPIRY, CIBA_REQUESTED_EXPIRY,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_OK);
  ck_assert_str_eq(CIBA_AUTH_REQ_ID, i_get_str_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_ID));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_EXPIRES_IN));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_INTERVAL));
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SECRET, CLIENT_SECRET_ERROR), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_ERROR_PARAM);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_ciba_jwt_auth_privkey_ok)
{
  struct _i_session i_session;
  struct _u_instance instance;
  jwk_t * jwk;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/ciba", 0, &callback_ciba_jwt_auth_code_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_TOKEN_METHOD, I_TOKEN_AUTH_METHOD_JWT_SIGN_PRIVKEY,
                                                    I_OPT_TOKEN_JTI_GENERATE, 32,
                                                    I_OPT_CLIENT_SIGN_ALG, "RS256",
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_CIBA_ENDPOINT, CIBA_ENDPOINT,
                                                    I_OPT_CIBA_MODE, I_CIBA_MODE_POLL,
                                                    I_OPT_CIBA_LOGIN_HINT, CIBA_LOGIN_HINT,
                                                    I_OPT_CIBA_LOGIN_HINT_FORMAT, I_CIBA_LOGIN_HINT_FORMAT_JSON,
                                                    I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN, CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                    I_OPT_CIBA_BINDING_MESSAGE, CIBA_BINDING_MESSAGE,
                                                    I_OPT_CIBA_REQUESTED_EXPIRY, CIBA_REQUESTED_EXPIRY,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_OK);
  ck_assert_str_eq(CIBA_AUTH_REQ_ID, i_get_str_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_ID));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_EXPIRES_IN));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_INTERVAL));
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str_2), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_KID, "2"), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_ERROR_PARAM);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_ciba_jwt_auth_privkey_signing_alg_ok)
{
  struct _i_session i_session;
  struct _u_instance instance;
  jwk_t * jwk;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/ciba", 0, &callback_ciba_jwt_auth_code_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_TOKEN_METHOD, I_TOKEN_AUTH_METHOD_JWT_SIGN_PRIVKEY,
                                                    I_OPT_TOKEN_JTI_GENERATE, 32,
                                                    I_OPT_TOKEN_ENDPOINT_SIGNING_ALG, "RS256",
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_CIBA_ENDPOINT, CIBA_ENDPOINT,
                                                    I_OPT_CIBA_MODE, I_CIBA_MODE_POLL,
                                                    I_OPT_CIBA_LOGIN_HINT, CIBA_LOGIN_HINT,
                                                    I_OPT_CIBA_LOGIN_HINT_FORMAT, I_CIBA_LOGIN_HINT_FORMAT_JSON,
                                                    I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN, CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                    I_OPT_CIBA_BINDING_MESSAGE, CIBA_BINDING_MESSAGE,
                                                    I_OPT_CIBA_REQUESTED_EXPIRY, CIBA_REQUESTED_EXPIRY,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_OK);
  ck_assert_str_eq(CIBA_AUTH_REQ_ID, i_get_str_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_ID));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_EXPIRES_IN));
  ck_assert_int_ne(0, i_get_int_parameter(&i_session, I_OPT_CIBA_AUTH_REQ_INTERVAL));
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str_2), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_KID, "2"), I_OK);
  ck_assert_int_eq(i_run_ciba_request(&i_session), I_ERROR_PARAM);
  
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
                                                    I_OPT_CIBA_BINDING_MESSAGE, CIBA_BINDING_MESSAGE,
                                                    I_OPT_CIBA_REQUESTED_EXPIRY, CIBA_REQUESTED_EXPIRY,
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
                                                    I_OPT_CIBA_BINDING_MESSAGE, CIBA_BINDING_MESSAGE,
                                                    I_OPT_CIBA_REQUESTED_EXPIRY, CIBA_REQUESTED_EXPIRY,
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
                                                    I_OPT_CIBA_BINDING_MESSAGE, CIBA_BINDING_MESSAGE,
                                                    I_OPT_CIBA_REQUESTED_EXPIRY, CIBA_REQUESTED_EXPIRY,
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
                                                    I_OPT_CIBA_BINDING_MESSAGE, CIBA_BINDING_MESSAGE,
                                                    I_OPT_CIBA_REQUESTED_EXPIRY, CIBA_REQUESTED_EXPIRY,
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
                                                    I_OPT_CIBA_BINDING_MESSAGE, CIBA_BINDING_MESSAGE,
                                                    I_OPT_CIBA_REQUESTED_EXPIRY, CIBA_REQUESTED_EXPIRY,
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
  tcase_add_test(tc_core, test_iddawc_ciba_jwt_auth_secret_ok);
  tcase_add_test(tc_core, test_iddawc_ciba_jwt_auth_secret_signing_alg_ok);
  tcase_add_test(tc_core, test_iddawc_ciba_jwt_auth_privkey_ok);
  tcase_add_test(tc_core, test_iddawc_ciba_jwt_auth_privkey_signing_alg_ok);
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
