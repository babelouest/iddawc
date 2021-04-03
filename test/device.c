/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <jansson.h>
#include <check.h>
#include <yder.h>
#include <iddawc.h>

#define DEVICE_ERROR "invalid_request"
#define DEVICE_ERROR_DESCRIPTION "invalid_request description"
#define DEVICE_ERROR_URI "https://as.tld/#error"
#define CLIENT_ID "client"
#define CLIENT_SECRET "client_secret"
#define DEVICE_AUTHORIZATION_ENDPOINT "http://localhost:8080/device"
#define TOKEN_ENDPOINT "http://localhost:8080/token"
#define SCOPE "scope1 scope2"
#define DEVICE_AUTH_CODE "deviceCode1234"
#define DEVICE_AUTH_USER_CODE "deviceUserCode1234"
#define DEVICE_AUTH_VERIFICATION_URI "https://isp.tld/deviceUserAuth"
#define DEVICE_AUTH_VERIFICATION_URI_COMPLETE "https://isp.tld/deviceUserAuth?code=deviceUserCode1234"
#define DEVICE_AUTH_EXPIRES_IN 90
#define DEVICE_AUTH_INTERVAL 5
#define ACCESS_TOKEN "2YotnFZFEjr1zCsicMWpAA"
#define REFRESH_TOKEN "tGzv3JOkF0XG5Qx2TlKWIA"
#define EXPIRES_IN 3600
#define TOKEN_TYPE "bearer"
#define CLAIM1 "claim1"
#define CLAIM2 "claim2"
#define CLAIM1_VALUE "248289761001"
#define CLAIM1_CONTENT "{\"value\":\""CLAIM1_VALUE"\"}"
#define RESOURCE_INDICATOR "https://resource.iddawc.tld/"

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

int callback_device_token_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * result = json_pack("{sssssiss}", 
                             "access_token", ACCESS_TOKEN,
                             "token_type", TOKEN_TYPE,
                             "expires_in", EXPIRES_IN,
                             "refresh_token", REFRESH_TOKEN);
  ulfius_set_json_body_response(response, 200, result);
  json_decref(result);
  return U_CALLBACK_CONTINUE;
}

int callback_device_token_encrypted_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  jwe_t * jwe_at, * jwe_rt;
  jwk_t * jwk;
  char * at_t, * rt_t;
  ck_assert_int_eq(r_jwe_init(&jwe_at), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_rt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_str), RHN_OK);
  
  ck_assert_int_eq(r_jwe_add_keys(jwe_at, NULL, jwk), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe_at, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe_at, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe_at, (const unsigned char *)ACCESS_TOKEN, o_strlen(ACCESS_TOKEN)), RHN_OK);
  ck_assert_ptr_ne(NULL, at_t = r_jwe_serialize(jwe_at, NULL, 0));
  
  ck_assert_int_eq(r_jwe_add_keys(jwe_rt, NULL, jwk), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe_rt, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe_rt, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe_rt, (const unsigned char *)REFRESH_TOKEN, o_strlen(REFRESH_TOKEN)), RHN_OK);
  ck_assert_ptr_ne(NULL, rt_t = r_jwe_serialize(jwe_rt, NULL, 0));
  
  json_t * result = json_pack("{sssssiss}", 
                             "access_token", at_t,
                             "token_type", "bearer",
                             "expires_in", 3600,
                             "refresh_token", rt_t);
  ulfius_set_json_body_response(response, 200, result);
  json_decref(result);
  o_free(at_t);
  o_free(rt_t);
  r_jwk_free(jwk);
  r_jwe_free(jwe_at);
  r_jwe_free(jwe_rt);
  return U_CALLBACK_CONTINUE;
}

int callback_device_token_invalid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_error = json_pack("{ssssss}", "error", DEVICE_ERROR, "error_description", DEVICE_ERROR_DESCRIPTION, "error_uri", DEVICE_ERROR_URI);
  ulfius_set_json_body_response(response, 400, j_error);
  json_decref(j_error);
  return U_CALLBACK_CONTINUE;
}

int callback_device_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_error = json_pack("{ss ss ss ss si si}", 
                               "device_code", DEVICE_AUTH_CODE, 
                               "user_code", DEVICE_AUTH_USER_CODE, 
                               "verification_uri", DEVICE_AUTH_VERIFICATION_URI,
                               "verification_uri_complete", DEVICE_AUTH_VERIFICATION_URI_COMPLETE,
                               "expires_in", DEVICE_AUTH_EXPIRES_IN,
                               "interval", DEVICE_AUTH_INTERVAL);
  ulfius_set_json_body_response(response, 200, j_error);
  json_decref(j_error);
  return U_CALLBACK_CONTINUE;
}

int callback_device_claims_resource_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_error = json_pack("{ss ss ss ss si si}", 
                               "device_code", DEVICE_AUTH_CODE, 
                               "user_code", DEVICE_AUTH_USER_CODE, 
                               "verification_uri", DEVICE_AUTH_VERIFICATION_URI,
                               "verification_uri_complete", DEVICE_AUTH_VERIFICATION_URI_COMPLETE,
                               "expires_in", DEVICE_AUTH_EXPIRES_IN,
                               "interval", DEVICE_AUTH_INTERVAL), * j_claims = json_pack("{s{so}s{s{so}}}", "userinfo", CLAIM1, json_loads(CLAIM1_CONTENT, JSON_DECODE_ANY, NULL), "id_token", CLAIM2, "essential", json_false());
  char * str_claims = json_dumps(j_claims, JSON_COMPACT);
  ck_assert_str_eq(u_map_get(request->map_post_body, "claims"), str_claims);
  ck_assert_str_eq(u_map_get(request->map_post_body, "resource"), RESOURCE_INDICATOR);
  ulfius_set_json_body_response(response, 200, j_error);
  json_decref(j_error);
  json_decref(j_claims);
  o_free(str_claims);
  return U_CALLBACK_CONTINUE;
}

int callback_device_invalid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_error = json_pack("{ssssss}", "error", DEVICE_ERROR, "error_description", DEVICE_ERROR_DESCRIPTION, "error_uri", DEVICE_ERROR_URI);
  ulfius_set_json_body_response(response, 400, j_error);
  json_decref(j_error);
  return U_CALLBACK_CONTINUE;
}

int callback_device_unauthorized (const struct _u_request * request, struct _u_response * response, void * user_data) {
  response->status = 403;
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_iddawc_device_auth_invalid_parameters)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/device", 0, &callback_device_invalid, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/device_403", 0, &callback_device_unauthorized, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, DEVICE_AUTHORIZATION_ENDPOINT,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_str_eq(DEVICE_ERROR, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_str_eq(DEVICE_ERROR_DESCRIPTION, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_str_eq(DEVICE_ERROR_URI, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, DEVICE_AUTHORIZATION_ENDPOINT "_403",
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_ERROR_UNAUTHORIZED);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_device_auth_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/device", 0, &callback_device_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, DEVICE_AUTHORIZATION_ENDPOINT,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_OK);
  ck_assert_str_eq(DEVICE_AUTH_CODE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_CODE));
  ck_assert_str_eq(DEVICE_AUTH_USER_CODE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_USER_CODE));
  ck_assert_str_eq(DEVICE_AUTH_VERIFICATION_URI, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI));
  ck_assert_str_eq(DEVICE_AUTH_VERIFICATION_URI_COMPLETE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE));
  ck_assert_int_eq(DEVICE_AUTH_EXPIRES_IN, i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_EXPIRES_IN));
  ck_assert_int_eq(DEVICE_AUTH_INTERVAL, i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_INTERVAL));
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_device_claims_resource_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/device", 0, &callback_device_claims_resource_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, DEVICE_AUTHORIZATION_ENDPOINT,
                                                    I_OPT_RESOURCE_INDICATOR, RESOURCE_INDICATOR,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(I_OK, i_add_claim_request(&i_session, I_CLAIM_TARGET_USERINFO, CLAIM1, I_CLAIM_ESSENTIAL_IGNORE, CLAIM1_CONTENT));
  ck_assert_int_eq(I_OK, i_add_claim_request(&i_session, I_CLAIM_TARGET_ID_TOKEN, CLAIM2, I_CLAIM_ESSENTIAL_FALSE, NULL));
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_OK);
  ck_assert_str_eq(DEVICE_AUTH_CODE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_CODE));
  ck_assert_str_eq(DEVICE_AUTH_USER_CODE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_USER_CODE));
  ck_assert_str_eq(DEVICE_AUTH_VERIFICATION_URI, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI));
  ck_assert_str_eq(DEVICE_AUTH_VERIFICATION_URI_COMPLETE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE));
  ck_assert_int_eq(DEVICE_AUTH_EXPIRES_IN, i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_EXPIRES_IN));
  ck_assert_int_eq(DEVICE_AUTH_INTERVAL, i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_INTERVAL));
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_device_auth_token_invalid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/device", 0, &callback_device_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_device_token_invalid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, DEVICE_AUTHORIZATION_ENDPOINT,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_OK);
  ck_assert_str_eq(DEVICE_AUTH_CODE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_CODE));
  ck_assert_str_eq(DEVICE_AUTH_USER_CODE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_USER_CODE));
  ck_assert_str_eq(DEVICE_AUTH_VERIFICATION_URI, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI));
  ck_assert_str_eq(DEVICE_AUTH_VERIFICATION_URI_COMPLETE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE));
  ck_assert_int_eq(DEVICE_AUTH_EXPIRES_IN, i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_EXPIRES_IN));
  ck_assert_int_eq(DEVICE_AUTH_INTERVAL, i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_INTERVAL));
  
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_str_eq(DEVICE_ERROR, i_get_str_parameter(&i_session, I_OPT_ERROR));
  ck_assert_str_eq(DEVICE_ERROR_DESCRIPTION, i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION));
  ck_assert_str_eq(DEVICE_ERROR_URI, i_get_str_parameter(&i_session, I_OPT_ERROR_URI));
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_device_auth_token_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/device", 0, &callback_device_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_device_token_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, DEVICE_AUTHORIZATION_ENDPOINT,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_OK);
  ck_assert_str_eq(DEVICE_AUTH_CODE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_CODE));
  ck_assert_str_eq(DEVICE_AUTH_USER_CODE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_USER_CODE));
  ck_assert_str_eq(DEVICE_AUTH_VERIFICATION_URI, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI));
  ck_assert_str_eq(DEVICE_AUTH_VERIFICATION_URI_COMPLETE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE));
  ck_assert_int_eq(DEVICE_AUTH_EXPIRES_IN, i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_EXPIRES_IN));
  ck_assert_int_eq(DEVICE_AUTH_INTERVAL, i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_INTERVAL));
  
  ck_assert_int_eq(i_run_token_request(&i_session), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), ACCESS_TOKEN);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), REFRESH_TOKEN);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), TOKEN_TYPE);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), EXPIRES_IN);
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_device_auth_encrypted_token_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  jwk_t * jwk;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/device", 0, &callback_device_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_device_token_encrypted_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, DEVICE_AUTHORIZATION_ENDPOINT,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_DECRYPT_REFRESH_TOKEN, 1,
                                                    I_OPT_DECRYPT_ACCESS_TOKEN, 1,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_OK);
  ck_assert_str_eq(DEVICE_AUTH_CODE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_CODE));
  ck_assert_str_eq(DEVICE_AUTH_USER_CODE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_USER_CODE));
  ck_assert_str_eq(DEVICE_AUTH_VERIFICATION_URI, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI));
  ck_assert_str_eq(DEVICE_AUTH_VERIFICATION_URI_COMPLETE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE));
  ck_assert_int_eq(DEVICE_AUTH_EXPIRES_IN, i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_EXPIRES_IN));
  ck_assert_int_eq(DEVICE_AUTH_INTERVAL, i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_INTERVAL));
  
  ck_assert_int_eq(i_run_token_request(&i_session), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), ACCESS_TOKEN);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), REFRESH_TOKEN);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), TOKEN_TYPE);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), EXPIRES_IN);
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_device_auth_encrypted_token_invalid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  jwk_t * jwk;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/device", 0, &callback_device_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_device_token_encrypted_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_DEVICE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                                    I_OPT_SCOPE, SCOPE,
                                                    I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, DEVICE_AUTHORIZATION_ENDPOINT,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_DECRYPT_REFRESH_TOKEN, 1,
                                                    I_OPT_DECRYPT_ACCESS_TOKEN, 1,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str_2), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_run_device_auth_request(&i_session), I_OK);
  ck_assert_str_eq(DEVICE_AUTH_CODE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_CODE));
  ck_assert_str_eq(DEVICE_AUTH_USER_CODE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_USER_CODE));
  ck_assert_str_eq(DEVICE_AUTH_VERIFICATION_URI, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI));
  ck_assert_str_eq(DEVICE_AUTH_VERIFICATION_URI_COMPLETE, i_get_str_parameter(&i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE));
  ck_assert_int_eq(DEVICE_AUTH_EXPIRES_IN, i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_EXPIRES_IN));
  ck_assert_int_eq(DEVICE_AUTH_INTERVAL, i_get_int_parameter(&i_session, I_OPT_DEVICE_AUTH_INTERVAL));
  
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

static Suite *iddawc_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Iddawc device tests");
  tc_core = tcase_create("test_iddawc_device");
  tcase_add_test(tc_core, test_iddawc_device_auth_invalid_parameters);
  tcase_add_test(tc_core, test_iddawc_device_auth_valid);
  tcase_add_test(tc_core, test_iddawc_device_claims_resource_valid);
  tcase_add_test(tc_core, test_iddawc_device_auth_token_invalid);
  tcase_add_test(tc_core, test_iddawc_device_auth_token_valid);
  tcase_add_test(tc_core, test_iddawc_device_auth_encrypted_token_valid);
  tcase_add_test(tc_core, test_iddawc_device_auth_encrypted_token_invalid);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc device tests");
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
