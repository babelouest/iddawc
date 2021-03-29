/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <iddawc.h>

#define SCOPE1 "scope1"
#define SCOPE2 "scope2"
#define SCOPE_LIST "scope1 scope2"
#define STATE "stateXyz1234"
#define REDIRECT_URI "https://iddawc.tld"
#define REDIRECT_TO "https://iddawc.tld#access_token=plop"
#define CLIENT_ID "clientXyz1234"
#define CLIENT_SECRET "secretXyx1234567"
#define CLIENT_SECRET_ERROR "secretXyx7654321"
#define TOKEN_ENDPOINT "http://localhost:8080/token"
#define TOKEN_ENDPOINT_CERT "https://localhost:8080/token"
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
#define USERNAME "dev"
#define USER_PASSWORD "password"

static char * get_file_content(const char * file_path) {
  char * buffer = NULL;
  size_t length, res;
  FILE * f;

  f = fopen (file_path, "rb");
  if (f) {
    fseek (f, 0, SEEK_END);
    length = ftell (f);
    fseek (f, 0, SEEK_SET);
    buffer = o_malloc((length+1)*sizeof(char));
    if (buffer) {
      res = fread (buffer, 1, length, f);
      if (res != length) {
        fprintf(stderr, "fread warning, reading %zu while expecting %zu", res, length);
      }
      // Add null character at the end of buffer, just in case
      buffer[length] = '\0';
    }
    fclose (f);
  } else {
    fprintf(stderr, "error opening file %s\n", file_path);
  }
  
  return buffer;
}

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

int callback_oauth2_token_invalid_request (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * error = json_pack("{ssssss}", 
                             "error", "invalid_request",
                             "error_description", "invalid_request description",
                             "error_uri", "invalid_request uri");
  ulfius_set_json_body_response(response, 400, error);
  json_decref(error);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_token_invalid_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * error = json_pack("{ssssss}", 
                             "error", "invalid_client",
                             "error_description", "invalid_client description",
                             "error_uri", "invalid_client uri");
  ulfius_set_json_body_response(response, 400, error);
  json_decref(error);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_token_invalid_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * error = json_pack("{ssssss}", 
                             "error", "invalid_grant",
                             "error_description", "invalid_grant description",
                             "error_uri", "invalid_grant uri");
  ulfius_set_json_body_response(response, 400, error);
  json_decref(error);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_token_unauthorized_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * error = json_pack("{ssssss}", 
                             "error", "unauthorized_client",
                             "error_description", "unauthorized_client description",
                             "error_uri", "unauthorized_client uri");
  ulfius_set_json_body_response(response, 400, error);
  json_decref(error);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_token_unsupported_grant_type (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * error = json_pack("{ssssss}", 
                             "error", "unsupported_grant_type",
                             "error_description", "unsupported_grant_type description",
                             "error_uri", "unsupported_grant_type uri");
  ulfius_set_json_body_response(response, 400, error);
  json_decref(error);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_token_invalid_scope (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * error = json_pack("{ssssss}", 
                             "error", "invalid_scope",
                             "error_description", "invalid_scope description",
                             "error_uri", "invalid_scope uri");
  ulfius_set_json_body_response(response, 400, error);
  json_decref(error);
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

int callback_oauth2_token_code_encrypted_ok (const struct _u_request * request, struct _u_response * response, void * user_data) {
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

int callback_oauth2_token_access_token_ok (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * result = json_pack("{sssssi}", 
                             "access_token", ACCESS_TOKEN,
                             "token_type", "bearer",
                             "expires_in", 3600);
  ulfius_set_json_body_response(response, 200, result);
  json_decref(result);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_token_jwt_auth_code_ok (const struct _u_request * request, struct _u_response * response, void * user_data) {
  if (0 == o_strcmp(u_map_get(request->map_post_body, "client_assertion_type"), "urn:ietf:params:oauth:client-assertion-type:jwt-bearer") && o_strlen(u_map_get(request->map_post_body, "client_assertion"))) {
    jwt_t * jwt;
    jwk_t * jwk;
    r_jwt_init(&jwt);
    r_jwk_init(&jwk);
    r_jwt_parse(jwt, u_map_get(request->map_post_body, "client_assertion"), 0);
    if (r_jwt_get_sign_alg(jwt) == R_JWA_ALG_HS256) {
      r_jwk_import_from_symmetric_key(jwk, (const unsigned char *)CLIENT_SECRET, o_strlen(CLIENT_SECRET));
      if (r_jwt_verify_signature(jwt, jwk, 0) == RHN_OK) {
        json_t * result = json_pack("{sssssiss}", 
                                   "access_token", ACCESS_TOKEN,
                                   "token_type", "bearer",
                                   "expires_in", 3600,
                                   "refresh_token", REFRESH_TOKEN);
        ulfius_set_json_body_response(response, 200, result);
        json_decref(result);
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
        json_t * result = json_pack("{sssssiss}", 
                                   "access_token", ACCESS_TOKEN,
                                   "token_type", "bearer",
                                   "expires_in", 3600,
                                   "refresh_token", REFRESH_TOKEN);
        ulfius_set_json_body_response(response, 200, result);
        json_decref(result);
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
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_token_code_cert_ok (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * result = json_pack("{sssssiss}", 
                             "access_token", ACCESS_TOKEN,
                             "token_type", "bearer",
                             "expires_in", 3600,
                             "refresh_token", REFRESH_TOKEN);
  if (request->client_cert != NULL) {
    ulfius_set_json_body_response(response, 200, result);
  } else {
    response->status = 403;
  }
  json_decref(result);

  return U_CALLBACK_CONTINUE;
}

START_TEST(test_iddawc_token_code_invalid_parameters)
{
  struct _i_session i_session;
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_CODE, CODE,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_CODE, CODE,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_CODE, CODE,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);
  
}
END_TEST

START_TEST(test_iddawc_token_code_invalid_request)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_invalid_request, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_CODE, CODE,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_request");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "invalid_request description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "invalid_request uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_code_invalid_client)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_invalid_client, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_CLIENT_ID, "error",
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_CODE, CODE,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_client");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "invalid_client description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "invalid_client uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_code_invalid_grant)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_invalid_grant, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_CODE, "error",
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_grant");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "invalid_grant description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "invalid_grant uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_code_unauthorized_client)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_unauthorized_client, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_CLIENT_ID, "error",
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_CODE, CODE,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "unauthorized_client");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "unauthorized_client description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "unauthorized_client uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_code_unsupported_grant_type)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_unsupported_grant_type, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_CODE, CODE,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "unsupported_grant_type");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "unsupported_grant_type description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "unsupported_grant_type uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_code_invalid_scope)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_invalid_scope, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_CODE, CODE,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_scope");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "invalid_scope description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "invalid_scope uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_code_ok)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_code_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_CODE, CODE,
                                                    I_OPT_NONE), I_OK);
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

START_TEST(test_iddawc_token_code_encrypted_invalid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  jwk_t * jwk;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_code_encrypted_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_CODE, CODE,
                                                  I_OPT_DECRYPT_REFRESH_TOKEN, 1,
                                                  I_OPT_DECRYPT_ACCESS_TOKEN, 1,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str_2), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_code_encrypted_ok)
{
  struct _i_session i_session;
  struct _u_instance instance;
  jwk_t * jwk;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_code_encrypted_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_CODE, CODE,
                                                  I_OPT_DECRYPT_REFRESH_TOKEN, 1,
                                                  I_OPT_DECRYPT_ACCESS_TOKEN, 1,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_run_token_request(&i_session), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), ACCESS_TOKEN);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), REFRESH_TOKEN);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), "bearer");
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 3600);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_password_invalid_parameters)
{
  struct _i_session i_session;

  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_PASSWORD,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_USERNAME, USERNAME,
                                                  I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_PASSWORD,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_PASSWORD,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_USERNAME, USERNAME,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);
  
}
END_TEST

START_TEST(test_iddawc_token_password_noclient_invalid_request)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_invalid_request, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_PASSWORD,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_USERNAME, USERNAME,
                                                    I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_request");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "invalid_request description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "invalid_request uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_password_noclient_unsupported_grant_type)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_unsupported_grant_type, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_PASSWORD,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_USERNAME, USERNAME,
                                                  I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "unsupported_grant_type");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "unsupported_grant_type description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "unsupported_grant_type uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_password_noclient_invalid_scope)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_invalid_scope, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_PASSWORD,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_USERNAME, USERNAME,
                                                  I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_scope");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "invalid_scope description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "invalid_scope uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_password_noclient_ok)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_code_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_PASSWORD,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_USERNAME, USERNAME,
                                                  I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                  I_OPT_NONE), I_OK);
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

START_TEST(test_iddawc_token_password_client_invalid_client)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_invalid_client, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_PASSWORD,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_CLIENT_ID, "error",
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_USERNAME, USERNAME,
                                                  I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_client");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "invalid_client description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "invalid_client uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_password_noclient_unauthorized_client)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_unauthorized_client, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_PASSWORD,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, "error",
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_USERNAME, USERNAME,
                                                  I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "unauthorized_client");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "unauthorized_client description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "unauthorized_client uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_password_client_ok)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_code_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_PASSWORD,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_USERNAME, USERNAME,
                                                  I_OPT_USER_PASSWORD, USER_PASSWORD,
                                                  I_OPT_NONE), I_OK);
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

START_TEST(test_iddawc_token_client_credentials_client_invalid_client)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_invalid_client, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CLIENT_CREDENTIALS,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_CLIENT_ID, "error",
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_client");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "invalid_client description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "invalid_client uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_client_credentials_client_unauthorized_client)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_unauthorized_client, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CLIENT_CREDENTIALS,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, "error",
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "unauthorized_client");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "unauthorized_client description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "unauthorized_client uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_client_credentials_client_ok)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_access_token_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CLIENT_CREDENTIALS,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_CLIENT_ID, CLIENT_ID,
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), "bearer");
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 3600);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_refresh_token_noclient_invalid_parameters)
{
  struct _i_session i_session;
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_REFRESH_TOKEN,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_REFRESH_TOKEN, REFRESH_TOKEN,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);

  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_REFRESH_TOKEN,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);

}
END_TEST

START_TEST(test_iddawc_token_refresh_token_noclient_invalid_grant)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_invalid_grant, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_REFRESH_TOKEN,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_CLIENT_ID, "error",
                                                  I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_REFRESH_TOKEN, "error",
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_grant");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "invalid_grant description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "invalid_grant uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_refresh_token_noclient_unauthorized_client)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_unauthorized_client, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_REFRESH_TOKEN,
                                                  I_OPT_SCOPE, SCOPE_LIST,
                                                  I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                  I_OPT_REFRESH_TOKEN, "error",
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "unauthorized_client");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "unauthorized_client description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "unauthorized_client uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_refresh_token_noclient_invalid_client)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_invalid_client, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_REFRESH_TOKEN,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_REFRESH_TOKEN, "error",
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 0);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_client");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), "invalid_client description");
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), "invalid_client uri");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_refresh_token_noclient_ok)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_access_token_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_REFRESH_TOKEN,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_REFRESH_TOKEN, REFRESH_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), "bearer");
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 3600);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_code_jwt_auth_secret_error_param)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_TOKEN_METHOD, I_TOKEN_AUTH_METHOD_JWT_SIGN_SECRET,
                                                    I_OPT_TOKEN_JTI_GENERATE, 32,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_CODE, CODE,
                                                    I_OPT_OPENID_CONFIG_STRICT, I_STRICT_YES,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SECRET, CLIENT_SECRET), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SECRET, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SIGN_ALG, "HS256"), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SECRET, CLIENT_SECRET), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SIGN_ALG, "RS256"), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_token_code_jwt_auth_privkey_error_param)
{
  struct _i_session i_session;
  jwk_t * jwk;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_TOKEN_METHOD, I_TOKEN_AUTH_METHOD_JWT_SIGN_SECRET,
                                                    I_OPT_TOKEN_JTI_GENERATE, 32,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_CODE, CODE,
                                                    I_OPT_OPENID_CONFIG_STRICT, I_STRICT_YES,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SIGN_ALG, "HS256"), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str_2), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SIGN_ALG, "RS256"), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_KID, "error"), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_token_code_jwt_auth_secret_ok)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_jwt_auth_code_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_TOKEN_METHOD, I_TOKEN_AUTH_METHOD_JWT_SIGN_SECRET,
                                                    I_OPT_TOKEN_JTI_GENERATE, 32,
                                                    I_OPT_CLIENT_SIGN_ALG, "HS256",
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_CODE, CODE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), "bearer");
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 3600);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SECRET, CLIENT_SECRET_ERROR), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_code_jwt_auth_privkey_ok)
{
  struct _i_session i_session;
  struct _u_instance instance;
  jwk_t * jwk;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_jwt_auth_code_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_TOKEN_METHOD, I_TOKEN_AUTH_METHOD_JWT_SIGN_PRIVKEY,
                                                    I_OPT_TOKEN_JTI_GENERATE, 32,
                                                    I_OPT_CLIENT_SIGN_ALG, "RS256",
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_CODE, CODE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_run_token_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), "bearer");
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 3600);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str_2), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_KID, "2"), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_PARAM);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_code_certificate_ok)
{
  struct _i_session i_session;
  struct _u_instance instance;
  char * cert = get_file_content("cert/server.crt"), * key = get_file_content("cert/server.key"), * ca = get_file_content("cert/root1.crt");

  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_code_cert_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_secure_ca_trust_framework(&instance, key, cert, ca), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT_CERT,
                                                    I_OPT_TOKEN_METHOD, I_TOKEN_AUTH_METHOD_TLS_CERTIFICATE,
                                                    I_OPT_TLS_KEY_FILE, "cert/user1.key",
                                                    I_OPT_TLS_CERT_FILE, "cert/user1.crt",
                                                    I_OPT_REMOTE_CERT_FLAG, I_REMOTE_VERIFY_NONE,
                                                    I_OPT_CODE, CODE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), "bearer");
  ck_assert_int_eq(i_get_int_parameter(&i_session, I_OPT_EXPIRES_IN), 3600);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  o_free(cert);
  o_free(key);
  o_free(ca);
}
END_TEST

START_TEST(test_iddawc_token_code_certificate_invalid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  char * cert = get_file_content("cert/server.crt"), * key = get_file_content("cert/server.key"), * ca = get_file_content("cert/root1.crt");

  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_oauth2_token_code_cert_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_secure_ca_trust_framework(&instance, key, cert, ca), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT_CERT,
                                                    I_OPT_TOKEN_METHOD, I_TOKEN_AUTH_METHOD_TLS_CERTIFICATE,
                                                    I_OPT_TLS_KEY_FILE, "cert/user2.key",
                                                    I_OPT_TLS_CERT_FILE, "cert/user2.crt",
                                                    I_OPT_REMOTE_CERT_FLAG, I_REMOTE_VERIFY_NONE,
                                                    I_OPT_CODE, CODE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_token_request(&i_session), I_ERROR_UNAUTHORIZED);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_REFRESH_TOKEN), NULL);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  o_free(cert);
  o_free(key);
  o_free(ca);
}
END_TEST

static Suite *iddawc_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Iddawc token tests");
  tc_core = tcase_create("test_iddawc_token");
  tcase_add_test(tc_core, test_iddawc_token_code_invalid_parameters);
  tcase_add_test(tc_core, test_iddawc_token_code_invalid_request);
  tcase_add_test(tc_core, test_iddawc_token_code_invalid_client);
  tcase_add_test(tc_core, test_iddawc_token_code_invalid_grant);
  tcase_add_test(tc_core, test_iddawc_token_code_unauthorized_client);
  tcase_add_test(tc_core, test_iddawc_token_code_unsupported_grant_type);
  tcase_add_test(tc_core, test_iddawc_token_code_invalid_scope);
  tcase_add_test(tc_core, test_iddawc_token_code_ok);
  tcase_add_test(tc_core, test_iddawc_token_code_encrypted_invalid);
  tcase_add_test(tc_core, test_iddawc_token_code_encrypted_ok);
  tcase_add_test(tc_core, test_iddawc_token_password_invalid_parameters);
  tcase_add_test(tc_core, test_iddawc_token_password_noclient_invalid_request);
  tcase_add_test(tc_core, test_iddawc_token_password_noclient_unsupported_grant_type);
  tcase_add_test(tc_core, test_iddawc_token_password_noclient_invalid_scope);
  tcase_add_test(tc_core, test_iddawc_token_password_noclient_ok);
  tcase_add_test(tc_core, test_iddawc_token_password_client_invalid_client);
  tcase_add_test(tc_core, test_iddawc_token_password_noclient_unauthorized_client);
  tcase_add_test(tc_core, test_iddawc_token_password_client_ok);
  tcase_add_test(tc_core, test_iddawc_token_client_credentials_client_invalid_client);
  tcase_add_test(tc_core, test_iddawc_token_client_credentials_client_unauthorized_client);
  tcase_add_test(tc_core, test_iddawc_token_client_credentials_client_ok);
  tcase_add_test(tc_core, test_iddawc_token_refresh_token_noclient_invalid_parameters);
  tcase_add_test(tc_core, test_iddawc_token_refresh_token_noclient_invalid_grant);
  tcase_add_test(tc_core, test_iddawc_token_refresh_token_noclient_unauthorized_client);
  tcase_add_test(tc_core, test_iddawc_token_refresh_token_noclient_invalid_client);
  tcase_add_test(tc_core, test_iddawc_token_refresh_token_noclient_ok);
  tcase_add_test(tc_core, test_iddawc_token_code_jwt_auth_secret_error_param);
  tcase_add_test(tc_core, test_iddawc_token_code_jwt_auth_privkey_error_param);
  tcase_add_test(tc_core, test_iddawc_token_code_jwt_auth_secret_ok);
  tcase_add_test(tc_core, test_iddawc_token_code_jwt_auth_privkey_ok);
  tcase_add_test(tc_core, test_iddawc_token_code_certificate_ok);
  tcase_add_test(tc_core, test_iddawc_token_code_certificate_invalid);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc token tests");
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
