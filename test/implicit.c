/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <iddawc.h>

#define SCOPE1 "scope1"
#define SCOPE2 "scope2"
#define SCOPE_LIST "scope1 scope2"
#define STATE "stateXyz1234"
#define CODE "codeXyz1234"
#define ACCESS_TOKEN "accessXyz1234"
#define TOKEN_TYPE "typeXyz1234"
#define EXPIRES_IN "3600"
#define ERROR "errorXyz1234"
#define ERROR_DESCRIPTION "errorDescriptionXyz1234"
#define ERROR_URI "errorUriXyz1234"
#define REDIRECT_URI "https://iddawc.tld"
#define REDIRECT_TO "https://iddawc.tld#access_token=plop"
#define REDIRECT_TO_CODE "https://iddawc.tld?code=" CODE "&state=" STATE "&query_param=value1#fragment_param=value2"
#define REDIRECT_TO_ACCESS_TOKEN "https://iddawc.tld#access_token=" ACCESS_TOKEN "&state=" STATE "&token_type=" TOKEN_TYPE "&expires_in=" EXPIRES_IN "&fragment_param=value2"
#define REDIRECT_TO_ERROR "https://iddawc.tld#error=" ERROR "&error_description=" ERROR_DESCRIPTION "&error_uri=" ERROR_URI "&state=" STATE "&fragment_param=value2"
#define REDIRECT_EXTERNAL_AUTH "https://glewlwyd.tld/login.html"
#define CLIENT_ID "clientXyz1234"
#define CLIENT_SECRET "secretXyx1234567"
#define CLIENT_SECRET_ERROR "secretXyx7654321"
#define AUTH_ENDPOINT "http://localhost:8080/auth"
#define REFRESH_TOKEN "refreshXyz1234"
#define ID_TOKEN "idTokenXyz1234"
#define GLEWLWYD_API_URL "https://glewlwyd.tld/api"
#define GLEWLWYD_COOKIE_SESSION "cookieXyz1234"

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

int callback_oauth2_unauthorized_public_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * redirect = msprintf("%s?error=unauthorized_client&error_description=Invalid+client_id&state=%s", u_map_get(request->map_url, "redirect_uri"), u_map_get(request->map_url, "state"));
  u_map_put(response->map_header, "Location", redirect);
  response->status = 302;
  o_free(redirect);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_invalid_scope (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * redirect = msprintf("%s?error=invalid_scope&error_description=Scope+missing&state=%s", u_map_get(request->map_url, "redirect_uri"), u_map_get(request->map_url, "state"));
  u_map_put(response->map_header, "Location", redirect);
  response->status = 302;
  o_free(redirect);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_invalid_response_type (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * redirect = msprintf("%s?error=invalid_request&state=%s", u_map_get(request->map_url, "redirect_uri"), u_map_get(request->map_url, "state"));
  u_map_put(response->map_header, "Location", redirect);
  response->status = 302;
  o_free(redirect);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_invalid_state (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * redirect = msprintf("%s?code=xyz&state=error%s", u_map_get(request->map_url, "redirect_uri"), u_map_get(request->map_url, "state"));
  u_map_put(response->map_header, "Location", redirect);
  response->status = 302;
  o_free(redirect);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_code_empty (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * redirect = msprintf("%s?code&state=%s", u_map_get(request->map_url, "redirect_uri"), u_map_get(request->map_url, "state"));
  u_map_put(response->map_header, "Location", redirect);
  response->status = 302;
  o_free(redirect);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_access_token_empty (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * redirect = msprintf("%s#access_token&token_type=" TOKEN_TYPE "&state=%s", u_map_get(request->map_url, "redirect_uri"), u_map_get(request->map_url, "state"));
  u_map_put(response->map_header, "Location", redirect);
  response->status = 302;
  o_free(redirect);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_token_type_empty (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * redirect = msprintf("%s#access_token=" ACCESS_TOKEN "&token_type&code&state=%s", u_map_get(request->map_url, "redirect_uri"), u_map_get(request->map_url, "state"));
  u_map_put(response->map_header, "Location", redirect);
  response->status = 302;
  o_free(redirect);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_expires_in_invalid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * redirect = msprintf("%s#access_token=" ACCESS_TOKEN "&token_type=" TOKEN_TYPE "&expires_in=error&code&state=%s", u_map_get(request->map_url, "redirect_uri"), u_map_get(request->map_url, "state"));
  u_map_put(response->map_header, "Location", redirect);
  response->status = 302;
  o_free(redirect);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_redirect_external_auth (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * redirect = msprintf(REDIRECT_EXTERNAL_AUTH "?redirect_uri=%s&state=%s", u_map_get(request->map_url, "redirect_uri"), u_map_get(request->map_url, "state"));
  u_map_put(response->map_header, "Location", redirect);
  response->status = 302;
  o_free(redirect);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_code_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * redirect = msprintf("%s?code=" CODE "&state=%s", u_map_get(request->map_url, "redirect_uri"), u_map_get(request->map_url, "state"));
  u_map_put(response->map_header, "Location", redirect);
  response->status = 302;
  o_free(redirect);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_access_token_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * redirect = msprintf("%s#access_token=" ACCESS_TOKEN "&token_type=" TOKEN_TYPE "&state=%s", u_map_get(request->map_url, "redirect_uri"), u_map_get(request->map_url, "state"));
  u_map_put(response->map_header, "Location", redirect);
  response->status = 302;
  o_free(redirect);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_id_token_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * redirect = msprintf("%s#id_token=" ID_TOKEN "&state=%s", u_map_get(request->map_url, "redirect_uri"), u_map_get(request->map_url, "state"));
  u_map_put(response->map_header, "Location", redirect);
  response->status = 302;
  o_free(redirect);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_access_token_id_token_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * redirect = msprintf("%s#access_token=" ACCESS_TOKEN "&id_token=" ID_TOKEN "&token_type=" TOKEN_TYPE "&state=%s", u_map_get(request->map_url, "redirect_uri"), u_map_get(request->map_url, "state"));
  u_map_put(response->map_header, "Location", redirect);
  response->status = 302;
  o_free(redirect);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_access_token_code_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * redirect = msprintf("%s#access_token=" ACCESS_TOKEN "&code=" CODE "&token_type=" TOKEN_TYPE "&state=%s", u_map_get(request->map_url, "redirect_uri"), u_map_get(request->map_url, "state"));
  u_map_put(response->map_header, "Location", redirect);
  response->status = 302;
  o_free(redirect);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_access_token_code_id_token_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * redirect = msprintf("%s#access_token=" ACCESS_TOKEN "&id_token=" ID_TOKEN "&code=" CODE "&token_type=" TOKEN_TYPE "&state=%s", u_map_get(request->map_url, "redirect_uri"), u_map_get(request->map_url, "state"));
  u_map_put(response->map_header, "Location", redirect);
  response->status = 302;
  o_free(redirect);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_code_valid_post (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * redirect = msprintf("%s?code=" CODE "&state=%s", u_map_get(request->map_post_body, "redirect_uri"), u_map_get(request->map_post_body, "state"));
  u_map_put(response->map_header, "Location", redirect);
  response->status = 302;
  o_free(redirect);
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_code_valid_post_jwt_signed (const struct _u_request * request, struct _u_response * response, void * user_data) {
  if (u_map_get(request->map_post_body, "request") != NULL) {
    jwt_t * jwt;
    jwk_t * jwk;
    r_jwt_init(&jwt);
    r_jwk_init(&jwk);
    r_jwt_parse(jwt, u_map_get(request->map_post_body, "request"), 0);
    if (r_jwt_get_sign_alg(jwt) == R_JWA_ALG_HS256) {
      r_jwk_import_from_symmetric_key(jwk, (const unsigned char *)CLIENT_SECRET, o_strlen(CLIENT_SECRET));
      if (r_jwt_verify_signature(jwt, jwk, 0) == RHN_OK) {
        char * redirect = msprintf("%s?code=" CODE "&state=%s", REDIRECT_URI, STATE);
        u_map_put(response->map_header, "Location", redirect);
        response->status = 302;
        o_free(redirect);
      } else {
        response->status = 400;
      }
    } else {
      r_jwk_import_from_json_str(jwk, jwk_pubkey_str);
      if (r_jwt_verify_signature(jwt, jwk, 0) == RHN_OK) {
        char * redirect = msprintf("%s?code=" CODE "&state=%s", REDIRECT_URI, STATE);
        u_map_put(response->map_header, "Location", redirect);
        response->status = 302;
        o_free(redirect);
      } else {
        response->status = 400;
      }
    }
    r_jwt_free(jwt);
    r_jwk_free(jwk);
  } else {
    response->status = 400;
  }
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_code_valid_post_jwt_encrypted (const struct _u_request * request, struct _u_response * response, void * user_data) {
  if (u_map_get(request->map_post_body, "request") != NULL) {
    jwt_t * jwt;
    jwk_t * jwk;
    r_jwt_init(&jwt);
    r_jwk_init(&jwk);
    r_jwt_parse(jwt, u_map_get(request->map_post_body, "request"), 0);
    if (r_jwt_get_enc_alg(jwt) == R_JWA_ALG_A128GCMKW) {
      r_jwk_import_from_symmetric_key(jwk, (const unsigned char *)CLIENT_SECRET, o_strlen(CLIENT_SECRET));
      if (r_jwt_decrypt(jwt, jwk, 0) == RHN_OK) {
        char * redirect = msprintf("%s?code=" CODE "&state=%s", REDIRECT_URI, STATE);
        u_map_put(response->map_header, "Location", redirect);
        response->status = 302;
        o_free(redirect);
      } else {
        response->status = 400;
      }
    } else {
      r_jwk_import_from_json_str(jwk, jwk_privkey_str);
      if (r_jwt_decrypt(jwt, jwk, 0) == RHN_OK) {
        char * redirect = msprintf("%s?code=" CODE "&state=%s", REDIRECT_URI, STATE);
        u_map_put(response->map_header, "Location", redirect);
        response->status = 302;
        o_free(redirect);
      } else {
        response->status = 400;
      }
    }
    r_jwt_free(jwt);
    r_jwk_free(jwk);
  } else {
    response->status = 400;
  }
  return U_CALLBACK_CONTINUE;
}

int callback_oauth2_code_valid_post_jwt_nested (const struct _u_request * request, struct _u_response * response, void * user_data) {
  if (u_map_get(request->map_post_body, "request") != NULL) {
    jwt_t * jwt;
    jwk_t * jwk = NULL, * jwk2 = NULL;
    r_jwt_init(&jwt);
    r_jwk_init(&jwk);
    r_jwk_init(&jwk2);
    r_jwt_parse(jwt, u_map_get(request->map_post_body, "request"), 0);
    if (r_jwt_get_type(jwt) == R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT) {
      if (r_jwt_get_enc_alg(jwt) == R_JWA_ALG_A128GCMKW) {
        r_jwk_import_from_symmetric_key(jwk, (const unsigned char *)CLIENT_SECRET, o_strlen(CLIENT_SECRET));
        r_jwk_import_from_symmetric_key(jwk2, (const unsigned char *)CLIENT_SECRET, o_strlen(CLIENT_SECRET));
        if (r_jwt_decrypt_verify_signature_nested(jwt, jwk, 0, jwk2, 0) == RHN_OK) {
          char * redirect = msprintf("%s?code=" CODE "&state=%s", REDIRECT_URI, STATE);
          u_map_put(response->map_header, "Location", redirect);
          response->status = 302;
          o_free(redirect);
        } else {
          response->status = 400;
        }
      } else {
        r_jwk_import_from_json_str(jwk, jwk_pubkey_str);
        r_jwk_import_from_json_str(jwk2, jwk_privkey_str);
        if (r_jwt_decrypt_verify_signature_nested(jwt, jwk, 0, jwk2, 0) == RHN_OK) {
          char * redirect = msprintf("%s?code=" CODE "&state=%s", REDIRECT_URI, STATE);
          u_map_put(response->map_header, "Location", redirect);
          response->status = 302;
          o_free(redirect);
        } else {
          response->status = 400;
        }
      }
    } else {
      response->status = 400;
    }
    r_jwt_free(jwt);
    r_jwk_free(jwk);
    r_jwk_free(jwk2);
  } else {
    response->status = 400;
  }
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_iddawc_unauthorized_public_client)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/auth", 0, &callback_oauth2_unauthorized_public_client, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_int_eq(i_get_result(&i_session), I_ERROR_UNAUTHORIZED);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "unauthorized_client");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_invalid_client_secret)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/auth", 0, &callback_oauth2_unauthorized_public_client, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_int_eq(i_get_result(&i_session), I_ERROR_UNAUTHORIZED);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "unauthorized_client");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_scope_empty)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/auth", 0, &callback_oauth2_invalid_scope, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_int_eq(i_get_result(&i_session), I_ERROR_UNAUTHORIZED);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_scope");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_invalid_response_type)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/auth", 0, &callback_oauth2_invalid_response_type, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_int_eq(i_get_result(&i_session), I_ERROR_UNAUTHORIZED);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), "invalid_request");
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_invalid_state)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/auth", 0, &callback_oauth2_invalid_state, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_SERVER);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_code_empty)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/auth", 0, &callback_oauth2_code_empty, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_SERVER);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_access_token_empty)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/auth", 0, &callback_oauth2_access_token_empty, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_TOKEN,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_SERVER);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_token_type_empty)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/auth", 0, &callback_oauth2_token_type_empty, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_TOKEN,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_SERVER);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_expires_in_invalid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/auth", 0, &callback_oauth2_expires_in_invalid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_TOKEN,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_SERVER);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_redirect_external_auth)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/auth", 0, &callback_oauth2_redirect_external_auth, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO), REDIRECT_EXTERNAL_AUTH "?redirect_uri=" REDIRECT_URI "&state=" STATE);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_code_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/auth", 0, &callback_oauth2_code_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_access_token_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/auth", 0, &callback_oauth2_access_token_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_TOKEN,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_id_token_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/auth", 0, &callback_oauth2_id_token_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_ID_TOKEN,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), NULL);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), NULL);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_access_token_id_token_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/auth", 0, &callback_oauth2_access_token_id_token_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_ID_TOKEN,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), NULL);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), NULL);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_access_token_code_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/auth", 0, &callback_oauth2_access_token_code_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_access_token_code_id_token_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/auth", 0, &callback_oauth2_access_token_code_id_token_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_CODE|I_RESPONSE_TYPE_ID_TOKEN,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), NULL);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), NULL);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_TOKEN_TYPE), NULL);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), NULL);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_code_valid_post)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/auth", 0, &callback_oauth2_code_valid_post, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_AUTH_METHOD, I_AUTH_METHOD_POST,
                                                    I_OPT_NONE), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_parse_redirect_to_code_ok)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_REDIRECT_TO, REDIRECT_TO_CODE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_parse_redirect_to(&i_session), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CODE), CODE);
  ck_assert_str_eq(i_get_additional_response(&i_session, "query_param"), "value1");
  ck_assert_ptr_eq(i_get_additional_response(&i_session, "fragment_param"), NULL);

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_parse_redirect_to_access_token_ok)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_TOKEN,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_REDIRECT_TO, REDIRECT_TO_ACCESS_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_parse_redirect_to(&i_session), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), ACCESS_TOKEN);
  ck_assert_ptr_eq(i_get_additional_response(&i_session, "query_param"), NULL);
  ck_assert_str_eq(i_get_additional_response(&i_session, "fragment_param"), "value2");

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_parse_redirect_to_error_ok)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_TOKEN,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_REDIRECT_TO, REDIRECT_TO_ERROR,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_parse_redirect_to(&i_session), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR), ERROR);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_DESCRIPTION), ERROR_DESCRIPTION);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ERROR_URI), ERROR_URI);
  ck_assert_ptr_eq(i_get_additional_response(&i_session, "query_param"), NULL);
  ck_assert_str_eq(i_get_additional_response(&i_session, "fragment_param"), "value2");

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_parse_redirect_to_code_error_state)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_REDIRECT_TO, "https://iddawc.tld?code=" CODE "&state=" "error" "&query_param=value1#fragment_param=value2",
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_parse_redirect_to(&i_session), I_ERROR_SERVER);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_CODE), CODE);
  ck_assert_str_eq(i_get_additional_response(&i_session, "query_param"), "value1");
  ck_assert_ptr_eq(i_get_additional_response(&i_session, "fragment_param"), NULL);

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_parse_redirect_to_access_token_error_state)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_TOKEN,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_REDIRECT_TO, "https://iddawc.tld#access_token=" ACCESS_TOKEN "&state=" "error" "&token_type=" TOKEN_TYPE "&expires_in=" EXPIRES_IN "&fragment_param=value2",
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_parse_redirect_to(&i_session), I_ERROR_SERVER);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), ACCESS_TOKEN);
  ck_assert_ptr_eq(i_get_additional_response(&i_session, "query_param"), NULL);
  ck_assert_str_eq(i_get_additional_response(&i_session, "fragment_param"), "value2");

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_parse_redirect_to_access_token_error_token_type)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_TOKEN,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_REDIRECT_TO, "https://iddawc.tld#access_token=" ACCESS_TOKEN "&state=" STATE "&expires_in=" EXPIRES_IN "&fragment_param=value2",
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_parse_redirect_to(&i_session), I_ERROR_SERVER);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), ACCESS_TOKEN);
  ck_assert_ptr_eq(i_get_additional_response(&i_session, "query_param"), NULL);
  ck_assert_str_eq(i_get_additional_response(&i_session, "fragment_param"), "value2");

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_parse_redirect_to_access_token_error_expires_in)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_TOKEN,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_REDIRECT_TO, "https://iddawc.tld#access_token=" ACCESS_TOKEN "&state=" STATE "&token_type=" TOKEN_TYPE "&fragment_param=value2",
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_parse_redirect_to(&i_session), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), ACCESS_TOKEN);
  ck_assert_ptr_eq(i_get_additional_response(&i_session, "query_param"), NULL);
  ck_assert_str_eq(i_get_additional_response(&i_session, "fragment_param"), "value2");

  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_code_valid_post_jwt_sign_secret_error_param)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_AUTH_METHOD, I_AUTH_METHOD_POST|I_AUTH_METHOD_JWT_SIGN_SECRET,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SECRET, CLIENT_SECRET), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SECRET, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SIGN_ALG, "HS256"), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SECRET, CLIENT_SECRET), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SIGN_ALG, "RSA1_5"), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SIGN_ALG, "RS256"), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_code_valid_post_jwt_sign_privkey_error_param)
{
  struct _i_session i_session;
  jwk_t * jwk;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SIGN_ALG, "RS256",
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_AUTH_METHOD, I_AUTH_METHOD_POST|I_AUTH_METHOD_JWT_SIGN_PRIVKEY,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SIGN_ALG, "RSA1_5"), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SIGN_ALG, "HS256"), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SIGN_ALG, "RS256"), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str_2), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_KID, "error"), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_code_valid_post_jwt_encrypt_secret_error_param)
{
  struct _i_session i_session;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_AUTH_METHOD, I_AUTH_METHOD_POST|I_AUTH_METHOD_JWT_ENCRYPT_SECRET,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SECRET, CLIENT_SECRET), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_ENC_ALG, "A128GCMKW"), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SECRET, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_ENC, "A128CBC-HS256"), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SECRET, CLIENT_SECRET), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_ENC_ALG, "RS256"), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_code_valid_post_jwt_encrypt_pubkey_error_param)
{
  struct _i_session i_session;
  jwk_t * jwk;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_AUTH_METHOD, I_AUTH_METHOD_POST|I_AUTH_METHOD_JWT_ENCRYPT_PUBKEY,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_ENC, "A128CBC-HS256"), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_ENC_ALG, "RS256"), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_ENC_ALG, "A128GCMKW"), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_ENC_ALG, "RSA1_5"), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_str_2), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_KID, "error"), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_code_valid_post_jwt_sign_secret)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/auth", 0, &callback_oauth2_code_valid_post_jwt_signed, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_CLIENT_SIGN_ALG, "HS256",
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_AUTH_METHOD, I_AUTH_METHOD_POST|I_AUTH_METHOD_JWT_SIGN_SECRET,
                                                    I_OPT_NONE), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SECRET, CLIENT_SECRET_ERROR), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_code_valid_post_jwt_sign_privkey)
{
  struct _i_session i_session;
  struct _u_instance instance;
  jwk_t * jwk;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/auth", 0, &callback_oauth2_code_valid_post_jwt_signed, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SIGN_ALG, "RS256",
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_AUTH_METHOD, I_AUTH_METHOD_POST|I_AUTH_METHOD_JWT_SIGN_PRIVKEY,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str_2), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_KID, "2"), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_code_valid_post_jwt_encrypt_secret)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/auth", 0, &callback_oauth2_code_valid_post_jwt_encrypted, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_CLIENT_ENC_ALG, "A128GCMKW",
                                                    I_OPT_CLIENT_ENC, "A128CBC-HS256",
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_AUTH_METHOD, I_AUTH_METHOD_POST|I_AUTH_METHOD_JWT_ENCRYPT_SECRET,
                                                    I_OPT_NONE), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_SECRET, CLIENT_SECRET_ERROR), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_code_valid_post_jwt_encrypt_pubkey)
{
  struct _i_session i_session;
  struct _u_instance instance;
  jwk_t * jwk;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/auth", 0, &callback_oauth2_code_valid_post_jwt_encrypted, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_ENC_ALG, "RSA1_5",
                                                    I_OPT_CLIENT_ENC, "A128CBC-HS256",
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_AUTH_METHOD, I_AUTH_METHOD_POST|I_AUTH_METHOD_JWT_ENCRYPT_PUBKEY,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_str_2), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CLIENT_KID, "2"), I_OK);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_ERROR_PARAM);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_code_valid_post_jwt_nested_secret)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/auth", 0, &callback_oauth2_code_valid_post_jwt_nested, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_CLIENT_ENC_ALG, "A128GCMKW",
                                                    I_OPT_CLIENT_ENC, "A128CBC-HS256",
                                                    I_OPT_CLIENT_SIGN_ALG, "HS256",
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_AUTH_METHOD, I_AUTH_METHOD_POST|I_AUTH_METHOD_JWT_ENCRYPT_SECRET|I_AUTH_METHOD_JWT_SIGN_SECRET,
                                                    I_OPT_NONE), I_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_code_valid_post_jwt_nested_pubkey)
{
  struct _i_session i_session;
  struct _u_instance instance;
  jwk_t * jwk;
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/auth", 0, &callback_oauth2_code_valid_post_jwt_nested, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_ENC_ALG, "RSA1_5",
                                                    I_OPT_CLIENT_ENC, "A128CBC-HS256",
                                                    I_OPT_CLIENT_SIGN_ALG, "RS256",
                                                    I_OPT_REDIRECT_URI, REDIRECT_URI,
                                                    I_OPT_SCOPE, SCOPE_LIST,
                                                    I_OPT_AUTH_ENDPOINT, AUTH_ENDPOINT,
                                                    I_OPT_STATE, STATE,
                                                    I_OPT_AUTH_METHOD, I_AUTH_METHOD_POST|I_AUTH_METHOD_JWT_ENCRYPT_PUBKEY|I_AUTH_METHOD_JWT_SIGN_PRIVKEY,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  ck_assert_int_eq(i_run_auth_request(&i_session), I_OK);
  ck_assert_ptr_ne(i_get_str_parameter(&i_session, I_OPT_CODE), NULL);
  
  r_jwk_free(jwk);
  i_clean_session(&i_session);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

static Suite *iddawc_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Iddawc oauth2 flow tests");
  tc_core = tcase_create("test_iddawc_oauth2");
  tcase_add_test(tc_core, test_iddawc_unauthorized_public_client);
  tcase_add_test(tc_core, test_iddawc_invalid_client_secret);
  tcase_add_test(tc_core, test_iddawc_scope_empty);
  tcase_add_test(tc_core, test_iddawc_invalid_response_type);
  tcase_add_test(tc_core, test_iddawc_invalid_state);
  tcase_add_test(tc_core, test_iddawc_code_empty);
  tcase_add_test(tc_core, test_iddawc_access_token_empty);
  tcase_add_test(tc_core, test_iddawc_token_type_empty);
  tcase_add_test(tc_core, test_iddawc_expires_in_invalid);
  tcase_add_test(tc_core, test_iddawc_redirect_external_auth);
  tcase_add_test(tc_core, test_iddawc_code_valid);
  tcase_add_test(tc_core, test_iddawc_access_token_valid);
  tcase_add_test(tc_core, test_iddawc_id_token_valid);
  tcase_add_test(tc_core, test_iddawc_access_token_id_token_valid);
  tcase_add_test(tc_core, test_iddawc_access_token_code_valid);
  tcase_add_test(tc_core, test_iddawc_access_token_code_id_token_valid);
  tcase_add_test(tc_core, test_iddawc_code_valid_post);
  tcase_add_test(tc_core, test_iddawc_parse_redirect_to_code_ok);
  tcase_add_test(tc_core, test_iddawc_parse_redirect_to_access_token_ok);
  tcase_add_test(tc_core, test_iddawc_parse_redirect_to_error_ok);
  tcase_add_test(tc_core, test_iddawc_parse_redirect_to_code_error_state);
  tcase_add_test(tc_core, test_iddawc_parse_redirect_to_access_token_error_state);
  tcase_add_test(tc_core, test_iddawc_parse_redirect_to_access_token_error_token_type);
  tcase_add_test(tc_core, test_iddawc_parse_redirect_to_access_token_error_expires_in);
  tcase_add_test(tc_core, test_iddawc_code_valid_post_jwt_sign_secret_error_param);
  tcase_add_test(tc_core, test_iddawc_code_valid_post_jwt_sign_privkey_error_param);
  tcase_add_test(tc_core, test_iddawc_code_valid_post_jwt_encrypt_secret_error_param);
  tcase_add_test(tc_core, test_iddawc_code_valid_post_jwt_encrypt_pubkey_error_param);
  tcase_add_test(tc_core, test_iddawc_code_valid_post_jwt_sign_secret);
  tcase_add_test(tc_core, test_iddawc_code_valid_post_jwt_sign_privkey);
  tcase_add_test(tc_core, test_iddawc_code_valid_post_jwt_encrypt_secret);
  tcase_add_test(tc_core, test_iddawc_code_valid_post_jwt_encrypt_pubkey);
  tcase_add_test(tc_core, test_iddawc_code_valid_post_jwt_nested_secret);
  tcase_add_test(tc_core, test_iddawc_code_valid_post_jwt_nested_pubkey);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc OAuth2 implicit flow tests");
  s = iddawc_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  //y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
