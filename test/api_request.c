/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <jansson.h>
#include <check.h>
#include <yder.h>
#include <iddawc.h>

const char jwk_privkey_str[] = "{\"kty\":\"RSA\",\"n\":\"ANgV1GxZbGBMIqqX5QsNrQQnPLk8UpkqH_60EuaHsI8YnUkPmPVXJ_4z_ziqZizvvjp_RhhXX2DnHEQuYwI-SZaBlK1VJiiWH9E"\
                                "XrUeazcpEryFUR0I5iBROcgRJfHSvRvC7D83-xg9xC-NGVvIQ2llduYzmaK8rfuiHWlGqow3O2m5os9NTortdQf7BeTniStDokFvZy-I4i24UFkemoNPWZ9MCN0"\
                                "WTea8n_TQmq9sVHGQtLIFqfblLxbSz_7m4g7_o3WfqlwXkVmCIu1wdzAjZV5BspBGrL0ed5Whpk9-bX69nUDvpcMAaPhuRwZ43e9koVRbVwXCNkne98VAs0_U\""\
                                ",\"e\":\"AQAB\",\"d\":\"AKOVsyDreb5VJRFcuIrrqYWxZqkc37MQTvR1wrE_HAzYp4n-AuAJQT-Sga6WYY-3V53VaG1ZB93GWIHNVCsImJEWPEYUZjTnoeK"\
                                "bOBUzPoPYB3UF5oReJYSp9msEbvGvF9d65fYe4DYkcMl4IK5Uz9hDugrPC4VBOmwyu8-DjLkP8OH-N2-KhJvX_kLKgivfzD3KOp6wryLnKuZYn8N4E6rCiNSfKM"\
                                "goM60bSHRNi0QHYB2jwqMU5T5EzdpD3Tu_ow6a-sXrW6SG1dtbuStck9hFcQ-QtRCeWoM5pFN8cKOsWBZd1unq-X3gMlCjdXUBUW7BYP44lpYsg1v9l_Ww64E\""\
                                ",\"p\":\"ANmlFUVM-836aC-wK-DekE3s3gl7GZ-9Qca8iKnaIeMszgyaLYkkbYNPpjjsiQHc37IG3axCaywK40PZqODzovL5PnUpwfNrnlMaI042rNaf8q1L4k"\
                                "vaBTkbO9Wbj0sTLMPt1frLQKBRsNDsYamRcL1SwvTC4aI7cgZBrNIBdPiR\",\"q\":\"AP4qYxRNGaI3aeZh5hgKPSGW82X8Ai2MzIKjzSDYmKGcD9HPRV0dAU"\
                                "mDCvqyjwCD6tL9iMtZKPz7VK66-KvV1n91WLMDtRzWs_eFFyDY7BYw47o6IQoZ2RxBT3-7WLhlFflaEner8k23zpGOjZbyzt0SIWRAYR0zlb7LrS_X4fcl\",\""\
                                "qi\":\"fnlvhYXAn6V0X6gmlwooZUWo9bR7ObChNhrUzMVDOReUVOrzOhlzGhBW1TEFBBr8k44ZWBCTeVEQh--LFHwVvCgEjDBxfjUPUMkeyKZzLhpIUB_cFBAg"\
                                "I7Fyy0yuPpY0mS1PfMt5Y4b6g_JvdBWZZ8VhTcCVG7qDqoH_IJMXPNg\",\"dp\":\"EAsiQUSGf02JJpLG-UGOw5_FUk-XuPW7honZTSP-QX_JBJbM6oIb7IUP"\
                                "jLyq8M82Uio9ZvhSbCG1VQgTcdmj1mNXHk3gtS_msNuJZLeVEBEkU2_3k33TyrzeMUXRT0hvkVXT4zPeZLMA5LW4EUbeV6ZlJqPC_DGDm0B2G9jtpXE\",\"dq"\
                                "\":\"AMTictPUEcpOILO9HG985vPxKeTTfaBpVDbSymDqR_nQmZSOeg3yHQAkCco_rXTZu3rruR7El3K5AlVEMsNxp3IepbIuagrH6qsPpuXkA6YBAzdMNjHL6h"\
                                "nwIbQxnT1h2M7KzklzogRAIT0x706CEmq_06wEDvZ-8j3VKvhHxBwd\",\"kid\":\"1\"}";

#define CLIENT_ID "clientXyz1234"
#define CLIENT_SECRET "secretXyx1234"
#define DPOP_HTM "POST"
#define DPOP_HTU "http://localhost:8080/object"
#define DPOP_HTU_QUERY "?query=true&params=yes"
#define DPOP_HTU_HASH "#token=myToken&code=myCode"
#define TOKEN_ENDPOINT "http://localhost:8080/token"
#define REFRESH_TOKEN "refreshXyz1234"
#define ACCESS_TOKEN "accessXyz1234"
#define ACCESS_TOKEN_2 "accessXyz5678"
#define TOKEN_TYPE "bearer"
#define EXPIRES_IN 3600
#define DPOP_NONCE "dpopNonceXyz1234"


const char resource_object[] = "{\"Hello\":\"World\"}";

static int callback_resource_service_object_at_header (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_response = json_loads(resource_object, JSON_DECODE_ANY, NULL);
  if (u_map_get(request->map_header, I_HEADER_AUTHORIZATION) != NULL) {
    ulfius_set_json_body_response(response, 200, j_response);
  } else {
    response->status = 401;
  }
  json_decref(j_response);
  return U_CALLBACK_CONTINUE;
}

static int callback_resource_service_object_at_body (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_response = json_loads(resource_object, JSON_DECODE_ANY, NULL);
  if (u_map_get(request->map_post_body, I_BODY_URL_PARAMETER) != NULL) {
    ulfius_set_json_body_response(response, 200, j_response);
  } else {
    response->status = 401;
  }
  json_decref(j_response);
  return U_CALLBACK_CONTINUE;
}

static int callback_resource_service_object_at_url (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_response = json_loads(resource_object, JSON_DECODE_ANY, NULL);
  if (u_map_get(request->map_url, I_BODY_URL_PARAMETER) != NULL) {
    ulfius_set_json_body_response(response, 200, j_response);
  } else {
    response->status = 401;
  }
  json_decref(j_response);
  return U_CALLBACK_CONTINUE;
}

int callback_resource_service_object_with_dpop (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_response = json_loads(resource_object, JSON_DECODE_ANY, NULL);
  jwt_t * jwt;
  
  if (0 == o_strcmp("DPoP "ACCESS_TOKEN, u_map_get(request->map_header, "Authorization")) && u_map_get(request->map_header, "DPoP") != NULL) {
    jwt = r_jwt_quick_parse(u_map_get(request->map_header, "DPoP"), R_PARSE_HEADER_JWK, 0);
    if (0 == o_strcmp(DPOP_HTU, r_jwt_get_claim_str_value(jwt, "htu"))) {
      ulfius_set_json_body_response(response, 200, j_response);
    } else {
      response->status = 401;
    }
    r_jwt_free(jwt);
  } else {
    response->status = 401;
  }
  json_decref(j_response);
  return U_CALLBACK_CONTINUE;
}

int callback_resource_service_object_with_dpop_nonce (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_response = json_loads(resource_object, JSON_DECODE_ANY, NULL);
  if (0 == o_strcmp("DPoP "ACCESS_TOKEN, u_map_get(request->map_header, "Authorization")) && u_map_get(request->map_header, "DPoP") != NULL) {
    jwt_t * jwt = r_jwt_quick_parse(u_map_get(request->map_header, I_HEADER_DPOP), R_PARSE_HEADER_JWK, 0);
    if (0 != o_strcmp(DPOP_NONCE, r_jwt_get_claim_str_value(jwt, "nonce"))) {
      ulfius_set_response_properties(response, U_OPT_STATUS, 401,
                                               U_OPT_HEADER_PARAMETER, "DPoP-Nonce", DPOP_NONCE,
                                               U_OPT_NONE);
    } else {
      ulfius_set_json_body_response(response, 200, j_response);
    }
    r_jwt_free(jwt);
  } else {
    response->status = 401;
  }
  json_decref(j_response);
  return U_CALLBACK_CONTINUE;
}

static int callback_refresh_token_invalid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  response->status = 403;
  return U_CALLBACK_CONTINUE;
}

static int callback_refresh_token_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * result = json_pack("{sssssi}", 
                             "access_token", ACCESS_TOKEN_2,
                             "token_type", TOKEN_TYPE,
                             "expires_in", EXPIRES_IN);
  ulfius_set_json_body_response(response, 200, result);
  json_decref(result);
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_iddawc_api_request_invalid_parameters)
{
  struct _i_session i_session;
  struct _u_request req;
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_request(&req), I_OK);
  ck_assert_int_eq(i_perform_resource_service_request(NULL, &req, NULL, 0, I_BEARER_TYPE_HEADER, 0, 0), I_ERROR_PARAM);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, NULL, NULL, 0, I_BEARER_TYPE_HEADER, 0, 0), I_ERROR_PARAM);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, NULL, 0, 42, 0, 0), I_ERROR_PARAM);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, NULL, 0, I_BEARER_TYPE_HEADER, 0, 0), I_ERROR_PARAM); // No access token
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, NULL, 0, I_BEARER_TYPE_HEADER, 1, 0), I_ERROR); // No jti
  ulfius_clean_request(&req);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_api_request_invalid_response_size_header)
{
  struct _i_session i_session;
  struct _u_request req;
  struct _u_response resp;
  struct _u_instance instance;

  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, DPOP_HTM, NULL, "/object", 0, &callback_resource_service_object_at_header, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_request(&req), I_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_RESPONSE_MAX_BODY_SIZE, 8,
                                                    I_OPT_RESPONSE_MAX_HEADER_COUNT, 2,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, DPOP_HTM, U_OPT_HTTP_URL, DPOP_HTU, U_OPT_NONE), U_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 0, I_BEARER_TYPE_HEADER, 0, 0), I_OK);
  ck_assert_int_eq(2, u_map_count(resp.map_header));
  ck_assert_int_eq(8, resp.binary_body_length);

  i_clean_session(&i_session);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_api_request_no_refresh_no_dpop)
{
  struct _i_session i_session;
  struct _u_request req;
  struct _u_response resp;
  struct _u_instance instance;
  json_t * j_resp, * j_control;

  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, DPOP_HTM, NULL, "/object", 0, &callback_resource_service_object_at_header, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_request(&req), I_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, DPOP_HTM, U_OPT_HTTP_URL, DPOP_HTU, U_OPT_NONE), U_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 0, I_BEARER_TYPE_HEADER, 0, 0), I_OK);
  ck_assert_ptr_ne(NULL, j_control = json_loads(resource_object, JSON_DECODE_ANY, NULL));
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(1, json_equal(j_control, j_resp));

  i_clean_session(&i_session);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  json_decref(j_control);
  json_decref(j_resp);
}
END_TEST

START_TEST(test_iddawc_api_request_refresh_not_required_no_dpop)
{
  struct _i_session i_session;
  struct _u_request req;
  struct _u_response resp;
  struct _u_instance instance;
  json_t * j_resp, * j_control;

  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, DPOP_HTM, NULL, "/object", 0, &callback_resource_service_object_at_header, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_request(&req), I_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_EXPIRES_IN, EXPIRES_IN,
                                                    I_OPT_EXPIRES_AT, ((unsigned int)time(NULL))+EXPIRES_IN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, DPOP_HTM, U_OPT_HTTP_URL, DPOP_HTU, U_OPT_NONE), U_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 1, I_BEARER_TYPE_HEADER, 0, 0), I_OK);
  ck_assert_ptr_ne(NULL, j_control = json_loads(resource_object, JSON_DECODE_ANY, NULL));
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(1, json_equal(j_control, j_resp));

  i_clean_session(&i_session);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  json_decref(j_control);
  json_decref(j_resp);
}
END_TEST

START_TEST(test_iddawc_api_request_refresh_required_not_available_no_dpop)
{
  struct _i_session i_session;
  struct _u_request req;
  struct _u_response resp;
  struct _u_instance instance;

  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, DPOP_HTM, NULL, "/object", 0, &callback_resource_service_object_at_header, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_refresh_token_invalid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_request(&req), I_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);
  
  // AT expired, no params to refresh
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_EXPIRES_IN, EXPIRES_IN,
                                                    I_OPT_EXPIRES_AT, ((unsigned int)time(NULL))-1,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, DPOP_HTM, U_OPT_HTTP_URL, DPOP_HTU, U_OPT_NONE), U_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 1, I_BEARER_TYPE_HEADER, 0, 0), I_ERROR_PARAM);
  
  // Set refresh params
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_REFRESH_TOKEN, REFRESH_TOKEN,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, DPOP_HTM, U_OPT_HTTP_URL, DPOP_HTU, U_OPT_NONE), U_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 1, I_BEARER_TYPE_HEADER, 0, 0), I_ERROR_PARAM);

  i_clean_session(&i_session);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_api_request_refresh_required_ok_no_dpop)
{
  struct _i_session i_session;
  struct _u_request req;
  struct _u_response resp;
  struct _u_instance instance;

  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, DPOP_HTM, NULL, "/object", 0, &callback_resource_service_object_at_header, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/token", 0, &callback_refresh_token_valid, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_request(&req), I_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);
  
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_EXPIRES_IN, EXPIRES_IN,
                                                    I_OPT_EXPIRES_AT, ((unsigned int)time(NULL))-1,
                                                    I_OPT_REFRESH_TOKEN, REFRESH_TOKEN,
                                                    I_OPT_CLIENT_ID, CLIENT_ID,
                                                    I_OPT_CLIENT_SECRET, CLIENT_SECRET,
                                                    I_OPT_TOKEN_ENDPOINT, TOKEN_ENDPOINT,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, DPOP_HTM, U_OPT_HTTP_URL, DPOP_HTU, U_OPT_NONE), U_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 1, I_BEARER_TYPE_HEADER, 0, 0), I_OK);
  
  i_clean_session(&i_session);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_api_request_refresh_not_required_dpop_required)
{
  struct _i_session i_session;
  struct _u_request req;
  struct _u_response resp;
  struct _u_instance instance;
  jwk_t * jwk;
  json_t * j_resp, * j_control;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, DPOP_HTM, NULL, "/object", 0, &callback_resource_service_object_with_dpop, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_request(&req), I_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_EXPIRES_IN, EXPIRES_IN,
                                                    I_OPT_EXPIRES_AT, ((unsigned int)time(NULL))+EXPIRES_IN,
                                                    I_OPT_DPOP_SIGN_ALG, "RS256",
                                                    I_OPT_TOKEN_JTI_GENERATE, 16,
                                                    I_OPT_NONE), I_OK);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, DPOP_HTM, U_OPT_HTTP_URL, DPOP_HTU, U_OPT_NONE), U_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 0, I_BEARER_TYPE_HEADER, 1, 0), I_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_control = json_loads(resource_object, JSON_DECODE_ANY, NULL));
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(1, json_equal(j_control, j_resp));
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 0, I_BEARER_TYPE_HEADER, 0, 0), I_OK);
  ck_assert_int_eq(401, resp.status);

  i_clean_session(&i_session);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  json_decref(j_control);
  json_decref(j_resp);
}
END_TEST

START_TEST(test_iddawc_api_request_with_query_and_dpop)
{
  struct _i_session i_session;
  struct _u_request req;
  struct _u_response resp;
  struct _u_instance instance;
  jwk_t * jwk;
  json_t * j_resp, * j_control;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, DPOP_HTM, NULL, "/object", 0, &callback_resource_service_object_with_dpop, NULL), U_OK);
  ck_assert_int_eq(ulfius_set_default_endpoint(&instance, &callback_resource_service_object_with_dpop, NULL), U_OK); // Apparently Debian buster doesn't like url DPOP_HTU DPOP_HTU_HASH DPOP_HTU_QUERY
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_request(&req), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_EXPIRES_IN, EXPIRES_IN,
                                                    I_OPT_EXPIRES_AT, ((unsigned int)time(NULL))+EXPIRES_IN,
                                                    I_OPT_DPOP_SIGN_ALG, "RS256",
                                                    I_OPT_TOKEN_JTI_GENERATE, 16,
                                                    I_OPT_NONE), I_OK);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);

  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, DPOP_HTM, U_OPT_HTTP_URL, DPOP_HTU DPOP_HTU_QUERY, U_OPT_NONE), U_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 0, I_BEARER_TYPE_HEADER, 1, 0), I_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_control = json_loads(resource_object, JSON_DECODE_ANY, NULL));
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(1, json_equal(j_control, j_resp));
  ulfius_clean_response(&resp);
  json_decref(j_control);
  json_decref(j_resp);

  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, DPOP_HTM, U_OPT_HTTP_URL, DPOP_HTU DPOP_HTU_HASH, U_OPT_NONE), U_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 0, I_BEARER_TYPE_HEADER, 1, 0), I_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_control = json_loads(resource_object, JSON_DECODE_ANY, NULL));
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(1, json_equal(j_control, j_resp));
  ulfius_clean_response(&resp);
  json_decref(j_control);
  json_decref(j_resp);

  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, DPOP_HTM, U_OPT_HTTP_URL, DPOP_HTU DPOP_HTU_QUERY DPOP_HTU_HASH, U_OPT_NONE), U_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 0, I_BEARER_TYPE_HEADER, 1, 0), I_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_control = json_loads(resource_object, JSON_DECODE_ANY, NULL));
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(1, json_equal(j_control, j_resp));
  ulfius_clean_response(&resp);
  json_decref(j_control);
  json_decref(j_resp);

  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, DPOP_HTM, U_OPT_HTTP_URL, DPOP_HTU DPOP_HTU_HASH DPOP_HTU_QUERY, U_OPT_NONE), U_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 0, I_BEARER_TYPE_HEADER, 1, 0), I_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_control = json_loads(resource_object, JSON_DECODE_ANY, NULL));
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(1, json_equal(j_control, j_resp));
  ulfius_clean_response(&resp);
  json_decref(j_control);
  json_decref(j_resp);

  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  i_clean_session(&i_session);
  ulfius_clean_request(&req);
}
END_TEST

START_TEST(test_iddawc_api_request_refresh_not_required_dpop_required_nonce)
{
  struct _i_session i_session;
  struct _u_request req;
  struct _u_response resp;
  struct _u_instance instance;
  jwk_t * jwk;
  json_t * j_resp, * j_control;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, DPOP_HTM, NULL, "/object", 0, &callback_resource_service_object_with_dpop_nonce, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_request(&req), I_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_EXPIRES_IN, EXPIRES_IN,
                                                    I_OPT_EXPIRES_AT, ((unsigned int)time(NULL))+EXPIRES_IN,
                                                    I_OPT_DPOP_SIGN_ALG, "RS256",
                                                    I_OPT_TOKEN_JTI_GENERATE, 16,
                                                    I_OPT_NONE), I_OK);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, DPOP_HTM, U_OPT_HTTP_URL, DPOP_HTU, U_OPT_NONE), U_OK);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_DPOP_NONCE_RS));
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 0, I_BEARER_TYPE_HEADER, 1, 0), I_OK);
  ck_assert_ptr_ne(NULL, i_get_str_parameter(&i_session, I_OPT_DPOP_NONCE_RS));
  ck_assert_int_eq(401, resp.status);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 0, I_BEARER_TYPE_HEADER, 1, 0), I_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_control = json_loads(resource_object, JSON_DECODE_ANY, NULL));
  ck_assert_ptr_ne(NULL, j_resp = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(1, json_equal(j_control, j_resp));

  i_clean_session(&i_session);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  json_decref(j_control);
  json_decref(j_resp);
}
END_TEST

START_TEST(test_iddawc_api_request_test_bearer_type)
{
  struct _i_session i_session;
  struct _u_request req;
  struct _u_response resp;
  struct _u_instance instance;

  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, DPOP_HTM, NULL, "/object", 0, &callback_resource_service_object_at_header, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(ulfius_init_request(&req), I_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, DPOP_HTM, U_OPT_HTTP_URL, DPOP_HTU, U_OPT_NONE), U_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 0, I_BEARER_TYPE_HEADER, 0, 0), I_OK);
  ck_assert_int_eq(200, resp.status);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 0, I_BEARER_TYPE_BODY, 0, 0), I_OK);
  ck_assert_int_eq(401, resp.status);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 0, I_BEARER_TYPE_URL, 0, 0), I_OK);
  ck_assert_int_eq(401, resp.status);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);
  
  ck_assert_int_eq(ulfius_remove_endpoint_by_val(&instance, DPOP_HTM, NULL, "/object"), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, DPOP_HTM, NULL, "/object", 0, &callback_resource_service_object_at_body, NULL), U_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 0, I_BEARER_TYPE_HEADER, 0, 0), I_OK);
  ck_assert_int_eq(401, resp.status);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 0, I_BEARER_TYPE_BODY, 0, 0), I_OK);
  ck_assert_int_eq(200, resp.status);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 0, I_BEARER_TYPE_URL, 0, 0), I_OK);
  ck_assert_int_eq(401, resp.status);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);

  ck_assert_int_eq(ulfius_remove_endpoint_by_val(&instance, DPOP_HTM, NULL, "/object"), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, DPOP_HTM, NULL, "/object", 0, &callback_resource_service_object_at_url, NULL), U_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 0, I_BEARER_TYPE_HEADER, 0, 0), I_OK);
  ck_assert_int_eq(401, resp.status);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 0, I_BEARER_TYPE_BODY, 0, 0), I_OK);
  ck_assert_int_eq(401, resp.status);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(ulfius_init_response(&resp), I_OK);
  ck_assert_int_eq(i_perform_resource_service_request(&i_session, &req, &resp, 0, I_BEARER_TYPE_URL, 0, 0), I_OK);
  ck_assert_int_eq(200, resp.status);

  i_clean_session(&i_session);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

static Suite *iddawc_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Iddawc API request tests");
  tc_core = tcase_create("test_iddawc_api_request");
  tcase_add_test(tc_core, test_iddawc_api_request_invalid_parameters);
  tcase_add_test(tc_core, test_iddawc_api_request_invalid_response_size_header);
  tcase_add_test(tc_core, test_iddawc_api_request_no_refresh_no_dpop);
  tcase_add_test(tc_core, test_iddawc_api_request_refresh_not_required_no_dpop);
  tcase_add_test(tc_core, test_iddawc_api_request_refresh_required_not_available_no_dpop);
  tcase_add_test(tc_core, test_iddawc_api_request_refresh_required_ok_no_dpop);
  tcase_add_test(tc_core, test_iddawc_api_request_refresh_not_required_dpop_required);
  tcase_add_test(tc_core, test_iddawc_api_request_with_query_and_dpop);
  tcase_add_test(tc_core, test_iddawc_api_request_refresh_not_required_dpop_required_nonce);
  tcase_add_test(tc_core, test_iddawc_api_request_test_bearer_type);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc API request tests");
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
