/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <jansson.h>
#include <check.h>
#include <yder.h>
#include <iddawc.h>

#define TOKEN "accessTokenXyz1234"

const char result[] = "{\"active\":true,\"client_id\":\"l238j323ds-23ij4\",\"username\":\"jdoe\",\"scope\":\"read write dolphin\",\"sub\":\"Z5O3upPC88QrAjx00dis\",\"aud\":\"https://protected.example.net/resource\",\"iss\":\"https://server.example.com/\",\"exp\":1419356238,\"iat\":1419350238,\"extension_field\":\"twenty-seven\"}";

const char jwk_privkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"ALrIdhuABv82Y7K1-LJCXRy1LVdmK9IAHwmmlI-HnOrFeEsSwuCeblUgEpqz_mj7lLtZN0Gnlz-7U0hOpGCeOYXRMn8184YismuCS5PYe"
                                   "0Jfot0kMumF2IOBV94AGBSeWQcK8J-Ed3X-rkR9vovv8gXhKyRDQH4mon_cPwtdCi2PScnRlkvlOjYkib9m0QQqpvjmcd02s8BYtakRVRva2mQT_dCvRYvM4Tb5yvvRM7I"
                                   "z3Ni6Jj-IOUZvaZtRW_2HPvhho6Pj_XuYDVHHWyi8SWXtvMQehOtiv9cNecOcvtvEN7YLf2sTM9nIBxOmkRF6k2wvmxwMeoqQZ-pZuvVQkn2opKHLFZlL5BTmPWnGIwmmi"
                                   "oxIRaDmc1KApufOw2voHqCSJR99UMwIyJpIulFqBw_F2y2vS-uXDODA3PmG1u1qpN2mqjvbHz1PwKYucPQH1GoMMRKeEPsjKamLLpftn_GgWUk17ti2-xAtYG8XEFsv4hz"
                                   "CWipx0zh4S0aVRLoomN9AisHTCWpOgdg1kFj3ECrKxhYMETWGUTKrItAOhE1VuyOenIPMN8ZEeWfqPdUnrRYtRN0ce7WCYulkDynavFJK_13NpJ7d-44ns_F2r2Bl9K6bY"
                                   "xK8W4d2Q9soCtfsb6eOabtuP-5yWuvPxn9gt6xgbIMEc643k__Lx2_ct6fT\",\"e\":\"AQAB\",\"d\":\"MZrdaw5ETXEnZyXWx5jCW8ZuJUD4MExh8dEwsTGl5d_Nw"
                                   "7pW0QqiaK8c4cMdtMnjxSG7gA8_JujcBF8GXraGtlhJnek5JI2AbvbqlXgvu__kI_DiKIyoZLxsFoRV4Nvw7uLj5qlqhIa_x2bRvR5bW15ic738mcQu8eAPSjhKZLEiOpw"
                                   "T21IkdI6dmpx2tDGTqJSi9sn5UQL-M8lrnfswdtWsWcjCoo8l3NDYLKpxnUkSxOgjEkpeU6txE5O2540MlzBvIi6Belp2ZxqXxijDIXPS5w7n5A-UvUtR5DZzpa_lz84b5"
                                   "9bwtUzfPEPHUSoJjvjRq9BQlw4k2uM7uLzOOmbrIQRbH8byc7Z9DUDK6zRaEW85xVKaXuM7bqcolUuNsHHGGzPGf5pkPYvMV7qACipy9Ksuo8iAGtoZPRan6dO_TfrP0oe"
                                   "eowtmg-6S2--lRPjKAHfhPRwqxKp9WKUdEKu1T9TxHOLkWoOJERRBaE7U7RI8kHO3BIaDxPkBzR47llNPr7ufJ0XZQsKx5kSfdNwJfJ_2kNErEe2neKswaIQ9UwTebYYAk"
                                   "glvaAs85AdP7-g0VLhF51fipK8Y-9g-hY4VITsEvmxQtS7tRKOgzKOY4PqHRpeB2CTJ4Dvj8JPAfbgWBnXpgh-nrq-37HVr1FLCDkFPqyDIzMur_NxRwSk\",\"p\":\"A"
                                   "NXj3t1HDn8OEo_QECNUm1Ie1-xl482FDYvca74igmfVyj017jNwlyl-HlOYYFp9O-hxXF6XLCKtUDk0h_acVOnFeKhYRZCSRlZzGrVjtIX8UtrVkosMxPfqIywl-V5TMLG"
                                   "JhdihNhYm02mdXsGk_ksiPXzmjKUxjwPc--kNgZ1rECeFSNCVQDMLHZ0V-W3MVwpxJKU1bc-BpU5hxvANqIfEzgUNpGLet80FAZaHKyWtYzXhRiIggHkJi7K8UjDhraZGH"
                                   "wPnfhyAIOAplPfA7zYuB0DIYHshKIQgDWTZ7IVTgzs9B_9OS31FUhXTrcSlNqL-RsE_dxMpPEZLUqOgl08\",\"q\":\"AN-OYtTrB8qNhC80CQV7jJD4pMsFwHmOCihl6"
                                   "QBjEj3NfhMP3DtGVhIcX84ZG91QA4NSj9iXswJa9KWpbSNBEzS9bA1AitM0P54_4_jbM9nIX3gXMMwzIbBYrcGuzsvuoz1p4nvWuGHFQhsA9mXiumQ1jj1_7pLopCbl_w9"
                                   "eVCafMB2vC55ZloIe5V5L6Ot6I2PenmVEZ4Kgf6DzexHyCXlgYNWP1nKgpE0aRjHAtL3xiBqct-a2HF-kwMH2tbLKmWW3pvNsPWgrsy3h4f2unk5kLCKxn_15gSm8xV4Nr"
                                   "54ai-ShQc_QYVr8tXXl_Y2nU9ubUQaA4khhU77G_KOsRj0\",\"qi\":\"ALp3wGNfSv7Ns-S3NlqZB68b4AeykPL59CybNKuaUQkAHkuEfpCaG2lAjeVPrA9UFSio2wKu"
                                   "255cwDOTcOkBPhuFeLlegchpWW4tTTyUu1sUYrqUIwhIGxoms4at9sXo3jbtUMe8R4iakfKaGk84ANL_s50uQoCHLevzKalTfItOT5J_7oQYtSZFCxFcZ8w4wDnBLhP4J8"
                                   "aFw_wHJZuH9dGGiOeAiJnr4wWWkRuuhHmfsgXxev27NI-dK11-vDaxxgLsCTbltN1_1EuU5bOwO-IUpYOqV3AqfBMfYr8cNgPGAP5dUxWkMV5VCR2efsIBHBmjvVuJv8aZ"
                                   "rKsLvqrmRx4\",\"dp\":\"PaCpfzJRD_S7DmrRq4xeMFwotLlq2LWkgI7jEGabElX8LoTSfEnNlCv9ivKVmJ0K3N-E0NBX7CnpuoHTRxAmOzElocPFT3GGCLSjlm4C_rQ"
                                   "EH393-M6WFiSFO9w5LJ9loVHRmehhUCKhuYWZXswuZPGZq9o13gcYgPF0N-MnXHcTsX9qyoamd86VGsTRGHzO-3g8KcnqOObO_XWYv2QAEhZ3kecrXT100gLGQVvy56k8s"
                                   "7KT5ZNd0QIaGUa_m8v6n7UGjLZvlMCqOExi2rvhcMf0WQsjGXclWGRv14Ye6w9z-WaNXldt0stdamKSZ91-j5oaQuYJZiD0eACN8A1-aw\",\"dq\":\"BKxbUIwhO5C9x"
                                   "KbX0W-FvroT59KU9XWMrM-EkWeAyB31lrxsJCkSP4qsTgikVnoHuMUPEL4LFe-E0bm6-FOx7RZQne5NeKDM-6fmQhuC9_iCVmZVtM8U0zTnXPckh4rTisMd4uzYKeMPwLT"
                                   "CcdrNfq7H7G0yNYv7cny4Wj_kjnIhdV1lZsgEp2-x58i6c8G336yVrxRA_bAROvIcDoH6xLjJDW3WU8sb5Ci6cuvOW3IjIDtKdN41taIiDWv03GnzzvaJ3OjUV8siEcF5E"
                                   "e6GjKj3azo_V_MkShUSIycyFqIDbqIYWBnJDzfdKzvFkyJ-VEbo6LPlBxJRx9ktCtbdGQ\",\"kid\":\"1\",\"alg\":\"RS256\"}";

int callback_introspect (const struct _u_request * request, struct _u_response * response, void * user_data) {
  if (0 == o_strcmp("Bearer "TOKEN, u_map_get(request->map_header, "Authorization"))) {
    if (0 == o_strcmp(TOKEN, u_map_get(request->map_post_body, "token"))) {
      json_t * j_response = json_loads(result, JSON_DECODE_ANY, NULL);
      ulfius_set_json_body_response(response, 200, j_response);
      json_decref(j_response);
    } else {
      json_t * j_response = json_loads("{\"active\":false}", JSON_DECODE_ANY, NULL);
      ulfius_set_json_body_response(response, 200, j_response);
      json_decref(j_response);
    }
  } else {
    response->status = 403;
  }
  return U_CALLBACK_CONTINUE;
}

int callback_introspect_dpop (const struct _u_request * request, struct _u_response * response, void * user_data) {
  if (0 == o_strcmp("Bearer "TOKEN, u_map_get(request->map_header, "Authorization")) && u_map_get(request->map_header, I_HEADER_DPOP) != NULL) {
    if (0 == o_strcmp(TOKEN, u_map_get(request->map_post_body, "token"))) {
      json_t * j_response = json_loads(result, JSON_DECODE_ANY, NULL);
      ulfius_set_json_body_response(response, 200, j_response);
      json_decref(j_response);
    } else {
      json_t * j_response = json_loads("{\"active\":false}", JSON_DECODE_ANY, NULL);
      ulfius_set_json_body_response(response, 200, j_response);
      json_decref(j_response);
    }
  } else {
    response->status = 403;
  }
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_iddawc_introspection_invalid)
{
  struct _i_session i_session;
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_get_token_introspection(&i_session, NULL, I_INTROSPECT_REVOKE_AUTH_ACCESS_TOKEN, 0), I_ERROR_PARAM);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_INTROSPECTION_ENDPOINT, "http://localhost:8080/introspect"), I_OK);
  ck_assert_int_eq(i_get_token_introspection(&i_session, NULL, I_INTROSPECT_REVOKE_AUTH_ACCESS_TOKEN, 0), I_ERROR_PARAM);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_INTROSPECTION_ENDPOINT, NULL), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_TOKEN_TARGET, TOKEN), I_OK);
  ck_assert_int_eq(i_get_token_introspection(&i_session, NULL, I_INTROSPECT_REVOKE_AUTH_ACCESS_TOKEN, 0), I_ERROR_PARAM);
  
  i_clean_session(&i_session);
  
}
END_TEST

START_TEST(test_iddawc_introspection_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  json_t * j_result = NULL, * j_expected;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/introspect", 0, &callback_introspect, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_INTROSPECTION_ENDPOINT, "http://localhost:8080/introspect",
                                                  I_OPT_ACCESS_TOKEN, TOKEN,
                                                  I_OPT_TOKEN_TARGET, TOKEN,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_get_token_introspection(&i_session, &j_result, I_INTROSPECT_REVOKE_AUTH_ACCESS_TOKEN, 0), I_OK);
  j_expected = json_loads(result, JSON_DECODE_ANY, NULL);
  ck_assert_int_eq(1, json_equal(j_expected, j_result));
  i_clean_session(&i_session);
  json_decref(j_result);
  json_decref(j_expected);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_INTROSPECTION_ENDPOINT, "http://localhost:8080/introspect",
                                                  I_OPT_ACCESS_TOKEN, TOKEN,
                                                  I_OPT_TOKEN_TARGET, TOKEN "error",
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_get_token_introspection(&i_session, &j_result, I_INTROSPECT_REVOKE_AUTH_ACCESS_TOKEN, 0), I_OK);
  j_expected = json_loads("{\"active\":false}", JSON_DECODE_ANY, NULL);
  ck_assert_int_eq(1, json_equal(j_expected, j_result));
  i_clean_session(&i_session);
  json_decref(j_result);
  json_decref(j_expected);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_INTROSPECTION_ENDPOINT, "http://localhost:8080/introspect",
                                                  I_OPT_ACCESS_TOKEN, TOKEN "error",
                                                  I_OPT_TOKEN_TARGET, TOKEN,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_get_token_introspection(&i_session, NULL, I_INTROSPECT_REVOKE_AUTH_NONE, 0), I_ERROR_UNAUTHORIZED);
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_introspection_dpop)
{
  struct _i_session i_session;
  struct _u_instance instance;
  json_t * j_result = NULL, * j_expected;
  jwk_t * jwk;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/introspect", 0, &callback_introspect_dpop, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_INTROSPECTION_ENDPOINT, "http://localhost:8080/introspect",
                                                  I_OPT_ACCESS_TOKEN, TOKEN,
                                                  I_OPT_TOKEN_TARGET, TOKEN,
                                                  I_OPT_USE_DPOP, 1,
                                                  I_OPT_TOKEN_JTI_GENERATE, 16,
                                                  I_OPT_DPOP_SIGN_ALG, "RS256",
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_get_token_introspection(&i_session, &j_result, I_INTROSPECT_REVOKE_AUTH_ACCESS_TOKEN, 0), I_OK);
  j_expected = json_loads(result, JSON_DECODE_ANY, NULL);
  ck_assert_int_eq(1, json_equal(j_expected, j_result));
  i_clean_session(&i_session);
  json_decref(j_result);
  json_decref(j_expected);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_INTROSPECTION_ENDPOINT, "http://localhost:8080/introspect",
                                                  I_OPT_ACCESS_TOKEN, TOKEN,
                                                  I_OPT_TOKEN_TARGET, TOKEN "error",
                                                  I_OPT_USE_DPOP, 1,
                                                  I_OPT_TOKEN_JTI_GENERATE, 16,
                                                  I_OPT_DPOP_SIGN_ALG, "RS256",
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_get_token_introspection(&i_session, &j_result, I_INTROSPECT_REVOKE_AUTH_ACCESS_TOKEN, 0), I_OK);
  j_expected = json_loads("{\"active\":false}", JSON_DECODE_ANY, NULL);
  ck_assert_int_eq(1, json_equal(j_expected, j_result));
  i_clean_session(&i_session);
  json_decref(j_result);
  json_decref(j_expected);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_INTROSPECTION_ENDPOINT, "http://localhost:8080/introspect",
                                                  I_OPT_ACCESS_TOKEN, TOKEN "error",
                                                  I_OPT_TOKEN_TARGET, TOKEN,
                                                  I_OPT_USE_DPOP, 1,
                                                  I_OPT_TOKEN_JTI_GENERATE, 16,
                                                  I_OPT_DPOP_SIGN_ALG, "RS256",
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_get_token_introspection(&i_session, NULL, I_INTROSPECT_REVOKE_AUTH_NONE, 0), I_ERROR_UNAUTHORIZED);
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_INTROSPECTION_ENDPOINT, "http://localhost:8080/introspect",
                                                  I_OPT_ACCESS_TOKEN, TOKEN,
                                                  I_OPT_TOKEN_TARGET, TOKEN,
                                                  I_OPT_USE_DPOP, 0,
                                                  I_OPT_TOKEN_JTI_GENERATE, 16,
                                                  I_OPT_DPOP_SIGN_ALG, "RS256",
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_get_token_introspection(&i_session, &j_result, I_INTROSPECT_REVOKE_AUTH_ACCESS_TOKEN, 0), I_ERROR_UNAUTHORIZED);
  i_clean_session(&i_session);
  json_decref(j_result);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

static Suite *iddawc_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Iddawc token introspection tests");
  tc_core = tcase_create("test_iddawc_introspection");
  tcase_add_test(tc_core, test_iddawc_introspection_invalid);
  tcase_add_test(tc_core, test_iddawc_introspection_valid);
  tcase_add_test(tc_core, test_iddawc_introspection_dpop);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc token introspection tests");
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
