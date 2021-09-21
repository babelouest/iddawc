/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <jansson.h>
#include <check.h>
#include <yder.h>
#include <iddawc.h>

const char jwk_privkey_str[] =    "{\"kty\":\"RSA\",\"n\":\"ANgV1GxZbGBMIqqX5QsNrQQnPLk8UpkqH_60EuaHsI8YnUkPmPVXJ_4z_ziqZizvvjp_RhhXX2DnHEQuYwI-SZaBlK1VJiiWH9E"\
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
const char jwk_privkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
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
                                   "HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";

#define DPOP_HTM "POST"
#define DPOP_HTU "https://resource.tld/object"

START_TEST(test_iddawc_dpop_invalid_parameters)
{
  struct _i_session i_session;
  jwk_t * jwk;
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_ptr_eq(NULL, i_generate_dpop_token(&i_session, DPOP_HTM, DPOP_HTU, 0));
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_ptr_eq(NULL, i_generate_dpop_token(&i_session, DPOP_HTM, DPOP_HTU, 0));
  
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_TOKEN_JTI_GENERATE, 16,
                                                    I_OPT_NONE), I_OK);
  ck_assert_ptr_eq(NULL, i_generate_dpop_token(&i_session, DPOP_HTM, DPOP_HTU, 0));

  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_DPOP_SIGN_ALG, "RS256",
                                                    I_OPT_TOKEN_JTI, NULL,
                                                    I_OPT_NONE), I_OK);
  ck_assert_ptr_eq(NULL, i_generate_dpop_token(&i_session, DPOP_HTM, DPOP_HTU, 0));

  ck_assert_ptr_eq(NULL, i_generate_dpop_token(&i_session, NULL, DPOP_HTU, 0));

  ck_assert_ptr_eq(NULL, i_generate_dpop_token(&i_session, DPOP_HTM, NULL, 0));

  i_clean_session(&i_session);
  
}
END_TEST

START_TEST(test_iddawc_dpop_valid_parameters)
{
  struct _i_session i_session;
  jwk_t * jwk;
  jwt_t * dpop_jwt;
  char * token;
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_DPOP_SIGN_ALG, "RS256",
                                                    I_OPT_TOKEN_JTI_GENERATE, 16,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_ptr_ne(NULL, token = i_generate_dpop_token(&i_session, DPOP_HTM, DPOP_HTU, 0));
  ck_assert_int_eq(r_jwt_init(&dpop_jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_advanced_parse(dpop_jwt, token, R_PARSE_HEADER_JWK, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_verify_signature(dpop_jwt, NULL, 0), RHN_OK);
  r_jwt_free(dpop_jwt);
  i_clean_session(&i_session);
  o_free(token);
}
END_TEST

START_TEST(test_iddawc_verify_dpop_proof_ok)
{
  struct _i_session i_session;
  jwk_t * jwk;
  jwt_t * dpop_jwt;
  char * token, * jtk;
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_DPOP_SIGN_ALG, "RS256",
                                                    I_OPT_TOKEN_JTI_GENERATE, 16,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str), RHN_OK);
  ck_assert_ptr_ne(NULL, jtk = r_jwk_thumbprint(jwk, R_JWK_THUMB_SHA256, R_FLAG_IGNORE_REMOTE));
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_ptr_ne(NULL, token = i_generate_dpop_token(&i_session, DPOP_HTM, DPOP_HTU, 0));
  ck_assert_int_eq(r_jwt_init(&dpop_jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_advanced_parse(dpop_jwt, token, R_PARSE_HEADER_JWK, 0), RHN_OK);
  ck_assert_int_eq(i_verify_dpop_proof(token, DPOP_HTM, DPOP_HTU, 10, jtk), I_OK);
  r_jwt_free(dpop_jwt);
  i_clean_session(&i_session);
  o_free(token);
  o_free(jtk);
}
END_TEST

START_TEST(test_iddawc_verify_dpop_proof_invalid)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_fool;
  jwt_t * dpop_jwt;
  char * token, * jtk;
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_DPOP_SIGN_ALG, "RS256",
                                                    I_OPT_TOKEN_JTI_GENERATE, 16,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_fool), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_fool, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_ptr_ne(NULL, jtk = r_jwk_thumbprint(jwk, R_JWK_THUMB_SHA256, R_FLAG_IGNORE_REMOTE));
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk_fool), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_fool);
  ck_assert_ptr_ne(NULL, token = i_generate_dpop_token(&i_session, DPOP_HTM, DPOP_HTU, 0));
  ck_assert_int_eq(r_jwt_init(&dpop_jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_advanced_parse(dpop_jwt, token, R_PARSE_HEADER_JWK, 0), RHN_OK);
  ck_assert_int_eq(i_verify_dpop_proof(token, DPOP_HTM, DPOP_HTU, 10, jtk), I_ERROR_UNAUTHORIZED);
  r_jwt_free(dpop_jwt);
  i_clean_session(&i_session);
  o_free(token);
  o_free(jtk);
}
END_TEST

static Suite *iddawc_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Iddawc DPoP token generation tests");
  tc_core = tcase_create("test_iddawc_dpop_token_generation");
  tcase_add_test(tc_core, test_iddawc_dpop_invalid_parameters);
  tcase_add_test(tc_core, test_iddawc_dpop_valid_parameters);
  tcase_add_test(tc_core, test_iddawc_verify_dpop_proof_ok);
  tcase_add_test(tc_core, test_iddawc_verify_dpop_proof_invalid);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc DPoP token generation tests");
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
