/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <iddawc.h>

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

const char id_token_invalid_sig_no_hash[] = 
"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbXIiOlsicGFzc3dvcmQiXSw"
"iYXVkIjoiY2xpZW50MV9pZCIsImF1dGhfdGltZSI6MTU3ODIzMTExNywiYXpwIjo"
"iY2xpZW50MV9pZCIsImV4cCI6MTU3ODIzNDcyMSwiaWF0IjoxNTc4MjMxMTIxLCJ"
"pc3MiOiJodHRwczovL2dsZXdsd3lkLnRsZCIsIm5vbmNlIjoiYWJjMTIzNCIsInN"
"1YiI6IndSTmFQVDFVQkl3NENsOWVvM3lPem9IN3ZFODFQaGZ1In0.JDaE508TDbC"
"jJLRGV2V0zHxuH3mFxmkJdV8S-jLfe7NrP9MW84i1IoCcGV-Z9dm3Jo1u4TkBHcx"
"kOd1b7VdhHy1SxNdEmZ0As8NHUL4K6sH1Dxlj4JQEDhJTkbyvofsopHOB3WVML3V"
"Og-qc5vk3Q4i0vJlSZUa4KOseUf-uzAlkjIVsw09zdD75_OopKU5nSHepvopx4Tw"
"3QKOPaWfd875KKU5f-VrusQ02O5mn2YEn0ile7fQ1yf6_7VXRQG5BHM1fTW97kvY"
"3E4JL3kZVnTsqFqgHW3JrB-33qxSIVsvW52nT4fBiLxwkGeZIqMaObxHSp6Us_5t"
"CPq-f2pyq5w";

const char code[] = "codeXyz1234";
const char access_token[] =  "accessXyz1234";

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

const char private_key[] =
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

START_TEST(test_iddawc_id_token)
{
  struct _i_session i_session;
  jwk_t * jwk;
  
  ck_assert_int_eq(r_init_jwk(&jwk), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_verify_id_token(NULL, I_HAS_NONE), I_ERROR_PARAM);
  ck_assert_int_eq(i_verify_id_token(&i_session, I_HAS_NONE), I_ERROR_PARAM);
  ck_assert_int_eq(i_verify_id_token(&i_session, I_HAS_ACCESS_TOKEN), I_ERROR_PARAM);
  ck_assert_int_eq(i_verify_id_token(&i_session, I_HAS_CODE), I_ERROR_PARAM);
  ck_assert_int_eq(i_verify_id_token(&i_session, I_HAS_CODE|I_HAS_ACCESS_TOKEN), I_ERROR_PARAM);
  
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ID_TOKEN, id_token_valid_sig_no_hash), I_OK);
  ck_assert_str_eq(i_get_parameter(&i_session, I_OPT_ID_TOKEN), id_token_valid_sig_no_hash);
  ck_assert_int_eq(i_verify_id_token(&i_session, I_HAS_NONE), I_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (unsigned char *)public_key, o_strlen(public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.jwks, jwk), RHN_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(i_verify_id_token(&i_session, I_HAS_NONE), I_OK);
  
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ID_TOKEN, id_token_invalid_sig_no_hash), I_OK);
  ck_assert_int_eq(i_verify_id_token(&i_session, I_HAS_NONE), I_ERROR_PARAM);
  
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_with_code)
{
  struct _i_session i_session;
  jwk_t * jwk;
  
  ck_assert_int_eq(r_init_jwk(&jwk), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ID_TOKEN, id_token_valid_sig_c_hash), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_CODE, code), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (unsigned char *)public_key, o_strlen(public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.jwks, jwk), RHN_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(i_verify_id_token(&i_session, I_HAS_CODE|I_HAS_ACCESS_TOKEN), I_ERROR_PARAM);
  ck_assert_int_eq(i_verify_id_token(&i_session, I_HAS_ACCESS_TOKEN), I_ERROR_PARAM);
  ck_assert_int_eq(i_verify_id_token(&i_session, I_HAS_CODE), I_OK);
  
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_with_access_token)
{
  struct _i_session i_session;
  jwk_t * jwk;
  
  ck_assert_int_eq(r_init_jwk(&jwk), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ID_TOKEN, id_token_valid_sig_at_hash), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ACCESS_TOKEN, access_token), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (unsigned char *)public_key, o_strlen(public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.jwks, jwk), RHN_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(i_verify_id_token(&i_session, I_HAS_ACCESS_TOKEN|I_HAS_CODE), I_ERROR_PARAM);
  ck_assert_int_eq(i_verify_id_token(&i_session, I_HAS_CODE), I_ERROR_PARAM);
  ck_assert_int_eq(i_verify_id_token(&i_session, I_HAS_ACCESS_TOKEN), I_OK);
  
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_with_code_access_token)
{
  struct _i_session i_session;
  jwk_t * jwk;
  
  ck_assert_int_eq(r_init_jwk(&jwk), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ID_TOKEN, id_token_valid_sig_c_hash_at_hash), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_ACCESS_TOKEN, access_token), I_OK);
  ck_assert_int_eq(i_set_parameter(&i_session, I_OPT_CODE, code), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (unsigned char *)public_key, o_strlen(public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.jwks, jwk), RHN_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(i_verify_id_token(&i_session, I_HAS_ACCESS_TOKEN|I_HAS_CODE), I_OK);
  ck_assert_int_eq(i_verify_id_token(&i_session, I_HAS_CODE), I_OK);
  ck_assert_int_eq(i_verify_id_token(&i_session, I_HAS_ACCESS_TOKEN), I_OK);
  
  i_clean_session(&i_session);
}
END_TEST

static Suite *iddawc_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Iddawc id_token tests");
  tc_core = tcase_create("test_iddawc_id_token");
  tcase_add_test(tc_core, test_iddawc_id_token);
  tcase_add_test(tc_core, test_iddawc_id_token_with_code);
  tcase_add_test(tc_core, test_iddawc_id_token_with_access_token);
  tcase_add_test(tc_core, test_iddawc_id_token_with_code_access_token);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc id_token tests");
  s = iddawc_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
