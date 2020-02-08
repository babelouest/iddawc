/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <iddawc.h>
#include <jwt.h>

const char id_token_pattern[] =
"{\"amr\":[\"password\"],\"aud\":\"%s\",\"auth_time\":%lld"
",\"azp\":\"%s\",\"exp\":%lld,\"iat\":%lld,\"iss\":\"%s\""
",\"nonce\":\"abc1234\",\"sub\":\"wRNaPT1UBIw4Cl9eo3yOzoH"
"7vE81Phfu\"}";
#define EXPIRES_IN 3600
#define ISSUER "https://glewlwyd.tld"
#define CLIENT_ID "client1_id"

const char code[] = "codeXyz1234";
const char c_hash[] = "xTrH4sIDT1DIDKEmAfED1g";

const char access_token[] =  "accessXyz1234";
const char at_hash[] =  "2f8ZKzK8O7SAUkTpR29Z_w";

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

const unsigned char private_key[] =
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

START_TEST(test_iddawc_id_token_invalid_iss)
{
  struct _i_session i_session;
  jwk_t * jwk;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(jwt_new(&jwt), 0);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(jwt_add_grants_json(jwt, grants), 0);
  ck_assert_int_eq(jwt_set_alg(jwt, JWT_ALG_RS256, private_key, o_strlen((const char *)private_key)), 0);
  ck_assert_ptr_ne((jwt_str = jwt_encode_str(jwt)), NULL);
  
  ck_assert_int_eq(r_init_jwk(&jwk), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, "error"), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (unsigned char *)public_key, o_strlen(public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.jwks, jwk), RHN_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_missing_iss)
{
  struct _i_session i_session;
  jwk_t * jwk;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(jwt_new(&jwt), 0);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(jwt_add_grants_json(jwt, grants), 0);
  ck_assert_int_eq(jwt_del_grants(jwt, "iss"), 0);
  ck_assert_int_eq(jwt_set_alg(jwt, JWT_ALG_RS256, private_key, o_strlen((const char *)private_key)), 0);
  ck_assert_ptr_ne((jwt_str = jwt_encode_str(jwt)), NULL);
  
  ck_assert_int_eq(r_init_jwk(&jwk), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (unsigned char *)public_key, o_strlen(public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.jwks, jwk), RHN_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_missing_sub)
{
  struct _i_session i_session;
  jwk_t * jwk;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(jwt_new(&jwt), 0);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(jwt_add_grants_json(jwt, grants), 0);
  ck_assert_int_eq(jwt_del_grants(jwt, "sub"), 0);
  ck_assert_int_eq(jwt_set_alg(jwt, JWT_ALG_RS256, private_key, o_strlen((const char *)private_key)), 0);
  ck_assert_ptr_ne((jwt_str = jwt_encode_str(jwt)), NULL);
  
  ck_assert_int_eq(r_init_jwk(&jwk), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (unsigned char *)public_key, o_strlen(public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.jwks, jwk), RHN_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_missing_aud)
{
  struct _i_session i_session;
  jwk_t * jwk;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(jwt_new(&jwt), 0);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(jwt_add_grants_json(jwt, grants), 0);
  ck_assert_int_eq(jwt_del_grants(jwt, "aud"), 0);
  ck_assert_int_eq(jwt_set_alg(jwt, JWT_ALG_RS256, private_key, o_strlen((const char *)private_key)), 0);
  ck_assert_ptr_ne((jwt_str = jwt_encode_str(jwt)), NULL);
  
  ck_assert_int_eq(r_init_jwk(&jwk), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (unsigned char *)public_key, o_strlen(public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.jwks, jwk), RHN_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_missing_exp)
{
  struct _i_session i_session;
  jwk_t * jwk;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(jwt_new(&jwt), 0);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(jwt_add_grants_json(jwt, grants), 0);
  ck_assert_int_eq(jwt_del_grants(jwt, "exp"), 0);
  ck_assert_int_eq(jwt_set_alg(jwt, JWT_ALG_RS256, private_key, o_strlen((const char *)private_key)), 0);
  ck_assert_ptr_ne((jwt_str = jwt_encode_str(jwt)), NULL);
  
  ck_assert_int_eq(r_init_jwk(&jwk), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (unsigned char *)public_key, o_strlen(public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.jwks, jwk), RHN_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_invalid_exp)
{
  struct _i_session i_session;
  jwk_t * jwk;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(jwt_new(&jwt), 0);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now - EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(jwt_add_grants_json(jwt, grants), 0);
  ck_assert_int_eq(jwt_set_alg(jwt, JWT_ALG_RS256, private_key, o_strlen((const char *)private_key)), 0);
  ck_assert_ptr_ne((jwt_str = jwt_encode_str(jwt)), NULL);
  
  ck_assert_int_eq(r_init_jwk(&jwk), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (unsigned char *)public_key, o_strlen(public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.jwks, jwk), RHN_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_missing_iat)
{
  struct _i_session i_session;
  jwk_t * jwk;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(jwt_new(&jwt), 0);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(jwt_add_grants_json(jwt, grants), 0);
  ck_assert_int_eq(jwt_del_grants(jwt, "iat"), 0);
  ck_assert_int_eq(jwt_set_alg(jwt, JWT_ALG_RS256, private_key, o_strlen((const char *)private_key)), 0);
  ck_assert_ptr_ne((jwt_str = jwt_encode_str(jwt)), NULL);
  
  ck_assert_int_eq(r_init_jwk(&jwk), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (unsigned char *)public_key, o_strlen(public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.jwks, jwk), RHN_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_invalid_iat)
{
  struct _i_session i_session;
  jwk_t * jwk;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(jwt_new(&jwt), 0);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(jwt_add_grants_json(jwt, grants), 0);
  ck_assert_int_eq(jwt_del_grants(jwt, "iat"), 0);
  ck_assert_int_eq(jwt_set_alg(jwt, JWT_ALG_RS256, private_key, o_strlen((const char *)private_key)), 0);
  ck_assert_ptr_ne((jwt_str = jwt_encode_str(jwt)), NULL);
  
  ck_assert_int_eq(r_init_jwk(&jwk), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (unsigned char *)public_key, o_strlen(public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.jwks, jwk), RHN_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token)
{
  struct _i_session i_session;
  jwk_t * jwk;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(jwt_new(&jwt), 0);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(jwt_add_grants_json(jwt, grants), 0);
  ck_assert_int_eq(jwt_set_alg(jwt, JWT_ALG_RS256, private_key, o_strlen((const char *)private_key)), 0);
  ck_assert_ptr_ne((jwt_str = jwt_encode_str(jwt)), NULL);
  
  ck_assert_int_eq(r_init_jwk(&jwk), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_verify_id_token(NULL), I_ERROR_PARAM);
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR_PARAM);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (unsigned char *)public_key, o_strlen(public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.jwks, jwk), RHN_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_OK);
  
  // Test invalid signature
  jwt_str[o_strlen(jwt_str) - 2] = '\0';
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_with_code)
{
  struct _i_session i_session;
  jwk_t * jwk;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(jwt_new(&jwt), 0);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(jwt_add_grants_json(jwt, grants), 0);
  ck_assert_int_eq(jwt_add_grant(jwt, "c_hash", c_hash), 0);
  ck_assert_int_eq(jwt_set_alg(jwt, JWT_ALG_RS256, private_key, o_strlen((const char *)private_key)), 0);
  ck_assert_ptr_ne((jwt_str = jwt_encode_str(jwt)), NULL);
  
  ck_assert_int_eq(r_init_jwk(&jwk), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CODE, code), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (unsigned char *)public_key, o_strlen(public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.jwks, jwk), RHN_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_OK);
  
  o_free(grants);
  o_free(jwt_str);
  jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_with_access_token)
{
  struct _i_session i_session;
  jwk_t * jwk;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_init_jwk(&jwk), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(jwt_new(&jwt), 0);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(jwt_add_grants_json(jwt, grants), 0);
  ck_assert_int_eq(jwt_add_grant(jwt, "at_hash", at_hash), 0);
  ck_assert_int_eq(jwt_set_alg(jwt, JWT_ALG_RS256, private_key, o_strlen((const char *)private_key)), 0);
  ck_assert_ptr_ne((jwt_str = jwt_encode_str(jwt)), NULL);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, access_token), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (unsigned char *)public_key, o_strlen(public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.jwks, jwk), RHN_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_OK);
  
  o_free(grants);
  o_free(jwt_str);
  jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_with_code_access_token)
{
  struct _i_session i_session;
  jwk_t * jwk;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_init_jwk(&jwk), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(jwt_new(&jwt), 0);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(jwt_add_grants_json(jwt, grants), 0);
  ck_assert_int_eq(jwt_add_grant(jwt, "at_hash", at_hash), 0);
  ck_assert_int_eq(jwt_add_grant(jwt, "c_hash", c_hash), 0);
  ck_assert_int_eq(jwt_set_alg(jwt, JWT_ALG_RS256, private_key, o_strlen((const char *)private_key)), 0);
  ck_assert_ptr_ne((jwt_str = jwt_encode_str(jwt)), NULL);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, access_token), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CODE, code), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (unsigned char *)public_key, o_strlen(public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.jwks, jwk), RHN_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_OK);
  
  o_free(grants);
  o_free(jwt_str);
  jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

static Suite *iddawc_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Iddawc id_token tests");
  tc_core = tcase_create("test_iddawc_id_token");
  tcase_add_test(tc_core, test_iddawc_id_token_invalid_iss);
  tcase_add_test(tc_core, test_iddawc_id_token_missing_iss);
  tcase_add_test(tc_core, test_iddawc_id_token_missing_sub);
  tcase_add_test(tc_core, test_iddawc_id_token_missing_aud);
  tcase_add_test(tc_core, test_iddawc_id_token_missing_exp);
  tcase_add_test(tc_core, test_iddawc_id_token_invalid_exp);
  tcase_add_test(tc_core, test_iddawc_id_token_missing_iat);
  tcase_add_test(tc_core, test_iddawc_id_token_invalid_iat);
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
