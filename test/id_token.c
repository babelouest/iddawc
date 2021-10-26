/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <rhonabwy.h>
#include <iddawc.h>

#define EXPIRES_IN 3600
#define ISSUER "https://glewlwyd.tld"
#define AUD "https://resource.tld"
#define CLIENT_ID "client1_id"
#define NONCE_INVALID "4321cba"
#define NONCE_VALID "abc1234"

const char id_token_pattern[] =
"{\"amr\":[\"password\"],\"aud\":\"%s\",\"auth_time\":%lld"
",\"azp\":\"%s\",\"exp\":%lld,\"iat\":%lld,\"iss\":\"%s\""
",\"nonce\":\"abc1234\",\"sub\":\"wRNaPT1UBIw4Cl9eo3yOzoH"
"7vE81Phfu\"}";
const char access_token_pattern[] =
"{\"iat\":%lld"
",\"exp\":%lld"
",\"iss\":\"%s\""
",\"sub\":\"wRNaPT1UBIw4Cl9eo3yOzoH7vE81Phfu\""
",\"client_id\":\""CLIENT_ID"\""
",\"aud\":\""AUD"\""
",\"jti\":\"vE81Phfuw3yOzoH7RNaPT1UBIw4Cl9eo\"}";

const char code[] = "codeXyz1234";
const char c_hash[] = "xTrH4sIDT1DIDKEmAfED1g";

const char access_token[] =  "accessXyz1234";
const char at_hash[] =  "2f8ZKzK8O7SAUkTpR29Z_w";

const char state[] =  "stateXyz1234";
const char s_hash[] =  "_jIffADbCLEZHXM4vOimzQ";

const char sid[] = "sidXyz1234";

const unsigned char public_key[] = 
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

const char jwk_pubkey_rsa_str_2[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                    "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                    "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                    ",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_privkey_rsa_str_2[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
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
const char jwk_privkey_fool_str[] = "{\"kty\":\"RSA\",\"n\":\"ANgV1GxZbGBMIqqX5QsNrQQnPLk8UpkqH_60EuaHsI8YnUkPmPVXJ_4z_ziqZizvvjp_RhhXX2DnHEQuYwI-SZaBlK1VJiiWH9E"\
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

START_TEST(test_iddawc_id_token_invalid_iss)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, "error"), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_missing_iss)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "iss", NULL), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_missing_sub)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "sub", NULL), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_missing_aud)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "aud", NULL), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_missing_exp)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "exp", NULL), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_invalid_exp)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now - EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_missing_iat)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "iat", NULL), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_invalid_iat)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)(now + EXPIRES_IN + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_invalid_nonce)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "nonce", "error"), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_OK);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_with_code)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "c_hash", c_hash), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CODE, code), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_OK);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_with_access_token)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "at_hash", at_hash), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, access_token), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_OK);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_with_state)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "s_hash", s_hash), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_STATE, state), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_OK);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_with_code_access_token)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "c_hash", c_hash), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "at_hash", at_hash), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CODE, code), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, access_token), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_OK);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_with_code_access_token_state)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "c_hash", c_hash), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "at_hash", at_hash), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "s_hash", s_hash), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_STATE, state), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_CODE, code), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, access_token), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_OK);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_with_sid)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "sid", sid), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN_SID), sid);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_nested)
{
  struct _i_session i_session;
  jwk_t * jwk_decrypt, * jwk_encrypt, * jwk_sign, * jwk_verify;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_encrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_verify), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_encrypt, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_decrypt, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_sign, jwk_privkey_rsa_str_2), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_verify, jwk_pubkey_rsa_str_2), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT, jwk_sign, 0, jwk_encrypt, 0)), NULL);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_verify), RHN_OK);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_OK);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  r_jwk_free(jwk_decrypt);
  r_jwk_free(jwk_encrypt);
  r_jwk_free(jwk_sign);
  r_jwk_free(jwk_verify);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_invalid_key)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_sign, jwk_pubkey_rsa_str_2), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_id_token_fooled_key)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign, * jwk_pub;
  jwt_t * jwt;
  json_t * j_jwk;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pub), RHN_OK);
  
  time(&now);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_sign, jwk_pubkey_rsa_str_2), RHN_OK);
  grants = msprintf(id_token_pattern, CLIENT_ID, (long long)now, CLIENT_ID, (long long)(now + EXPIRES_IN), (long long)now, ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_fool_str), RHN_OK);
  ck_assert_int_eq(r_jwk_set_property_str(jwk, "kid", r_jwk_get_property_str(jwk_sign, "kid")), RHN_OK);
  ck_assert_int_eq(r_jwk_extract_pubkey(jwk, jwk_pub, 0), RHN_OK);
  ck_assert_ptr_ne(j_jwk = r_jwk_export_to_json_t(jwk_pub), NULL);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt, "jwk", j_jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ID_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ID_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  
  ck_assert_int_eq(i_verify_id_token(&i_session), I_ERROR);
  
  json_decref(j_jwk);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  r_jwk_free(jwk_pub);
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_access_token_invalid_iss)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, "error"), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_jwt_access_token(&i_session, AUD), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_access_token_invalid_typ)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_jwt_access_token(&i_session, AUD), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_access_token_missing_iss)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "iss", NULL), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_jwt_access_token(&i_session, AUD), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_access_token_missing_exp)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "exp", NULL), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_jwt_access_token(&i_session, AUD), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_access_token_missing_iat)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "iat", NULL), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_jwt_access_token(&i_session, AUD), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_access_token_missing_aud)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "aud", NULL), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_jwt_access_token(&i_session, AUD), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_access_token_missing_sub)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "sub", NULL), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_jwt_access_token(&i_session, AUD), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_access_token_missing_client_id)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "client_id", NULL), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_jwt_access_token(&i_session, AUD), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_access_token_missing_jti)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "jti", NULL), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_jwt_access_token(&i_session, AUD), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_access_token_invalid_exp)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)(now - 2*EXPIRES_IN), (long long)(now - EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_jwt_access_token(&i_session, NULL), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_access_token_invalid_iat)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)(now + EXPIRES_IN), (long long)(now + 2*EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_jwt_access_token(&i_session, NULL), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_access_token)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_jwt_access_token(&i_session, NULL), I_OK);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_access_token_fooled_key)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign, * jwk_pub;
  jwt_t * jwt;
  json_t * j_jwk;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_fool_str), RHN_OK);
  ck_assert_int_eq(r_jwk_set_property_str(jwk, "kid", r_jwk_get_property_str(jwk_sign, "kid")), RHN_OK);
  ck_assert_int_eq(r_jwk_extract_pubkey(jwk, jwk_pub, 0), RHN_OK);
  ck_assert_ptr_ne(j_jwk = r_jwk_export_to_json_t(jwk_pub), NULL);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt, "jwk", j_jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  
  ck_assert_int_eq(i_verify_jwt_access_token(&i_session, NULL), I_ERROR_PARAM);
  
  json_decref(j_jwk);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  r_jwk_free(jwk_pub);
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_access_token_invalid_aud)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "aud", AUD), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_jwt_access_token(&i_session, "error"), I_ERROR_PARAM);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_access_token_aud)
{
  struct _i_session i_session;
  jwk_t * jwk, * jwk_sign;
  jwt_t * jwt;
  char * grants = NULL, * jwt_str;
  time_t now;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  time(&now);
  grants = msprintf(access_token_pattern, (long long)now, (long long)(now + EXPIRES_IN), ISSUER);
  ck_assert_ptr_ne(grants, NULL);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, grants), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "aud", AUD), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", "at+jwt"), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, private_key, o_strlen((const char *)private_key)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((jwt_str = r_jwt_serialize_signed(jwt, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ISSUER, ISSUER), I_OK);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_ACCESS_TOKEN, jwt_str), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN), jwt_str);
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_NONCE, NONCE_VALID), I_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_sign, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, public_key, o_strlen((const char *)public_key)), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  r_jwk_free(jwk);
  r_jwk_free(jwk_sign);
  
  ck_assert_int_eq(i_verify_jwt_access_token(&i_session, AUD), I_OK);
  
  o_free(grants);
  o_free(jwt_str);
  r_jwt_free(jwt);
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
  tcase_add_test(tc_core, test_iddawc_id_token_invalid_nonce);
  tcase_add_test(tc_core, test_iddawc_id_token);
  tcase_add_test(tc_core, test_iddawc_id_token_with_code);
  tcase_add_test(tc_core, test_iddawc_id_token_with_access_token);
  tcase_add_test(tc_core, test_iddawc_id_token_with_state);
  tcase_add_test(tc_core, test_iddawc_id_token_with_code_access_token);
  tcase_add_test(tc_core, test_iddawc_id_token_with_code_access_token_state);
  tcase_add_test(tc_core, test_iddawc_id_token_with_sid);
  tcase_add_test(tc_core, test_iddawc_id_token_nested);
  tcase_add_test(tc_core, test_iddawc_id_token_invalid_key);
  tcase_add_test(tc_core, test_iddawc_id_token_fooled_key);
  tcase_add_test(tc_core, test_iddawc_access_token_invalid_typ);
  tcase_add_test(tc_core, test_iddawc_access_token_invalid_iss);
  tcase_add_test(tc_core, test_iddawc_access_token_missing_iss);
  tcase_add_test(tc_core, test_iddawc_access_token_missing_exp);
  tcase_add_test(tc_core, test_iddawc_access_token_missing_iat);
  tcase_add_test(tc_core, test_iddawc_access_token_missing_aud);
  tcase_add_test(tc_core, test_iddawc_access_token_missing_sub);
  tcase_add_test(tc_core, test_iddawc_access_token_missing_client_id);
  tcase_add_test(tc_core, test_iddawc_access_token_missing_jti);
  tcase_add_test(tc_core, test_iddawc_access_token_invalid_exp);
  tcase_add_test(tc_core, test_iddawc_access_token_invalid_iat);
  tcase_add_test(tc_core, test_iddawc_access_token);
  tcase_add_test(tc_core, test_iddawc_access_token_fooled_key);
  tcase_add_test(tc_core, test_iddawc_access_token_invalid_aud);
  tcase_add_test(tc_core, test_iddawc_access_token_aud);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc id_token tests");
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
