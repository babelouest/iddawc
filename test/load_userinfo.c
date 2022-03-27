/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <iddawc.h>

#define USERINFO_NAME "Dave Lopper"
#define USERINFO_AUD "abcdxyz"
#define USERINFO_EMAIL "dev@iddawc.tld"
#define ACCESS_TOKEN "accessXyz1234"
#define DPOP_NONCE "dpopNonceXyz1234"

static char userinfo_json[] = "{"\
  "\"name\":\"" USERINFO_NAME "\","\
  "\"aud\":\"" USERINFO_AUD "\","\
  "\"email\":\"" USERINFO_EMAIL "\""\
"}";

const char jwk_pubkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"ALrIdhuABv82Y7K1-LJCXRy1LVdmK9IAHwmmlI-HnOrFeEsSwuCeblUgEpqz_mj7lLtZN0Gnlz-7U0hOpGCeOYXRMn8184YismuCS5PYe0"
                                  "Jfot0kMumF2IOBV94AGBSeWQcK8J-Ed3X-rkR9vovv8gXhKyRDQH4mon_cPwtdCi2PScnRlkvlOjYkib9m0QQqpvjmcd02s8BYtakRVRva2mQT_dCvRYvM4Tb5yvvRM7Iz3"
                                  "Ni6Jj-IOUZvaZtRW_2HPvhho6Pj_XuYDVHHWyi8SWXtvMQehOtiv9cNecOcvtvEN7YLf2sTM9nIBxOmkRF6k2wvmxwMeoqQZ-pZuvVQkn2opKHLFZlL5BTmPWnGIwmmioxI"
                                  "RaDmc1KApufOw2voHqCSJR99UMwIyJpIulFqBw_F2y2vS-uXDODA3PmG1u1qpN2mqjvbHz1PwKYucPQH1GoMMRKeEPsjKamLLpftn_GgWUk17ti2-xAtYG8XEFsv4hzCWip"
                                  "x0zh4S0aVRLoomN9AisHTCWpOgdg1kFj3ECrKxhYMETWGUTKrItAOhE1VuyOenIPMN8ZEeWfqPdUnrRYtRN0ce7WCYulkDynavFJK_13NpJ7d-44ns_F2r2Bl9K6bYxK8W4"
                                  "d2Q9soCtfsb6eOabtuP-5yWuvPxn9gt6xgbIMEc643k__Lx2_ct6fT\",\"e\":\"AQAB\",\"kid\":\"1\",\"alg\":\"RS256\"}";
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

const char jwk_pubkey_rsa_str_2[] = "{\"kty\":\"RSA\",\"n\":\"ANjyvB_f8xm80wMZM4Z7VO6UrTaFoDd68pgf2BCnnMsnH9lo4z40Yg-wWFhPhgZmSTFZjYUkWHGZoEpordO8xq6d_o3gkL2-ValGfxD8"
                                    "2B7465IKNodJY7bldLaBqsVcQrottkL2UC3SXuIkDfZGG6_XU6Lr14rgNvw65mWavejYLNz2GVvmc54p36PArwPSY8fvdQsijrmrvsxx9av0qZASbxjfHkuibnsC4sW3b"
                                    "bsObZG_eOBkEwOwh_RVSV5GyprA4mZfnj_rTnWVN4OENa756cyk1JwWRzRWR0Q7xdlvcAzga3S3M_9dJb386Oip3SsFhIeZekyh2lAEi2E5VUWP8uOf-UCuEj04B9hNl5"
                                    "szmNMts5AsBxBKwK_ixWNif8NBGQyA8mqRpYr7ddaBnCxreDuZyV6AwPBRfIOb29zgIi5OZzISsvFjFACDrgtX5sF_M_Q6usnyN-3LKoqHMqcL3dk0_a93gsuYMpK4OPm"
                                    "N6-82CekUsJ_m--3cZbknmeixPnRQGJLZNSZrpd0KZ1A0Dzmkr6RqWTlu51-cI50lyZXJiHR8hv-_tW2iRN3DWs6uI24S44-1-mSYfXL5vLYu6cBlIGYh55wLHK4GwyfF"
                                    "-GopckkedidJjX-zVPwJSq2CjmgitDvjoZMaDawoKgkH_uTWqobUNIS_4BPQiAET\",\"e\":\"AQAB\",\"kid\":\"2\"}";
const char jwk_privkey_rsa_str_2[] = "{\"kty\":\"RSA\",\"n\":\"ANjyvB_f8xm80wMZM4Z7VO6UrTaFoDd68pgf2BCnnMsnH9lo4z40Yg-wWFhPhgZmSTFZjYUkWHGZoEpordO8xq6d_o3gkL2-ValGfxD"
                                     "82B7465IKNodJY7bldLaBqsVcQrottkL2UC3SXuIkDfZGG6_XU6Lr14rgNvw65mWavejYLNz2GVvmc54p36PArwPSY8fvdQsijrmrvsxx9av0qZASbxjfHkuibnsC4sW"
                                     "3bbsObZG_eOBkEwOwh_RVSV5GyprA4mZfnj_rTnWVN4OENa756cyk1JwWRzRWR0Q7xdlvcAzga3S3M_9dJb386Oip3SsFhIeZekyh2lAEi2E5VUWP8uOf-UCuEj04B9h"
                                     "Nl5szmNMts5AsBxBKwK_ixWNif8NBGQyA8mqRpYr7ddaBnCxreDuZyV6AwPBRfIOb29zgIi5OZzISsvFjFACDrgtX5sF_M_Q6usnyN-3LKoqHMqcL3dk0_a93gsuYMpK"
                                     "4OPmN6-82CekUsJ_m--3cZbknmeixPnRQGJLZNSZrpd0KZ1A0Dzmkr6RqWTlu51-cI50lyZXJiHR8hv-_tW2iRN3DWs6uI24S44-1-mSYfXL5vLYu6cBlIGYh55wLHK4"
                                     "GwyfF-GopckkedidJjX-zVPwJSq2CjmgitDvjoZMaDawoKgkH_uTWqobUNIS_4BPQiAET\",\"e\":\"AQAB\",\"d\":\"cf9SlRkzf5G1-4nRhlfmMBuVzPF4V87WD"
                                     "NOm0FGS1TkwxigUSIp0ALR0J6tZzKEQ0sqwz4ZipwbHsHHC7WDjsbu5l8mppNqP3ov5lu6VjejUt_9_2aTZrbBynLgUCPLK6VO90v_k7778Nq4lXARI5iQqgZCVyRa6L"
                                     "d2xVTBznBeDs3PprV2x4Sk1p7FHBaYW4mdURE6bWrsBXiJ_qiS8uMTG9fW_0JSAo0jH6obRNRqGvrAzDw3m4-ht-Bicndpq-dhi3tJdsE6wAp8u9X-SSehuTydJxN77-"
                                     "WdguV0DQJcK9Okz7bearhO_Ek8D_8XKPqH-mtYt6nid47APoT3kLNp1v5qiXQ8hLN4N1YM_s7LG44Gtns32Vzs7nwwBnBHAdhUxm5q40twVGXraw6SrTZC1hMpVCgJvp"
                                     "Ta-Ebz8RM7b7Qw142_4BRfi4p2QuOxoxY5ahmKD7xF8MH5307hPCC2-MO8FNe8c5sr4soEj93eFEf9V0UV5YHekopAKHDaS15sSbCIrDk78vFVmO2R6RCa3JKWLhg5Lk"
                                     "V5SeT5u3_TYdQ_3tgpZusuV534DbUV-Ztan2Emu4ds4-icL-SqkXzA_1TvDYtwnMxIWlG07gqTw-BshL2JuY18_8FjVzy4MWB7J8s2GVzJqKT8iY-L4JTJY5cvYsaQkF"
                                     "xRFEc2oE4E\",\"p\":\"AOLIjerOJBuW-Odoq2WSGSRzD5M5i4wwHV88wsNhzLsarB_ebyKwQwEKyalhOAUFTXjUQzg2G8FB9FLPmdgnUukWNCmd4c0pRBKCLNXHQwK"
                                     "uYTHf8lkfn2WchyGGIVQUFbgSdJtN6PGZbRa-26sz4xQgtyiFLerA8shwGl6Q07Sjd6CvRi-NvGqEW2LCz10iNPCqzQYfS0cPWhYXDrIqL_BFTo6A3bU0ifg_NukCvcR"
                                     "KZtlD2FaMCMF5xxfoCMtfXF1Owf_QwCAI5GebTbmLf3BmaCNjlmFm6nR1Vo-17Tk0nq3_rPYGiqLr2ANk8NHeMs6xe1GcWuO_nD1gE6o5QtM\",\"q\":\"APTlzxeo8"
                                     "IINCZulhQyOr3-zBTAtyaHgHQk2-AQYK98Ev6pfBvxwwMzAkSoVpCm1pxyp3JCSyjRSYFd4ibnZDjwd5p8RBfLr_zEnfx-IdUIrY7SyCGaFcKt2jS__4DUZQZu0-3Ysi"
                                     "dK8AECtVr0pa4XifZQnkqWnOeqkZqW1lT1yI8w4NbpCJVAT3ohhhRbTcCLFMhZjmWt5ZGgPz9r251PE-7i-04UvShSevhwdS6YJ3ma4gWhYbDMoADOXFfc5Qr1LxHd1w"
                                     "8LUk20bYTW_yZM8tDZxOQqkGivFW53kcgifzmKYjADNgQQojKO4KhG7xGxqvNrzNJQjM3SPdmUM4ME\",\"qi\":\"DwIv9lrwRP5ptwss0aNKgE1wRaaT8upXvzzlZA"
                                     "uNwolrVhmft_ELSNFuMRv-FCL1BK7YQgBwqux0_iRljvMcRogpeCs7w9DwLpivWyVcJf4PKZZWWlm7_kjIoVxRmNBzZUPpadCTQpAc8uGDtlz6OVgnvnb8FWtYDmHJMy"
                                     "UUdOb5Yxyg98P69pQ9ubPkkRwisDNnujjU3FCdiKZM1W1-l-qGJSHx0L8FEV3pckdOqzejw4jvb0mQroS5_UyeeY5nD93dwyI2faoD6K8xdh_Q1l6yW-7S3z7Z9qTkcP"
                                     "Ikb_BnWE59bAJniLDFx9KCSLMXv-_AhtY8AoGmSwT2rzAFpw\",\"dp\":\"ALDkPIZNOq7miMl_xElatw_OS_TLawTzNsXlkAl0jIvZFy9YghltoSX78yaSNW79HtvD"
                                     "vZbn5ahNuLSrR9XpfmtfLVrU0p8DtBw3u58YaTV7LUcI5nEMEHniqSjGBdMeQ36rrpbBI5Tn1sZqItAcjeBSUGtjzlgRHo6nmnnuv6Nj6ljEvpszFCeFi_6x86syllau"
                                     "83L2D_Kij-MxIv5nl7LzbH4NGGJSU9f1_u-rerfUTPrlR6biXaYERf5ouAtiG5qQZxQSEPor1XTXF75FiCb1Sf9om5DoBLLIH7fC8QGxAKC6EIBqw9Km4XxsTMd2aOz-"
                                     "VTFoIyEIgWcCPPSG648\",\"dq\":\"GW-xJdz3NhrSj6cOfbJoShQ3Cr0Gv1h-y5E5C3vTOrPMkI6UNC4l6F5r9XoP9gEXHWQLM7z7YZnYxd0QOQxxbQ8SAB2Nh6C5f"
                                     "cqDaqwKude14HPJaZSckkKbAYxLJli8NscCg1C28_tw70bRxo4BzAMtVfESS0BmRJfUzYtht-MeEr0X34O1Sm714yZ141wMvp_KxwaLTd1q72AND8orVskT-Clh4Oh7g"
                                     "k7Gojbsv48w2Wx6jHL6sgmKk9Eyh94br3uqKVpC_f6EXYXFgAaukitw8GKsMQ3AZiF2lZy_t2OZ1SXRDNhLeToY-XxMalEdYsFnYjp2kJhjZMzt2CsRQQ\",\"kid\":\"2\"}";

static char userinfo_char[] = USERINFO_NAME ";" USERINFO_AUD ";" USERINFO_EMAIL;

int callback_openid_userinfo_valid_json (const struct _u_request * request, struct _u_response * response, void * user_data) {
  if (0 == o_strcmp(u_map_get(request->map_header, "Authorization"), "Bearer " ACCESS_TOKEN)) {
    json_t * j_response = json_loads(userinfo_json, JSON_DECODE_ANY, NULL);
    ulfius_set_json_body_response(response, 200, j_response);
    json_decref(j_response);
  } else {
    response->status = 401;
  }
  return U_CALLBACK_CONTINUE;
}

int callback_openid_userinfo_valid_json_dpop (const struct _u_request * request, struct _u_response * response, void * user_data) {
  if (0 == o_strcmp(u_map_get(request->map_header, "Authorization"), "DPoP " ACCESS_TOKEN) && u_map_get(request->map_header, I_HEADER_DPOP) != NULL) {
    json_t * j_response = json_loads(userinfo_json, JSON_DECODE_ANY, NULL);
    ulfius_set_json_body_response(response, 200, j_response);
    json_decref(j_response);
  } else {
    response->status = 401;
  }
  return U_CALLBACK_CONTINUE;
}

int callback_openid_userinfo_valid_json_dpop_nonce (const struct _u_request * request, struct _u_response * response, void * user_data) {
  if (0 == o_strcmp(u_map_get(request->map_header, "Authorization"), "DPoP " ACCESS_TOKEN) && u_map_get(request->map_header, I_HEADER_DPOP) != NULL) {
    jwt_t * jwt = r_jwt_quick_parse(u_map_get(request->map_header, I_HEADER_DPOP), R_PARSE_HEADER_JWK, 0);
    if (0 != o_strcmp(DPOP_NONCE, r_jwt_get_claim_str_value(jwt, "nonce"))) {
      ulfius_set_response_properties(response, U_OPT_STATUS, 400,
                                               U_OPT_HEADER_PARAMETER, "DPoP-Nonce", DPOP_NONCE,
                                               U_OPT_NONE);
    } else {
      json_t * j_response = json_loads(userinfo_json, JSON_DECODE_ANY, NULL);
      ulfius_set_json_body_response(response, 200, j_response);
      json_decref(j_response);
    }
    r_jwt_free(jwt);
  } else {
    response->status = 401;
  }
  return U_CALLBACK_CONTINUE;
}

int callback_openid_userinfo_valid_char (const struct _u_request * request, struct _u_response * response, void * user_data) {
  if (0 == o_strcmp(u_map_get(request->map_header, "Authorization"), "Bearer " ACCESS_TOKEN)) {
    ulfius_set_string_body_response(response, 200, userinfo_char);
  } else {
    response->status = 401;
  }
  return U_CALLBACK_CONTINUE;
}

int callback_openid_userinfo_valid_empty_result (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_CALLBACK_CONTINUE;
}

int callback_openid_userinfo_invalid_response (const struct _u_request * request, struct _u_response * response, void * user_data) {
  response->status = 401;
  return U_CALLBACK_CONTINUE;
}

int callback_openid_userinfo_valid_jwt_signed (const struct _u_request * request, struct _u_response * response, void * user_data) {
  jwt_t * jwt;
  jwk_t * jwk;
  char * token = NULL;
  
  r_jwt_init(&jwt);
  r_jwk_init(&jwk);
  r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str);
  r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256);
  r_jwt_set_full_claims_json_str(jwt, userinfo_json);
  if (0 == o_strcmp(u_map_get(request->map_header, "Authorization"), "Bearer " ACCESS_TOKEN)) {
    token = r_jwt_serialize_signed(jwt, jwk, 0);
    u_map_put(response->map_header, "Content-Type", "application/jwt");
    ulfius_set_string_body_response(response, 200, token);
  } else {
    response->status = 401;
  }
  r_jwt_free(jwt);
  r_jwk_free(jwk);
  r_free(token);
  return U_CALLBACK_CONTINUE;
}

int callback_openid_userinfo_valid_jwt_encrypted (const struct _u_request * request, struct _u_response * response, void * user_data) {
  jwt_t * jwt;
  jwk_t * jwk;
  char * token = NULL;
  
  r_jwt_init(&jwt);
  r_jwk_init(&jwk);
  r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_str);
  r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5);
  r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC);
  r_jwt_set_full_claims_json_str(jwt, userinfo_json);
  if (0 == o_strcmp(u_map_get(request->map_header, "Authorization"), "Bearer " ACCESS_TOKEN)) {
    token = r_jwt_serialize_encrypted(jwt, jwk, 0);
    u_map_put(response->map_header, "Content-Type", "application/jwt");
    ulfius_set_string_body_response(response, 200, token);
  } else {
    response->status = 401;
  }
  r_jwt_free(jwt);
  r_jwk_free(jwk);
  r_free(token);
  return U_CALLBACK_CONTINUE;
}

int callback_openid_userinfo_valid_jwt_nested (const struct _u_request * request, struct _u_response * response, void * user_data) {
  jwt_t * jwt;
  jwk_t * jwk_encrypt, * jwk_sign;
  char * token = NULL;
  
  r_jwt_init(&jwt);
  r_jwk_init(&jwk_encrypt);
  r_jwk_init(&jwk_sign);
  r_jwk_import_from_json_str(jwk_encrypt, jwk_pubkey_rsa_str);
  r_jwk_import_from_json_str(jwk_sign, jwk_privkey_rsa_str_2);
  r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5);
  r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC);
  r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256);
  r_jwt_set_full_claims_json_str(jwt, userinfo_json);
  if (0 == o_strcmp(u_map_get(request->map_header, "Authorization"), "Bearer " ACCESS_TOKEN)) {
    token = r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT, jwk_sign, 0, jwk_encrypt, 0);
    u_map_put(response->map_header, "Content-Type", "application/jwt");
    ulfius_set_string_body_response(response, 200, token);
  } else {
    response->status = 401;
  }
  r_jwt_free(jwt);
  r_jwk_free(jwk_encrypt);
  r_jwk_free(jwk_sign);
  r_free(token);
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_iddawc_userinfo_invalid_parameters)
{
  struct _i_session i_session;
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_get_userinfo(&i_session, 0), I_ERROR_PARAM);
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_USERINFO_ENDPOINT, "http://localhost:8080/userinfo",
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_get_userinfo(&i_session, 0), I_ERROR_PARAM);
  i_clean_session(&i_session);
}
END_TEST

START_TEST(test_iddawc_userinfo_invalid_response)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_openid_userinfo_invalid_response, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_USERINFO_ENDPOINT, "http://localhost:8080/userinfo",
                                                    I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_get_userinfo(&i_session, 0), I_ERROR_UNAUTHORIZED);
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_userinfo_response_unauthorized)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_openid_userinfo_valid_json, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_USERINFO_ENDPOINT, "http://localhost:8080/userinfo",
                                                    I_OPT_ACCESS_TOKEN, "error",
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_get_userinfo(&i_session, 0), I_ERROR_UNAUTHORIZED);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_USERINFO), NULL);
  ck_assert_ptr_eq(i_session.j_userinfo, NULL);
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_userinfo_response_empty)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_openid_userinfo_valid_empty_result, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_USERINFO_ENDPOINT, "http://localhost:8080/userinfo",
                                                    I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_get_userinfo(&i_session, 0), I_ERROR);
  ck_assert_ptr_eq(i_get_str_parameter(&i_session, I_OPT_USERINFO), NULL);
  ck_assert_ptr_eq(i_session.j_userinfo, NULL);
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_userinfo_response_char)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_openid_userinfo_valid_char, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_USERINFO_ENDPOINT, "http://localhost:8080/userinfo",
                                                    I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_get_userinfo(&i_session, 0), I_OK);
  ck_assert_str_eq(i_get_str_parameter(&i_session, I_OPT_USERINFO), userinfo_char);
  ck_assert_ptr_eq(i_session.j_userinfo, NULL);
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_userinfo_response_json)
{
  struct _i_session i_session;
  struct _u_instance instance;
  json_t * j_userinfo = json_loads(userinfo_json, JSON_DECODE_ANY, NULL);
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_openid_userinfo_valid_json, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_USERINFO_ENDPOINT, "http://localhost:8080/userinfo",
                                                    I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_get_userinfo(&i_session, 0), I_OK);
  ck_assert_int_eq(json_equal(i_session.j_userinfo, j_userinfo), 1);
  i_clean_session(&i_session);
  json_decref(j_userinfo);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_userinfo_response_json_dpop)
{
  struct _i_session i_session;
  struct _u_instance instance;
  json_t * j_userinfo = json_loads(userinfo_json, JSON_DECODE_ANY, NULL);
  jwk_t * jwk;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_openid_userinfo_valid_json_dpop, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_USERINFO_ENDPOINT, "http://localhost:8080/userinfo",
                                                    I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_USE_DPOP, 1,
                                                    I_OPT_TOKEN_JTI_GENERATE, 16,
                                                    I_OPT_DPOP_SIGN_ALG, "RS256",
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_get_userinfo(&i_session, 0), I_OK);
  ck_assert_int_eq(json_equal(i_session.j_userinfo, j_userinfo), 1);
  i_clean_session(&i_session);
  json_decref(j_userinfo);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_userinfo_response_json_dpop_nonce)
{
  struct _i_session i_session;
  struct _u_instance instance;
  json_t * j_userinfo = json_loads(userinfo_json, JSON_DECODE_ANY, NULL);
  jwk_t * jwk;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_openid_userinfo_valid_json_dpop_nonce, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_USERINFO_ENDPOINT, "http://localhost:8080/userinfo",
                                                    I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_USE_DPOP, 1,
                                                    I_OPT_TOKEN_JTI_GENERATE, 16,
                                                    I_OPT_DPOP_SIGN_ALG, "RS256",
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_DPOP_NONCE_RS));
  ck_assert_int_eq(i_get_userinfo(&i_session, 0), I_ERROR_PARAM);
  ck_assert_ptr_ne(NULL, i_get_str_parameter(&i_session, I_OPT_DPOP_NONCE_RS));
  ck_assert_int_eq(i_get_userinfo(&i_session, 0), I_OK);
  ck_assert_int_eq(json_equal(i_session.j_userinfo, j_userinfo), 1);
  i_clean_session(&i_session);
  json_decref(j_userinfo);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_userinfo_response_json_dpop_invalid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  jwk_t * jwk;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_openid_userinfo_valid_json_dpop, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_USERINFO_ENDPOINT, "http://localhost:8080/userinfo",
                                                    I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_USE_DPOP, 0,
                                                    I_OPT_TOKEN_JTI_GENERATE, 16,
                                                    I_OPT_DPOP_SIGN_ALG, "RS256",
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(i_get_userinfo(&i_session, 0), I_ERROR_UNAUTHORIZED);
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_userinfo_response_jwt_signed)
{
  struct _i_session i_session;
  struct _u_instance instance;
  jwk_t * jwk_sign;
  json_t * j_userinfo = json_loads(userinfo_json, JSON_DECODE_ANY, NULL);
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_openid_userinfo_valid_jwt_signed, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_sign), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_sign, jwk_pubkey_rsa_str), RHN_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_USERINFO_ENDPOINT, "http://localhost:8080/userinfo",
                                                    I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_sign), RHN_OK);
  ck_assert_int_eq(i_get_userinfo(&i_session, 1), I_OK);
  ck_assert_int_eq(json_equal(i_session.j_userinfo, j_userinfo), 1);
  i_clean_session(&i_session);
  json_decref(j_userinfo);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  r_jwk_free(jwk_sign);
}
END_TEST

START_TEST(test_iddawc_userinfo_response_jwt_nested)
{
  struct _i_session i_session;
  struct _u_instance instance;
  jwk_t * jwk_decrypt, * jwk_verify;
  json_t * j_userinfo = json_loads(userinfo_json, JSON_DECODE_ANY, NULL);
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/userinfo", 0, &callback_openid_userinfo_valid_jwt_nested, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_verify), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_decrypt, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_verify, jwk_pubkey_rsa_str_2), RHN_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_USERINFO_ENDPOINT, "http://localhost:8080/userinfo",
                                                    I_OPT_ACCESS_TOKEN, ACCESS_TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.client_jwks, jwk_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(i_session.server_jwks, jwk_verify), RHN_OK);
  ck_assert_int_eq(i_get_userinfo(&i_session, 1), I_OK);
  ck_assert_int_eq(json_equal(i_session.j_userinfo, j_userinfo), 1);
  i_clean_session(&i_session);
  json_decref(j_userinfo);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  r_jwk_free(jwk_decrypt);
  r_jwk_free(jwk_verify);
}
END_TEST

static Suite *iddawc_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Iddawc oauth2 flow tests");
  tc_core = tcase_create("test_iddawc_oauth2");
  tcase_add_test(tc_core, test_iddawc_userinfo_invalid_parameters);
  tcase_add_test(tc_core, test_iddawc_userinfo_invalid_response);
  tcase_add_test(tc_core, test_iddawc_userinfo_response_unauthorized);
  tcase_add_test(tc_core, test_iddawc_userinfo_response_empty);
  tcase_add_test(tc_core, test_iddawc_userinfo_response_char);
  tcase_add_test(tc_core, test_iddawc_userinfo_response_json);
  tcase_add_test(tc_core, test_iddawc_userinfo_response_json_dpop);
  tcase_add_test(tc_core, test_iddawc_userinfo_response_json_dpop_nonce);
  tcase_add_test(tc_core, test_iddawc_userinfo_response_json_dpop_invalid);
  tcase_add_test(tc_core, test_iddawc_userinfo_response_jwt_signed);
  tcase_add_test(tc_core, test_iddawc_userinfo_response_jwt_nested);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc oidc userinfo loader tests");
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
