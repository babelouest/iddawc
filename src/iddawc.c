/**
 *
 * Iddawc OAuth2 client library
 *
 * iddawc.c: library implementation
 *
 * Copyright 2019-2022 Nicolas Mora <mail@babelouest.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdarg.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <yder.h>

#include "iddawc.h"

/**
 *
 * Generates a random long integer between 0 and max
 *
 */
unsigned char random_at_most(unsigned char max, int nonce) {
  unsigned char
  num_bins = (unsigned char) max + 1,
  num_rand = (unsigned char) 0xff,
  bin_size = num_rand / num_bins,
  defect   = num_rand % num_bins;

  unsigned char x[1];
  do {
    gnutls_rnd(nonce?GNUTLS_RND_NONCE:GNUTLS_RND_KEY, x, sizeof(x));
  }
  // This is carefully written not to overflow
  while (num_rand - defect <= (unsigned char)x[0]);

  // Truncated division is intentional
  return x[0]/bin_size;
}

static int string_use_char_list_only(const char * str, const char * char_list) {
  int ret = 1;
  size_t i;

  if (o_strlen(str) && o_strlen(char_list)) {
    for (i=0; i<o_strlen(str); i++) {
      if (o_strchr(char_list, str[i]) == NULL) {
        ret = 0;
        break;
      }
    }
  } else {
    ret = 0;
  }
  return ret;
}

/**
 * return true if the JSON array has a element matching value
 */
static int _i_json_array_has_string(json_t * j_array, const char * value) {
  json_t * j_element = NULL;
  size_t index = 0;

  json_array_foreach(j_array, index, j_element) {
    if (json_is_string(j_element) && 0 == o_strcmp(value, json_string_value(j_element))) {
      return 1;
    }
  }
  return 0;
}

/**
 * Generates a random string used as nonce and store it in str
 */
static char * rand_string_nonce(char * str, size_t str_size) {
  const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  size_t n;

  if (str_size && str != NULL) {
    for (n = 0; n < str_size; n++) {
      str[n] = charset[random_at_most((sizeof(charset)) - 2, 1)];
    }
    str[str_size] = '\0';
    return str;
  } else {
    return NULL;
  }
}

static int _i_has_claims(struct _i_session * i_session) {
  return json_object_size(json_object_get(i_session->j_claims, "userinfo")) && json_object_size(json_object_get(i_session->j_claims, "id_token"));
}

static int _i_init_request(struct _i_session * i_session, struct _u_request * request) {
  int ret, flag_host = 0, flag_proxy = 0;

  if (i_session->remote_cert_flag & I_REMOTE_HOST_VERIFY_PEER) {
    flag_host |= U_SSL_VERIFY_PEER;
  }
  if (i_session->remote_cert_flag & I_REMOTE_HOST_VERIFY_HOSTNAME) {
    flag_host |= U_SSL_VERIFY_HOSTNAME;
  }
  if (i_session->remote_cert_flag & I_REMOTE_PROXY_VERIFY_PEER) {
    flag_proxy |= U_SSL_VERIFY_PEER;
  }
  if (i_session->remote_cert_flag & I_REMOTE_PROXY_VERIFY_HOSTNAME) {
    flag_proxy |= U_SSL_VERIFY_HOSTNAME;
  }

  if (ulfius_init_request(request) == U_OK) {
    if (ulfius_set_request_properties(request, U_OPT_CHECK_SERVER_CERTIFICATE_FLAG, flag_host, U_OPT_CHECK_PROXY_CERTIFICATE_FLAG, flag_proxy, U_OPT_NONE) == U_OK) {
      ret = I_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "_i_init_request - Error setting TLS flags");
      ret = I_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "_i_init_request - Error init request");
    ret = I_ERROR;
  }
  return ret;
}

static const char * _i_get_endpoint(struct _i_session * i_session, const char * endpoint_id) {
  const char * endpoint = NULL;
  int use_tls = (i_session->token_method & I_TOKEN_AUTH_METHOD_TLS_CERTIFICATE);
  if (0 == o_strcmp("token", endpoint_id)) {
    if (use_tls && (endpoint = json_string_value(json_object_get(json_object_get(i_session->openid_config, "mtls_endpoint_aliases"), "token_endpoint"))) != NULL) {
      return endpoint;
    } else {
      return i_session->token_endpoint;
    }
  } else if (0 == o_strcmp("device", endpoint_id)) {
    if (use_tls && (endpoint = json_string_value(json_object_get(json_object_get(i_session->openid_config, "mtls_endpoint_aliases"), "device_authorization_endpoint"))) != NULL) {
      return endpoint;
    } else {
      return i_session->device_authorization_endpoint;
    }
  } else if (0 == o_strcmp("revocation", endpoint_id)) {
    if (use_tls && (endpoint = json_string_value(json_object_get(json_object_get(i_session->openid_config, "mtls_endpoint_aliases"), "revocation_endpoint"))) != NULL) {
      return endpoint;
    } else {
      return i_session->revocation_endpoint;
    }
  } else if (0 == o_strcmp("introspection", endpoint_id)) {
    if (use_tls && (endpoint = json_string_value(json_object_get(json_object_get(i_session->openid_config, "mtls_endpoint_aliases"), "introspection_endpoint"))) != NULL) {
      return endpoint;
    } else {
      return i_session->introspection_endpoint;
    }
  } else if (0 == o_strcmp("par", endpoint_id)) {
    if (use_tls && (endpoint = json_string_value(json_object_get(json_object_get(i_session->openid_config, "mtls_endpoint_aliases"), "pushed_authorization_request_endpoint"))) != NULL) {
      return endpoint;
    } else {
      return i_session->pushed_authorization_request_endpoint;
    }
  } else if (0 == o_strcmp("ciba", endpoint_id)) {
    if (use_tls && (endpoint = json_string_value(json_object_get(json_object_get(i_session->openid_config, "mtls_endpoint_aliases"), "backchannel_authentication_endpoint"))) != NULL) {
      return endpoint;
    } else {
      return i_session->ciba_endpoint;
    }
  } else {
    return NULL;
  }
}

static char * _i_decrypt_jwe_token(struct _i_session * i_session, const char * token) {
  jwe_t * jwe = NULL;
  jwk_t * jwk_dec = NULL;
  char * payload_dup = NULL;
  const unsigned char * payload;
  size_t payload_len = 0;

  if (r_jwe_init(&jwe) == RHN_OK) {
    if (r_jwe_advanced_parse(jwe, token, R_PARSE_NONE, i_session->x5u_flags) == RHN_OK) {
      if ((i_session->client_kid != NULL && (jwk_dec = r_jwks_get_by_kid(i_session->client_jwks, i_session->client_kid)) != NULL) || (r_jwks_size(i_session->client_jwks) == 1 && (jwk_dec = r_jwks_get_at(i_session->client_jwks, 0)) != NULL)) {
        if (r_jwe_decrypt(jwe, jwk_dec, i_session->x5u_flags) == RHN_OK) {
          payload = r_jwe_get_payload(jwe, &payload_len);
          payload_dup = o_strndup((const char *)payload, payload_len);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_decrypt_jwe_token - Error r_jwe_decrypt");
        }
      } else if (!r_jwks_size(i_session->client_jwks)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_i_decrypt_jwe_token - Client has no private key");
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "_i_decrypt_jwe_token - Client has more than one private key, please specify one with the parameter I_OPT_CLIENT_KID");
      }
      r_jwk_free(jwk_dec);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "_i_decrypt_jwe_token - Error r_jwe_advanced_parse");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "_i_decrypt_jwe_token - Error r_jwe_init");
  }
  r_jwe_free(jwe);

  return payload_dup;
}

static const char * _i_get_parameter_key(int token_type, const char * key_type) {
  const char * param = NULL;
  switch (token_type) {
    case I_TOKEN_TYPE_ACCESS_TOKEN:
      if (0 == o_strcmp("signing_alg_values_supported", key_type)) {
        param = "access_token_signing_alg_values_supported";
      } else if (0 == o_strcmp("encryption_alg_values_supported", key_type)) {
        param = "access_token_encryption_alg_values_supported";
      } else if (0 == o_strcmp("encryption_enc_values_supported", key_type)) {
        param = "access_token_encryption_enc_values_supported";
      }
      break;
    case I_TOKEN_TYPE_ID_TOKEN:
      if (0 == o_strcmp("signing_alg_values_supported", key_type)) {
        param = "id_token_signing_alg_values_supported";
      } else if (0 == o_strcmp("encryption_alg_values_supported", key_type)) {
        param = "id_token_encryption_alg_values_supported";
      } else if (0 == o_strcmp("encryption_enc_values_supported", key_type)) {
        param = "id_token_encryption_enc_values_supported";
      }
      break;
    case I_TOKEN_TYPE_USERINFO:
      if (0 == o_strcmp("signing_alg_values_supported", key_type)) {
        param = "userinfo_signing_alg_values_supported";
      } else if (0 == o_strcmp("encryption_alg_values_supported", key_type)) {
        param = "userinfo_encryption_alg_values_supported";
      } else if (0 == o_strcmp("encryption_enc_values_supported", key_type)) {
        param = "userinfo_encryption_enc_values_supported";
      }
      break;
    case I_TOKEN_TYPE_INTROSPECTION:
      if (0 == o_strcmp("signing_alg_values_supported", key_type)) {
        param = "introspection_signing_alg_values_supported";
      } else if (0 == o_strcmp("encryption_alg_values_supported", key_type)) {
        param = "introspection_encryption_alg_values_supported";
      } else if (0 == o_strcmp("encryption_enc_values_supported", key_type)) {
        param = "introspection_encryption_enc_values_supported";
      }
      break;
    default:
      break;
  }
  return param;
}

static const char * _i_get_response_type(unsigned int response_type) {
  static char result[32] = {0};
  switch (response_type) {
    case I_RESPONSE_TYPE_CODE:
      o_strcpy(result, "code");
      break;
    case I_RESPONSE_TYPE_TOKEN:
      o_strcpy(result, "token");
      break;
    case I_RESPONSE_TYPE_ID_TOKEN:
      o_strcpy(result, "id_token");
      break;
    case I_RESPONSE_TYPE_PASSWORD:
      o_strcpy(result, "password");
      break;
    case I_RESPONSE_TYPE_CLIENT_CREDENTIALS:
      o_strcpy(result, "client_credentials");
      break;
    case I_RESPONSE_TYPE_REFRESH_TOKEN:
      o_strcpy(result, "refresh_token");
      break;
    case I_RESPONSE_TYPE_CODE|I_RESPONSE_TYPE_ID_TOKEN:
      o_strcpy(result, "code id_token");
      break;
    case I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_ID_TOKEN:
      o_strcpy(result, "token id_token");
      break;
    case I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_CODE|I_RESPONSE_TYPE_ID_TOKEN:
      o_strcpy(result, "code token id_token");
      break;
    case I_RESPONSE_TYPE_DEVICE_CODE:
      o_strcpy(result, "device_code");
      break;
    case I_RESPONSE_TYPE_CIBA:
      o_strcpy(result, "ciba");
      break;
    default:
      o_strcpy(result, "");
      break;
  }
  return result;
}

static int _i_has_openid_config_parameter_value(struct _i_session * i_session, const char * parameter, const char * value) {
  int ret;
  size_t index = 0;
  json_t * j_element = NULL, * j_param;

  if (i_session != NULL) {
    if (i_session->openid_config_strict == I_STRICT_YES) {
      if (i_session->openid_config != NULL && (j_param = json_object_get(i_session->openid_config, parameter)) != NULL) {
        if (json_is_string(json_object_get(i_session->openid_config, parameter))) {
          if (0 == o_strcmp(value, json_string_value(j_param))) {
            ret = 1;
          } else {
            ret = 0;
          }
        } else if (json_is_array(j_param)) {
          ret = 0;
          json_array_foreach(j_param, index, j_element) {
            if (0 == o_strcmp(value, json_string_value(j_element))) {
              ret = 1;
            }
          }
        } else {
          ret = 0;
        }
      } else {
        ret = 1;
      }
    } else {
      ret = 1;
    }
  } else {
    ret = 0;
  }
  return ret;
}

static int _i_verify_jwt_sig_enc(struct _i_session * i_session, const char * token, int token_type, jwt_t * jwt) {
  int ret = I_ERROR_PARAM, res = RHN_ERROR;
  jwk_t * jwk_sign;

  if (i_session != NULL && token != NULL) {
    if (r_jwt_advanced_parse(jwt, token, R_PARSE_NONE, i_session->x5u_flags) == RHN_OK) {
      if (r_jwt_get_sign_alg(jwt) != R_JWA_ALG_NONE &&
          _i_has_openid_config_parameter_value(i_session, _i_get_parameter_key(token_type, "signing_alg_values_supported"), r_jwa_alg_to_str(r_jwt_get_sign_alg(jwt)))) {
        if (r_jwks_size(i_session->server_jwks) > 1) {
          jwk_sign = r_jwks_get_by_kid(i_session->server_jwks, r_jwt_get_header_str_value(jwt, "kid"));
        } else {
          jwk_sign = r_jwks_get_at(i_session->server_jwks, 0);
        }
        if (r_jwt_add_enc_jwks(jwt, i_session->client_jwks, NULL) == RHN_OK) {
          if (jwt->type == R_JWT_TYPE_SIGN) {
            res = r_jwt_verify_signature(jwt, jwk_sign, i_session->x5u_flags);
          } else if (jwt->type == R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT) {
            if (_i_has_openid_config_parameter_value(i_session, _i_get_parameter_key(token_type, "encryption_alg_values_supported"), r_jwa_alg_to_str(r_jwt_get_enc_alg(jwt))) &&
                _i_has_openid_config_parameter_value(i_session, _i_get_parameter_key(token_type, "encryption_enc_values_supported"), r_jwa_enc_to_str(r_jwt_get_enc(jwt)))) {
              res = r_jwt_decrypt_verify_signature_nested(jwt, jwk_sign, i_session->x5u_flags, NULL, i_session->x5u_flags);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_jwt_access_token - Error invalid jwt encryption");
              res = I_ERROR;
            }
          }
          if (res == RHN_OK) {
            // expected typ value is recommended but not mandatory
            switch (token_type) {
              case I_TOKEN_TYPE_ACCESS_TOKEN:
                if (0 != o_strcmp("at+jwt", r_jwt_get_header_str_value(jwt, "typ"))) {
                  y_log_message(Y_LOG_LEVEL_DEBUG, "Invalid jwt 'typ' value, expected: 'at+jwt', result: '%s'", r_jwt_get_header_str_value(jwt, "typ"));
                }
                if (i_session->openid_config_strict == I_STRICT_YES) {
                  if (i_session->access_token_signing_alg != R_JWA_ALG_UNKNOWN && i_session->access_token_signing_alg != r_jwt_get_sign_alg(jwt)) {
                    y_log_message(Y_LOG_LEVEL_DEBUG, "Invalid jwt access token sign alg value: '%s'", r_jwa_alg_to_str(r_jwt_get_sign_alg(jwt)));
                  }
                  if (i_session->access_token_encryption_alg != R_JWA_ALG_UNKNOWN && i_session->access_token_encryption_alg != r_jwt_get_enc_alg(jwt)) {
                    y_log_message(Y_LOG_LEVEL_DEBUG, "Invalid jwt access token enc alg value: '%s'", r_jwa_alg_to_str(r_jwt_get_enc_alg(jwt)));
                  }
                  if (i_session->access_token_encryption_enc != R_JWA_ENC_UNKNOWN && i_session->access_token_encryption_enc != r_jwt_get_enc(jwt)) {
                    y_log_message(Y_LOG_LEVEL_DEBUG, "Invalid jwt access token enc alg value: '%s'", r_jwa_enc_to_str(r_jwt_get_enc(jwt)));
                  }
                }
                break;
              case I_TOKEN_TYPE_USERINFO:
                if (i_session->openid_config_strict == I_STRICT_YES) {
                  if (i_session->userinfo_signing_alg != R_JWA_ALG_UNKNOWN && i_session->userinfo_signing_alg != r_jwt_get_sign_alg(jwt)) {
                    y_log_message(Y_LOG_LEVEL_DEBUG, "Invalid jwt userinfo sign alg value: '%s'", r_jwa_alg_to_str(r_jwt_get_sign_alg(jwt)));
                  }
                  if (i_session->userinfo_encryption_alg != R_JWA_ALG_UNKNOWN && i_session->userinfo_encryption_alg != r_jwt_get_enc_alg(jwt)) {
                    y_log_message(Y_LOG_LEVEL_DEBUG, "Invalid jwt userinfo enc alg value: '%s'", r_jwa_alg_to_str(r_jwt_get_enc_alg(jwt)));
                  }
                  if (i_session->userinfo_encryption_enc != R_JWA_ENC_UNKNOWN && i_session->userinfo_encryption_enc != r_jwt_get_enc(jwt)) {
                    y_log_message(Y_LOG_LEVEL_DEBUG, "Invalid jwt userinfo enc alg value: '%s'", r_jwa_enc_to_str(r_jwt_get_enc(jwt)));
                  }
                }
                if (0 != o_strcmp("token-userinfo+jwt", r_jwt_get_header_str_value(jwt, "typ"))) {
                  y_log_message(Y_LOG_LEVEL_DEBUG, "Invalid jwt 'typ' value, expected: 'token-userinfo+jwt', result: '%s'", r_jwt_get_header_str_value(jwt, "typ"));
                }
                break;
              case I_TOKEN_TYPE_INTROSPECTION:
                if (0 != o_strcmp("token-introspection+jwt", r_jwt_get_header_str_value(jwt, "typ"))) {
                  y_log_message(Y_LOG_LEVEL_DEBUG, "Invalid jwt 'typ' value, expected: 'token-introspection+jwt', result: '%s'", r_jwt_get_header_str_value(jwt, "typ"));
                }
                break;
              case I_TOKEN_TYPE_ID_TOKEN:
                // I don't see any typ value for id_token in the specs, weird eh?
                if (i_session->openid_config_strict == I_STRICT_YES) {
                  if (i_session->id_token_signing_alg != R_JWA_ALG_UNKNOWN && i_session->id_token_signing_alg != r_jwt_get_sign_alg(jwt)) {
                    y_log_message(Y_LOG_LEVEL_DEBUG, "Invalid jwt id token sign alg value: '%s'", r_jwa_alg_to_str(r_jwt_get_sign_alg(jwt)));
                  }
                  if (i_session->id_token_encryption_alg != R_JWA_ALG_UNKNOWN && i_session->id_token_encryption_alg != r_jwt_get_enc_alg(jwt)) {
                    y_log_message(Y_LOG_LEVEL_DEBUG, "Invalid jwt id token enc alg value: '%s'", r_jwa_alg_to_str(r_jwt_get_enc_alg(jwt)));
                  }
                  if (i_session->id_token_encryption_enc != R_JWA_ENC_UNKNOWN && i_session->id_token_encryption_enc != r_jwt_get_enc(jwt)) {
                    y_log_message(Y_LOG_LEVEL_DEBUG, "Invalid jwt id token enc alg value: '%s'", r_jwa_enc_to_str(r_jwt_get_enc(jwt)));
                  }
                }
                break;
              case I_TOKEN_TYPE_RESPONSE_AUTH:
                if (i_session->openid_config_strict == I_STRICT_YES) {
                  if (i_session->auth_response_signing_alg != R_JWA_ALG_UNKNOWN && i_session->auth_response_signing_alg != r_jwt_get_sign_alg(jwt)) {
                    y_log_message(Y_LOG_LEVEL_DEBUG, "Invalid jwt response auth sign alg value: '%s'", r_jwa_alg_to_str(r_jwt_get_sign_alg(jwt)));
                  }
                  if (i_session->auth_response_encryption_alg != R_JWA_ALG_UNKNOWN && i_session->auth_response_encryption_alg != r_jwt_get_enc_alg(jwt)) {
                    y_log_message(Y_LOG_LEVEL_DEBUG, "Invalid jwt response auth enc alg value: '%s'", r_jwa_alg_to_str(r_jwt_get_enc_alg(jwt)));
                  }
                  if (i_session->auth_response_encryption_enc != R_JWA_ENC_UNKNOWN && i_session->auth_response_encryption_enc != r_jwt_get_enc(jwt)) {
                    y_log_message(Y_LOG_LEVEL_DEBUG, "Invalid jwt response auth enc alg value: '%s'", r_jwa_enc_to_str(r_jwt_get_enc(jwt)));
                  }
                }
                break;
              default:
                break;
            }
            ret = I_OK;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_jwt_access_token - Error token validation");
            ret = I_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_jwt_access_token - Error Adding JWKS to jwt");
          ret = I_ERROR;
        }
        r_jwk_free(jwk_sign);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_jwt_access_token - Error invalid jwt signature");
        ret = I_ERROR_UNAUTHORIZED;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_jwt_access_token - Error parsing access_token");
      ret = I_ERROR_PARAM;
    }
  } else {
    ret = I_ERROR_PARAM;
  }

  return ret;
}

static int _i_parse_jwt_response(struct _i_session * i_session, const char * token, struct _u_map * map) {
  int ret;
  jwt_t * jwt = NULL;
  json_t * j_claims, * j_element = NULL;
  const char * key = NULL;
  
  if (r_jwt_init(&jwt) == RHN_OK) {
    if ((ret = _i_verify_jwt_sig_enc(i_session, token, I_TOKEN_TYPE_RESPONSE_AUTH, jwt)) == I_OK) {
      if (r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, i_get_str_parameter(i_session, I_OPT_ISSUER),
                                     R_JWT_CLAIM_AUD, i_get_str_parameter(i_session, I_OPT_CLIENT_ID),
                                     R_JWT_CLAIM_EXP, R_JWT_CLAIM_NOW,
                                     R_JWT_CLAIM_NOP) == RHN_OK) {
        j_claims = r_jwt_get_full_claims_json_t(jwt);
        json_object_foreach(j_claims, key, j_element) {
          if (json_is_string(j_element)) {
            u_map_put(map, key, json_string_value(j_element));
          }
        }
        json_decref(j_claims);
        ret = I_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_jwt_response - Error invalid mandatory claims");
        ret = I_ERROR_SERVER;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_jwt_response - Error r_jwt_init");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_jwt_response - Error r_jwt_init");
    ret = I_ERROR;
  }
  r_jwt_free(jwt);
  return ret;
}

static int _i_extract_parameters(struct _i_session * i_session, const char * url_params, struct _u_map * map) {
  char ** unescaped_parameters = NULL, * key, * value;
  size_t offset = 0;
  int ret = I_OK;

  if (split_string(url_params, "&", &unescaped_parameters)) {
    for (offset = 0; ret == I_OK && unescaped_parameters[offset] != NULL; offset++) {
      if (o_strchr(unescaped_parameters[offset], '=') != NULL) {
        key = o_strndup(unescaped_parameters[offset], o_strchr(unescaped_parameters[offset], '=') - unescaped_parameters[offset]);
        value = ulfius_url_decode(o_strchr(unescaped_parameters[offset], '=')+1);
        if (0 == o_strcmp("response", key)) {
          ret = _i_parse_jwt_response(i_session, value, map);
        } else {
          u_map_put(map, key, value);
        }
        o_free(key);
        o_free(value);
      } else {
        u_map_put(map, unescaped_parameters[offset], NULL);
      }
    }
    free_string_array(unescaped_parameters);
  } else {
    ret = I_ERROR;
  }
  return ret;
}

static int _i_parse_redirect_to_parameters(struct _i_session * i_session, struct _u_map * map) {
  const char ** keys = u_map_enum_keys(map), * key = NULL;
  size_t i;
  int ret = I_OK, c_ret;
  char * endptr = NULL, * payload_dup = NULL;
  long expires_in = 0;
  time_t expires_at;

  for (i=0; keys[i] != NULL; i++) {
    key = keys[i];
    if (0 == o_strcasecmp(key, "code") && (i_get_response_type(i_session) & I_RESPONSE_TYPE_CODE) && o_strlen(u_map_get(map, key))) {
      if (i_session->decrypt_code) {
        if ((payload_dup = _i_decrypt_jwe_token(i_session, u_map_get(map, key))) != NULL) {
          c_ret = i_set_str_parameter(i_session, I_OPT_CODE, payload_dup);
          ret = ret!=I_OK?ret:c_ret;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_redirect_to_parameters - Error _i_decrypt_jwe_token code");
          ret = I_ERROR_PARAM;
        }
        o_free(payload_dup);
        payload_dup = NULL;
      } else {
        c_ret = i_set_str_parameter(i_session, I_OPT_CODE, u_map_get(map, key));
        ret = ret!=I_OK?ret:c_ret;
      }
    } else if (0 == o_strcasecmp(key, "id_token") && i_get_response_type(i_session) & I_RESPONSE_TYPE_ID_TOKEN && o_strlen(u_map_get(map, key))) {
      c_ret = i_set_str_parameter(i_session, I_OPT_ID_TOKEN, u_map_get(map, key));
      ret = ret!=I_OK?ret:c_ret;
    } else if (0 == o_strcasecmp(key, "access_token") && (i_get_response_type(i_session) & I_RESPONSE_TYPE_TOKEN) && o_strlen(u_map_get(map, key))) {
      if (i_session->decrypt_access_token) {
        if ((payload_dup = _i_decrypt_jwe_token(i_session, u_map_get(map, key))) != NULL) {
          c_ret = i_set_str_parameter(i_session, I_OPT_ACCESS_TOKEN, payload_dup);
          ret = ret!=I_OK?ret:c_ret;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_redirect_to_parameters - Error _i_decrypt_jwe_token access_token");
          ret = I_ERROR;
        }
        o_free(payload_dup);
        payload_dup = NULL;
      } else {
        c_ret = i_set_str_parameter(i_session, I_OPT_ACCESS_TOKEN, u_map_get(map, key));
        ret = ret!=I_OK?ret:c_ret;
        if (!o_strlen(u_map_get_case(map, "token_type"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_redirect_to_parameters - Got parameter token but token_type is missing");
          ret = ret!=I_OK?ret:I_ERROR_SERVER;
        }
      }
    } else if (0 == o_strcasecmp(key, "token_type")) {
      c_ret = i_set_str_parameter(i_session, I_OPT_TOKEN_TYPE, u_map_get(map, key));
      ret = ret!=I_OK?ret:c_ret;
    } else if (0 == o_strcasecmp(key, "expires_in")) {
      expires_in = strtol(u_map_get(map, key), &endptr, 10);
      time(&expires_at);
      expires_at += (time_t)expires_in;
      if (endptr != (char *)u_map_get(map, key)) {
        if (i_set_int_parameter(i_session, I_OPT_EXPIRES_IN, (unsigned int)expires_in) != I_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_redirect_to_parameters - expires_in invalid");
          ret = ret!=I_OK?ret:I_ERROR_SERVER;
        }
        if (i_set_int_parameter(i_session, I_OPT_EXPIRES_AT, (unsigned int)expires_at) != I_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_redirect_to_parameters - expires_at invalid");
          ret = ret!=I_OK?ret:I_ERROR_SERVER;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_redirect_to_parameters - expires_in not numeric");
        ret = I_ERROR_SERVER;
      }
    } else if (0 == o_strcasecmp(key, "iss")) {
      ret = (0==o_strcmp(u_map_get(map, key), i_get_str_parameter(i_session, I_OPT_ISSUER)))?I_OK:I_ERROR_SERVER;
    } else if (0 == o_strcasecmp(key, "error")) {
      c_ret = i_set_result(i_session, I_ERROR_UNAUTHORIZED);
      ret = ret!=I_OK?ret:c_ret;
      c_ret = i_set_str_parameter(i_session, I_OPT_ERROR, u_map_get(map, key));
      ret = ret!=I_OK?ret:c_ret;
    } else if (0 == o_strcasecmp(key, "error_description")) {
      c_ret = i_set_result(i_session, I_ERROR_UNAUTHORIZED);
      ret = ret!=I_OK?ret:c_ret;
      c_ret = i_set_str_parameter(i_session, I_OPT_ERROR_DESCRIPTION, u_map_get(map, key));
      ret = ret!=I_OK?ret:c_ret;
    } else if (0 == o_strcasecmp(key, "error_uri")) {
      c_ret = i_set_result(i_session, I_ERROR_UNAUTHORIZED);
      ret = ret!=I_OK?ret:c_ret;
      c_ret = i_set_str_parameter(i_session, I_OPT_ERROR_URI, u_map_get(map, key));
      ret = ret!=I_OK?ret:c_ret;
    } else {
      c_ret = i_set_additional_response(i_session, key, u_map_get(map, key));
      ret = ret!=I_OK?ret:c_ret;
    }
  }
  return ret;
}

static int _i_parse_error_response(struct _i_session * i_session, json_t * j_response) {
  int ret = I_OK;
  const char * key = NULL;
  json_t * j_element = NULL;
  char * value;

  if (j_response != NULL) {
    if (json_string_length(json_object_get(j_response, "error")) && i_set_str_parameter(i_session, I_OPT_ERROR, json_string_value(json_object_get(j_response, "error"))) != I_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_error_response - Error setting error");
      ret = I_ERROR;
    }
    if (json_string_length(json_object_get(j_response, "error_description")) && i_set_str_parameter(i_session, I_OPT_ERROR_DESCRIPTION, json_string_value(json_object_get(j_response, "error_description"))) != I_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_error_response - Error setting error_description");
      ret = I_ERROR;
    }
    if (json_string_length(json_object_get(j_response, "error_uri")) && i_set_str_parameter(i_session, I_OPT_ERROR_URI, json_string_value(json_object_get(j_response, "error_uri"))) != I_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_error_response - Error setting error_uri");
      ret = I_ERROR;
    }
    json_object_foreach(j_response, key, j_element) {
      if (0 != o_strcmp("error", key) &&
          0 != o_strcmp("error_description", key) &&
          0 != o_strcmp("error_uri", key)) {
        if (json_is_string(j_element)) {
          if (i_set_additional_response(i_session, key, json_string_value(j_element)) != I_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_error_response - Error i_set_additional_response %s - %s", key, json_string_value(j_element));
            ret = I_ERROR;
          }
        } else {
          value = json_dumps(j_element, JSON_ENCODE_ANY);
          if (i_set_additional_response(i_session, key, value) != I_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_error_response - Error i_set_additional_response %s - %s", key, json_string_value(j_element));
            ret = I_ERROR;
          }
          o_free(value);
        }
      }
    }
  }
  return ret;
}

static int _i_load_jwks_endpoint(struct _i_session * i_session) {
  int ret;
  struct _u_request request;
  struct _u_response response;
  json_t * j_jwks = NULL;

  if (i_session != NULL && json_string_length(json_object_get(i_session->openid_config, "jwks_uri"))) {
    _i_init_request(i_session, &request);
    ulfius_init_response(&response);

    ulfius_set_request_properties(&request, U_OPT_HEADER_PARAMETER, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR,
                                            U_OPT_HEADER_PARAMETER, "Accept", "application/json",
                                            U_OPT_HTTP_URL, json_string_value(json_object_get(i_session->openid_config, "jwks_uri")),
                                            U_OPT_NONE);
    if (ulfius_send_http_request(&request, &response) == U_OK) {
      if (response.status == 200 && (NULL != o_strstr(u_map_get_case(response.map_header, ULFIUS_HTTP_HEADER_CONTENT), ULFIUS_HTTP_ENCODING_JSON) || NULL != o_strstr(u_map_get_case(response.map_header, ULFIUS_HTTP_HEADER_CONTENT), I_CONTENT_TYPE_JWKS))) {
        if ((j_jwks = json_loadb(response.binary_body, response.binary_body_length, JSON_DECODE_ANY, NULL)) != NULL) {
          r_jwks_free(i_session->server_jwks);
          r_jwks_init(&i_session->server_jwks);
          if (r_jwks_import_from_json_t(i_session->server_jwks, j_jwks) == RHN_OK) {
            ret = I_OK;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "_i_load_jwks_endpoint - Error r_jwks_import_from_json_str");
            ret = I_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_load_jwks_endpoint - Error loading jwks content");
          ret = I_ERROR;
        }
        json_decref(j_jwks);
      } else if (response.status == 401 || response.status == 403) {
        ret = I_ERROR_UNAUTHORIZED;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "_i_load_jwks_endpoint - Error invalid response status: %d", response.status);
        ret = I_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "_i_load_jwks_endpoint - Error getting config_endpoint");
      ret = I_ERROR;
    }
    ulfius_clean_request(&request);
    ulfius_clean_response(&response);
  } else {
    ret = I_ERROR_PARAM;
  }
  return ret;
}

static int _i_parse_openid_config(struct _i_session * i_session, int get_jwks) {
  int ret, res;
  size_t index = 0;
  json_t * j_element = NULL;

  if (i_session != NULL && json_is_object(i_session->openid_config)) {
    // Check required metadata
    if (json_string_length(json_object_get(i_session->openid_config, "issuer")) &&
        json_string_length(json_object_get(i_session->openid_config, "authorization_endpoint")) &&
        json_string_length(json_object_get(i_session->openid_config, "jwks_uri")) &&
        json_is_array(json_object_get(i_session->openid_config, "response_types_supported")) &&
        json_is_array(json_object_get(i_session->openid_config, "subject_types_supported")) &&
        json_is_array(json_object_get(i_session->openid_config, "id_token_signing_alg_values_supported"))) {
      ret = I_OK;
      do {
        if (i_set_str_parameter(i_session, I_OPT_ISSUER, json_string_value(json_object_get(i_session->openid_config, "issuer"))) != I_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_openid_config - Error setting issuer");
          ret = I_ERROR;
          break;
        }
        if (i_set_str_parameter(i_session, I_OPT_AUTH_ENDPOINT, json_string_value(json_object_get(i_session->openid_config, "authorization_endpoint"))) != I_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_openid_config - Error setting authorization_endpoint");
          ret = I_ERROR;
          break;
        }
        if (get_jwks && (res = _i_load_jwks_endpoint(i_session)) != I_OK && res != I_ERROR_UNAUTHORIZED) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_openid_config - Error _i_load_jwks_endpoint");
          ret = I_ERROR;
          break;
        }
        json_array_foreach(json_object_get(i_session->openid_config, "response_types_supported"), index, j_element) {
          if (!json_string_length(j_element)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_openid_config - Error response_types_supported invalid at index %zu", index);
            ret = I_ERROR;
            break;
          }
        }
        if (ret != I_OK) {
          break;
        }
        json_array_foreach(json_object_get(i_session->openid_config, "subject_types_supported"), index, j_element) {
          if (!json_string_length(j_element)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_openid_config - Error subject_types_supported invalid at index %zu", index);
            ret = I_ERROR;
            break;
          }
        }
        if (ret != I_OK) {
          break;
        }
        json_array_foreach(json_object_get(i_session->openid_config, "id_token_signing_alg_values_supported"), index, j_element) {
          if (!json_string_length(j_element)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_openid_config - Error id_token_signing_alg_values_supported invalid at index %zu", index);
            ret = I_ERROR;
            break;
          }
        }
        if (ret != I_OK) {
          break;
        }
      } while (0);
      if (json_string_length(json_object_get(i_session->openid_config, "token_endpoint"))) {
        if (i_set_str_parameter(i_session, I_OPT_TOKEN_ENDPOINT, json_string_value(json_object_get(i_session->openid_config, "token_endpoint"))) != I_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_openid_config - Error setting token_endpoint");
          ret = I_ERROR;
        }
      }
      if (json_string_length(json_object_get(i_session->openid_config, "userinfo_endpoint"))) {
        if (i_set_str_parameter(i_session, I_OPT_USERINFO_ENDPOINT, json_string_value(json_object_get(i_session->openid_config, "userinfo_endpoint"))) != I_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_openid_config - Error setting userinfo_endpoint");
          ret = I_ERROR;
        }
      }
      if (json_string_length(json_object_get(i_session->openid_config, "revocation_endpoint"))) {
        if (i_set_str_parameter(i_session, I_OPT_REVOCATION_ENDPOINT, json_string_value(json_object_get(i_session->openid_config, "revocation_endpoint"))) != I_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_openid_config - Error setting revocation_endpoint");
          ret = I_ERROR;
        }
      }
      if (json_string_length(json_object_get(i_session->openid_config, "introspection_endpoint"))) {
        if (i_set_str_parameter(i_session, I_OPT_INTROSPECTION_ENDPOINT, json_string_value(json_object_get(i_session->openid_config, "introspection_endpoint"))) != I_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_openid_config - Error setting introspection_endpoint");
          ret = I_ERROR;
        }
      }
      if (json_string_length(json_object_get(i_session->openid_config, "registration_endpoint"))) {
        if (i_set_str_parameter(i_session, I_OPT_REGISTRATION_ENDPOINT, json_string_value(json_object_get(i_session->openid_config, "registration_endpoint"))) != I_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_openid_config - Error setting registration_endpoint");
          ret = I_ERROR;
        }
      }
      if (json_string_length(json_object_get(i_session->openid_config, "backchannel_authentication_endpoint"))) {
        if (i_set_str_parameter(i_session, I_OPT_CIBA_ENDPOINT, json_string_value(json_object_get(i_session->openid_config, "backchannel_authentication_endpoint"))) != I_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_openid_config - Error setting backchannel_authentication_endpoint");
          ret = I_ERROR;
        }
      }
      if (json_string_length(json_object_get(i_session->openid_config, "end_session_endpoint"))) {
        if (i_set_str_parameter(i_session, I_OPT_END_SESSION_ENDPOINT, json_string_value(json_object_get(i_session->openid_config, "end_session_endpoint"))) != I_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_openid_config - Error setting end_session_endpoint");
          ret = I_ERROR;
        }
      }
      if (json_string_length(json_object_get(i_session->openid_config, "check_session_iframe"))) {
        if (i_set_str_parameter(i_session, I_OPT_CHECK_SESSION_IRAME, json_string_value(json_object_get(i_session->openid_config, "check_session_iframe"))) != I_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_openid_config - Error setting check_session_iframe");
          ret = I_ERROR;
        }
      }
      if (json_string_length(json_object_get(i_session->openid_config, "device_authorization_endpoint"))) {
        if (i_set_str_parameter(i_session, I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, json_string_value(json_object_get(i_session->openid_config, "device_authorization_endpoint"))) != I_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_openid_config - Error setting device_authorization_endpoint");
          ret = I_ERROR;
        }
      }
      if (json_string_length(json_object_get(i_session->openid_config, "pushed_authorization_request_endpoint"))) {
        if (i_set_str_parameter(i_session, I_OPT_PUSHED_AUTH_REQ_ENDPOINT, json_string_value(json_object_get(i_session->openid_config, "pushed_authorization_request_endpoint"))) != I_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_openid_config - Error setting pushed_authorization_request_endpoint");
          ret = I_ERROR;
        }
        if (i_set_int_parameter(i_session, I_OPT_PUSHED_AUTH_REQ_REQUIRED, json_object_get(i_session->openid_config, "require_pushed_authorization_requests")==json_true()) != I_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_openid_config - Error setting require_pushed_authorization_requests");
          ret = I_ERROR;
        }
      }
      if (i_set_int_parameter(i_session, I_OPT_OPENID_CONFIG_STRICT, I_STRICT_YES) != I_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_openid_config - Error setting openid_config_strict");
        ret = I_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_openid_config - Error missing required metadata in JSON response");
      ret = I_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_openid_config - Error invalid JSON response");
    if (i_session != NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "issuer: %s", json_string_length(json_object_get(i_session->openid_config, "issuer"))?"valid":"invalid");
      y_log_message(Y_LOG_LEVEL_ERROR, "authorization_endpoint: %s", json_string_length(json_object_get(i_session->openid_config, "authorization_endpoint"))?"valid":"invalid");
      y_log_message(Y_LOG_LEVEL_ERROR, "jwks_uri: %s", json_string_length(json_object_get(i_session->openid_config, "jwks_uri"))?"valid":"invalid");
      y_log_message(Y_LOG_LEVEL_ERROR, "response_types_supported: %s", json_is_array(json_object_get(i_session->openid_config, "response_types_supported"))?"valid":"invalid");
      y_log_message(Y_LOG_LEVEL_ERROR, "subject_types_supported: %s", json_is_array(json_object_get(i_session->openid_config, "subject_types_supported"))?"valid":"invalid");
      y_log_message(Y_LOG_LEVEL_ERROR, "id_token_signing_alg_values_supported: %s", json_is_array(json_object_get(i_session->openid_config, "id_token_signing_alg_values_supported"))?"valid":"invalid");
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_openid_config - i_session is NULL");
    }
    ret = I_ERROR_PARAM;
  }
  return ret;
}

static int _i_check_strict_parameters(struct _i_session * i_session) {
  char ** str_array = NULL;
  int ret;
  size_t i;

  if (i_session != NULL) {
    ret = 1;
    if (i_session->scope != NULL) {
      if (split_string(i_session->scope, " ", &str_array)) {
        for (i=0; str_array[i]!=NULL; i++) {
          if (!_i_has_openid_config_parameter_value(i_session, "scopes_supported", str_array[i])) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "scope %s not supported", str_array[i]);
            ret = 0;
          }
        }
      }
      free_string_array(str_array);
    }
    if (i_session->response_type != I_RESPONSE_TYPE_DEVICE_CODE && i_session->response_type != I_RESPONSE_TYPE_CIBA &&!_i_has_openid_config_parameter_value(i_session, "response_types_supported", _i_get_response_type(i_session->response_type))) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "response_type '%s' not supported", _i_get_response_type(i_session->response_type));
      ret = 0;
    }
  } else {
    ret = 0;
  }
  return ret;
}

static json_t * _i_export_u_map(struct _u_map * map) {
  json_t * j_return = NULL;
  const char ** keys;
  size_t i;
  if (map != NULL) {
    if ((j_return = json_object()) != NULL) {
      keys = u_map_enum_keys(map);
      for (i=0; keys[i]!=NULL; i++) {
        json_object_set_new(j_return, keys[i], json_string(u_map_get(map, keys[i])));
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "_i_export_u_map - Error allocating resources for j_return");
    }
  }
  return j_return;
}

static char * _i_generate_auth_jwt(struct _i_session * i_session) {
  jwt_t * jwt = NULL;
  jwk_t * jwk_sign = NULL, * jwk_enc = NULL;
  char * jwt_str = NULL;
  const char ** keys = NULL;
  unsigned int i;
  jwa_alg sign_alg = R_JWA_ALG_UNKNOWN, enc_alg = R_JWA_ALG_UNKNOWN;
  jwa_enc enc = R_JWA_ENC_UNKNOWN;
  int has_error = 0;

  if (i_session != NULL) {
    r_jwt_init(&jwt);
    r_jwt_set_claim_str_value(jwt, "redirect_uri", i_session->redirect_uri);
    r_jwt_set_claim_str_value(jwt, "response_type", _i_get_response_type(i_session->response_type));
    r_jwt_set_claim_str_value(jwt, "client_id", i_session->client_id);
    if (i_session->state != NULL) {
      r_jwt_set_claim_str_value(jwt, "state", i_session->state);
    }
    if (i_session->scope != NULL) {
      r_jwt_set_claim_str_value(jwt, "scope", i_session->scope);
    }
    if (i_session->nonce != NULL) {
      r_jwt_set_claim_str_value(jwt, "nonce", i_session->nonce);
    }
    if (i_session->resource_indicator != NULL) {
      r_jwt_set_claim_str_value(jwt, "resource", i_session->resource_indicator);
    }
    if (json_array_size(i_session->j_authorization_details)) {
      r_jwt_set_claim_json_t_value(jwt, "authorization_details", i_session->j_authorization_details);
    }

    keys = u_map_enum_keys(&i_session->additional_parameters);

    for (i=0; keys[i] != NULL; i++) {
      r_jwt_set_claim_str_value(jwt, keys[i], u_map_get(&i_session->additional_parameters, keys[i]));
    }

    if (_i_has_claims(i_session)) {
      r_jwt_set_claim_json_t_value(jwt, "claims", i_session->j_claims);
    }

    if (i_session->auth_method & I_AUTH_METHOD_JWT_SIGN_SECRET) {
      if (o_strlen(i_session->client_secret)) {
        if (i_session->client_sign_alg != R_JWA_ALG_UNKNOWN) {
          sign_alg = i_session->client_sign_alg;
        } else if (i_session->request_object_signing_alg != R_JWA_ALG_UNKNOWN) {
          sign_alg = i_session->request_object_signing_alg;
        }
        if ((sign_alg == R_JWA_ALG_HS256 || sign_alg == R_JWA_ALG_HS384 || sign_alg == R_JWA_ALG_HS512) && !_i_has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", r_jwa_alg_to_str(sign_alg))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "signature alg is not specified or supported by the server");
          sign_alg = R_JWA_ALG_UNKNOWN;
        } else if (sign_alg == R_JWA_ALG_UNKNOWN && json_array_size(json_object_get(i_session->openid_config, "request_object_signing_alg_values_supported"))) {
          // no signtature alg specified, use one supported by the server
          if (_i_has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "HS256")) {
            sign_alg = R_JWA_ALG_HS256;
          } else if (_i_has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "HS384")) {
            sign_alg = R_JWA_ALG_HS384;
          } else if (_i_has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "HS512")) {
            sign_alg = R_JWA_ALG_HS512;
          }
        }
        if (sign_alg != R_JWA_ALG_UNKNOWN) {
          r_jwt_set_sign_alg(jwt, sign_alg);
          r_jwk_init(&jwk_sign);
          r_jwk_import_from_symmetric_key(jwk_sign, (const unsigned char *)i_session->client_secret, o_strlen(i_session->client_secret));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "Invalid signing key parameters");
          has_error = 1;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "Client has no secret");
        has_error = 1;
      }
    } else if (i_session->auth_method & I_AUTH_METHOD_JWT_SIGN_PRIVKEY) {
      if ((i_session->client_kid != NULL && (jwk_sign = r_jwks_get_by_kid(i_session->client_jwks, i_session->client_kid)) != NULL) ||
          (r_jwks_size(i_session->client_jwks) == 1 && (jwk_sign = r_jwks_get_at(i_session->client_jwks, 0)) != NULL)) {
        if (i_session->client_sign_alg != R_JWA_ALG_UNKNOWN) {
          sign_alg = i_session->client_sign_alg;
        } else if (i_session->request_object_signing_alg != R_JWA_ALG_UNKNOWN) {
          sign_alg = i_session->request_object_signing_alg;
        }
        if ((sign_alg == R_JWA_ALG_RS256 || sign_alg == R_JWA_ALG_RS384 || sign_alg == R_JWA_ALG_RS512 ||
             sign_alg == R_JWA_ALG_PS256 || sign_alg == R_JWA_ALG_PS384 || sign_alg == R_JWA_ALG_PS512) &&
             _i_has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", r_jwa_alg_to_str(sign_alg))) {
          if (!(r_jwk_key_type(jwk_sign, NULL, i_session->x5u_flags) & (R_KEY_TYPE_RSA|R_KEY_TYPE_PRIVATE))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "Invalid signing key type");
            has_error = 1;
          }
        } else if ((sign_alg == R_JWA_ALG_ES256 || sign_alg == R_JWA_ALG_ES384 || sign_alg == R_JWA_ALG_ES512) && _i_has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", r_jwa_alg_to_str(sign_alg))) {
          if (!(r_jwk_key_type(jwk_sign, NULL, i_session->x5u_flags) & (R_KEY_TYPE_EC|R_KEY_TYPE_PRIVATE))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "Invalid signing key type");
            has_error = 1;
          }
        } else if (sign_alg == R_JWA_ALG_EDDSA && _i_has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", r_jwa_alg_to_str(sign_alg))) {
          if (!(r_jwk_key_type(jwk_sign, NULL, i_session->x5u_flags) & (R_KEY_TYPE_EDDSA|R_KEY_TYPE_PRIVATE))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "Invalid signing key type");
            has_error = 1;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "Invalid signing key parameters");
          has_error = 1;
        }
      } else if (!r_jwks_size(i_session->client_jwks)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "Client has no private key ");
        has_error = 1;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "Client has more than one private key, please specify one with the parameter I_OPT_CLIENT_KID");
        has_error = 1;
      }
      if (jwk_sign != NULL) {
        r_jwt_set_sign_alg(jwt, i_session->client_sign_alg);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "Client has no signing key");
        has_error = 1;
      }
    }
    if (i_session->auth_method & I_AUTH_METHOD_JWT_ENCRYPT_SECRET) {
      if (o_strlen(i_session->client_secret)) {
        if (i_session->client_enc != R_JWA_ENC_UNKNOWN) {
          enc = i_session->client_enc;
        } else if (i_session->request_object_encryption_enc != R_JWA_ENC_UNKNOWN) {
          enc = i_session->request_object_encryption_enc;
        }
        if (enc != R_JWA_ENC_UNKNOWN && !_i_has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", r_jwa_enc_to_str(enc))) {
          enc = R_JWA_ENC_UNKNOWN;
        } else if (enc == R_JWA_ENC_UNKNOWN && json_array_size(json_object_get(i_session->openid_config, "request_object_encryption_enc_values_supported"))) {
          if (_i_has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A128CBC-HS256")) {
            enc = R_JWA_ENC_A128CBC;
          } else if (_i_has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A192CBC-HS384")) {
            enc = R_JWA_ENC_A192CBC;
          } else if (_i_has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A256CBC-HS512")) {
            enc = R_JWA_ENC_A256CBC;
          } else if (_i_has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A128GCM")) {
            enc = R_JWA_ENC_A128GCM;
          } else if (_i_has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A192GCM")) {
            enc = R_JWA_ENC_A192GCM;
          } else if (_i_has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A256GCM")) {
            enc = R_JWA_ENC_A256GCM;
          }
        }
        if (i_session->client_enc_alg != R_JWA_ALG_UNKNOWN) {
          enc_alg = i_session->client_enc_alg;
        } else if (i_session->request_object_encryption_alg != R_JWA_ALG_UNKNOWN) {
          enc_alg = i_session->request_object_encryption_alg;
        }
        if ((enc_alg == R_JWA_ALG_A128GCMKW ||
             enc_alg == R_JWA_ALG_A192GCMKW ||
             enc_alg == R_JWA_ALG_A256GCMKW ||
             enc_alg == R_JWA_ALG_A128KW ||
             enc_alg == R_JWA_ALG_A192KW ||
             enc_alg == R_JWA_ALG_A256KW ||
             enc_alg == R_JWA_ALG_DIR ||
             enc_alg == R_JWA_ALG_PBES2_H256 ||
             enc_alg == R_JWA_ALG_PBES2_H384 ||
             enc_alg == R_JWA_ALG_PBES2_H512) &&
             !_i_has_openid_config_parameter_value(i_session, "request_object_encryption_alg_values_supported", r_jwa_alg_to_str(enc_alg))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "signature alg is not specified or supported by the server");
          enc_alg = R_JWA_ALG_UNKNOWN;
        } else if (i_session->client_enc_alg == R_JWA_ALG_UNKNOWN && json_array_size(json_object_get(i_session->openid_config, "request_object_encryption_alg_values_supported"))) {
          // no signtature alg specified, use one supported by the server
          if (_i_has_openid_config_parameter_value(i_session, "request_object_encryption_alg_values_supported", "A128KW")) {
            enc_alg = R_JWA_ALG_A128KW;
          } else if (_i_has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "A192KW")) {
            enc_alg = R_JWA_ALG_A192KW;
          } else if (_i_has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "A256KW")) {
            enc_alg = R_JWA_ALG_A256KW;
          } else if (_i_has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "A128GCMKW")) {
            enc_alg = R_JWA_ALG_A128GCMKW;
          } else if (_i_has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "A192GCMKW")) {
            enc_alg = R_JWA_ALG_A192GCMKW;
          } else if (_i_has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "A256GCMKW")) {
            enc_alg = R_JWA_ALG_A256GCMKW;
          } else if (_i_has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "dir")) {
            enc_alg = R_JWA_ALG_DIR;
          } else if (_i_has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "PBES2-HS256+A128KW")) {
            enc_alg = R_JWA_ALG_PBES2_H256;
          } else if (_i_has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "PBES2-HS384+A192KW")) {
            enc_alg = R_JWA_ALG_PBES2_H384;
          } else if (_i_has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "PBES2-HS512+A256KW")) {
            enc_alg = R_JWA_ALG_PBES2_H512;
          }
        }
        if (enc_alg != R_JWA_ALG_UNKNOWN && enc != R_JWA_ENC_UNKNOWN) {
          r_jwt_set_enc_alg(jwt, enc_alg);
          r_jwt_set_enc(jwt, enc);
          r_jwk_init(&jwk_enc);
          r_jwk_import_from_symmetric_key(jwk_enc, (const unsigned char *)i_session->client_secret, o_strlen(i_session->client_secret));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "Invalid encrypt key parameters (secret)");
          has_error = 1;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "Client has no secret");
        has_error = 1;
      }
    } else if (i_session->auth_method & I_AUTH_METHOD_JWT_ENCRYPT_PUBKEY) {
      if ((i_session->server_kid != NULL && (jwk_enc = r_jwks_get_by_kid(i_session->server_jwks, i_session->server_kid)) != NULL) || (r_jwks_size(i_session->server_jwks) == 1 && (jwk_enc = r_jwks_get_at(i_session->server_jwks, 0)) != NULL)) {
        if (i_session->client_enc != R_JWA_ENC_UNKNOWN && _i_has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", i_get_str_parameter(i_session, I_OPT_CLIENT_ENC))) {
          enc = i_session->client_enc;
        } else if (i_session->request_object_encryption_enc != R_JWA_ENC_UNKNOWN && _i_has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", i_get_str_parameter(i_session, I_OPT_REQUEST_OBJECT_ENCRYPTION_ENC))) {
          enc = i_session->request_object_encryption_enc;
        } else if (i_session->client_enc == R_JWA_ENC_UNKNOWN && json_array_size(json_object_get(i_session->openid_config, "request_object_encryption_enc_values_supported"))) {
          if (_i_has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A128CBC-HS256")) {
            enc = R_JWA_ENC_A128CBC;
          } else if (_i_has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A192CBC-HS384")) {
            enc = R_JWA_ENC_A192CBC;
          } else if (_i_has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A256CBC-HS512")) {
            enc = R_JWA_ENC_A256CBC;
          } else if (_i_has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A128GCM")) {
            enc = R_JWA_ENC_A128GCM;
          } else if (_i_has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A192GCM")) {
            enc = R_JWA_ENC_A192GCM;
          } else if (_i_has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A256GCM")) {
            enc = R_JWA_ENC_A256GCM;
          }
        }
        if (i_session->client_enc_alg != R_JWA_ALG_UNKNOWN) {
          enc_alg = i_session->client_enc_alg;
        } else if (i_session->request_object_encryption_alg != R_JWA_ALG_UNKNOWN) {
          enc_alg = i_session->request_object_encryption_alg;
        }
        if ((enc_alg == R_JWA_ALG_RSA1_5 || enc_alg == R_JWA_ALG_RSA_OAEP || enc_alg == R_JWA_ALG_RSA_OAEP_256) && _i_has_openid_config_parameter_value(i_session, "request_object_encryption_alg_values_supported", r_jwa_alg_to_str(enc_alg))) {
          if (!(r_jwk_key_type(jwk_enc, NULL, i_session->x5u_flags) & (R_KEY_TYPE_RSA|R_KEY_TYPE_PRIVATE))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "Invalid encrypt key type");
            has_error = 1;
          }
        } else if ((enc_alg == R_JWA_ALG_ECDH_ES || enc_alg == R_JWA_ALG_ECDH_ES_A128KW || enc_alg == R_JWA_ALG_ECDH_ES_A192KW || enc_alg == R_JWA_ALG_ECDH_ES_A256KW) && _i_has_openid_config_parameter_value(i_session, "request_object_encryption_alg_values_supported", r_jwa_alg_to_str(enc_alg))) {
          if (!(r_jwk_key_type(jwk_enc, NULL, i_session->x5u_flags) & (R_KEY_TYPE_EC|R_KEY_TYPE_PRIVATE))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "Invalid encrypt key type");
            has_error = 1;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_generate_auth_jwt - Invalid encrypt key parameters (pubkey)");
          has_error = 1;
        }
      } else if (!r_jwks_size(i_session->client_jwks)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "Server has no public key ");
        has_error = 1;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "Server has more than one public key, please specify one with the parameter I_OPT_SERVER_KID");
        has_error = 1;
      }
      if (enc_alg != R_JWA_ALG_UNKNOWN && enc != R_JWA_ENC_UNKNOWN) {
        r_jwt_set_enc_alg(jwt, enc_alg);
        r_jwt_set_enc(jwt, enc);
      } else {
        has_error = 1;
      }
    }
    if (!has_error) {
      if (i_session->auth_method & (I_AUTH_METHOD_JWT_SIGN_SECRET|I_AUTH_METHOD_JWT_SIGN_PRIVKEY) && !(i_session->auth_method & (I_AUTH_METHOD_JWT_ENCRYPT_SECRET|I_AUTH_METHOD_JWT_ENCRYPT_PUBKEY))) {
        jwt_str = r_jwt_serialize_signed(jwt, jwk_sign, i_session->x5u_flags);
      } else if (!(i_session->auth_method & (I_AUTH_METHOD_JWT_SIGN_SECRET|I_AUTH_METHOD_JWT_SIGN_PRIVKEY)) && i_session->auth_method & (I_AUTH_METHOD_JWT_ENCRYPT_SECRET|I_AUTH_METHOD_JWT_ENCRYPT_PUBKEY)) {
        jwt_str = r_jwt_serialize_encrypted(jwt, jwk_enc, i_session->x5u_flags);
      } else {
        jwt_str = r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT, jwk_sign, i_session->x5u_flags, jwk_enc, i_session->x5u_flags);
      }
    }
    r_jwt_free(jwt);
    r_jwk_free(jwk_sign);
    r_jwk_free(jwk_enc);
  }
  return jwt_str;
}

static char * _i_generate_client_assertion(struct _i_session * i_session, const char * aud, jwa_alg sign_alg, jwa_alg enc_alg, jwa_enc enc) {
  char * token = NULL;
  jwt_t * jwt = NULL;
  jwk_t * jwk_sign = NULL, * jwk_enc = NULL;
  time_t now;
  int ret = I_OK;
  const char * sign_alg_values = "token_endpoint_auth_signing_alg_values_supported",
             * enc_alg_values = "token_endpoint_auth_encryption_alg_values_supported",
             * enc_values = "token_endpoint_auth_encryption_enc_values_supported";

  if (i_session->response_type == I_RESPONSE_TYPE_CIBA) {
    sign_alg_values = "backchannel_authentication_request_signing_alg_values_supported";
    enc_alg_values = "backchannel_authentication_request_encryption_alg_values_supported";
    enc_values = "backchannel_authentication_request_encryption_enc_values_supported";
  }
  if (i_session->token_jti != NULL) {
    time(&now);
    r_jwt_init(&jwt);
    r_jwt_set_claim_str_value(jwt, "iss", i_session->client_id);
    r_jwt_set_claim_str_value(jwt, "sub", i_session->client_id);
    r_jwt_set_claim_str_value(jwt, "aud", aud);
    r_jwt_set_claim_str_value(jwt, "jti", i_session->token_jti);
    r_jwt_set_claim_int_value(jwt, "exp", now+i_session->token_exp);
    r_jwt_set_claim_int_value(jwt, "nbf", now);
    r_jwt_set_claim_int_value(jwt, "iat", now);
    if (i_session->token_method == I_TOKEN_AUTH_METHOD_JWT_SIGN_SECRET) {
      if (i_session->client_secret != NULL) {
        if ((sign_alg == R_JWA_ALG_HS256 || sign_alg == R_JWA_ALG_HS384 || sign_alg == R_JWA_ALG_HS512) && !_i_has_openid_config_parameter_value(i_session, sign_alg_values, r_jwa_alg_to_str(sign_alg))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "signature alg is not specified or supported by the server");
          ret = I_ERROR_PARAM;
        } else if (sign_alg == R_JWA_ALG_UNKNOWN && json_array_size(json_object_get(i_session->openid_config, sign_alg_values))) {
          // no signtature alg specified, use one supported by the server
          if (_i_has_openid_config_parameter_value(i_session, sign_alg_values, "HS256")) {
            sign_alg = R_JWA_ALG_HS256;
          } else if (_i_has_openid_config_parameter_value(i_session, sign_alg_values, "HS384")) {
            sign_alg = R_JWA_ALG_HS384;
          } else if (_i_has_openid_config_parameter_value(i_session, sign_alg_values, "HS512")) {
            sign_alg = R_JWA_ALG_HS512;
          }
        }
        if (sign_alg != R_JWA_ALG_UNKNOWN) {
          r_jwt_set_sign_alg(jwt, sign_alg);
          r_jwk_init(&jwk_sign);
          r_jwk_import_from_symmetric_key(jwk_sign, (const unsigned char *)i_session->client_secret, o_strlen(i_session->client_secret));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "Invalid signing key parameters");
          ret = I_ERROR_PARAM;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "Client has no secret");
        ret = I_ERROR_PARAM;
      }
    } else {
      if ((i_session->client_kid != NULL && (jwk_sign = r_jwks_get_by_kid(i_session->client_jwks, i_session->client_kid)) != NULL) || (r_jwks_size(i_session->client_jwks) == 1 && (jwk_sign = r_jwks_get_at(i_session->client_jwks, 0)) != NULL)) {
        if ((sign_alg == R_JWA_ALG_RS256 || sign_alg == R_JWA_ALG_RS384 || sign_alg == R_JWA_ALG_RS512 ||
             sign_alg == R_JWA_ALG_PS256 || sign_alg == R_JWA_ALG_PS384 || sign_alg == R_JWA_ALG_PS512) &&
             _i_has_openid_config_parameter_value(i_session, sign_alg_values, r_jwa_alg_to_str(sign_alg))) {
          if (!(r_jwk_key_type(jwk_sign, NULL, i_session->x5u_flags) & (R_KEY_TYPE_RSA|R_KEY_TYPE_PRIVATE))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "Invalid signing key type");
            ret = I_ERROR_PARAM;
          }
        } else if ((sign_alg == R_JWA_ALG_ES256 || sign_alg == R_JWA_ALG_ES384 || sign_alg == R_JWA_ALG_ES512) && _i_has_openid_config_parameter_value(i_session, sign_alg_values, r_jwa_alg_to_str(sign_alg))) {
          if (!(r_jwk_key_type(jwk_sign, NULL, i_session->x5u_flags) & (R_KEY_TYPE_EC|R_KEY_TYPE_PRIVATE))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "Invalid signing key type");
            ret = I_ERROR_PARAM;
          }
        } else if (sign_alg == R_JWA_ALG_EDDSA && _i_has_openid_config_parameter_value(i_session, sign_alg_values, r_jwa_alg_to_str(sign_alg))) {
          if (!(r_jwk_key_type(jwk_sign, NULL, i_session->x5u_flags) & (R_KEY_TYPE_EDDSA|R_KEY_TYPE_PRIVATE))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "Invalid signing key type");
            ret = I_ERROR_PARAM;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "Invalid signing key parameters");
          ret = I_ERROR_PARAM;
        }
        r_jwt_set_sign_alg(jwt, sign_alg);
      } else if (!r_jwks_size(i_session->client_jwks)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "Client has no private key ");
        ret = I_ERROR_PARAM;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "Client has more than one private key, please specify one with the parameter I_OPT_CLIENT_KID");
        ret = I_ERROR_PARAM;
      }
    }
    if (i_session->token_method & I_TOKEN_AUTH_METHOD_JWT_ENCRYPT_SECRET) {
      if (o_strlen(i_session->client_secret)) {
        if (i_session->client_enc == R_JWA_ENC_UNKNOWN && json_array_size(json_object_get(i_session->openid_config, sign_alg_values))) {
          if (_i_has_openid_config_parameter_value(i_session, sign_alg_values, "A128CBC-HS256")) {
            enc = R_JWA_ENC_A128CBC;
          } else if (_i_has_openid_config_parameter_value(i_session, sign_alg_values, "A192CBC-HS384")) {
            enc = R_JWA_ENC_A192CBC;
          } else if (_i_has_openid_config_parameter_value(i_session, sign_alg_values, "A256CBC-HS512")) {
            enc = R_JWA_ENC_A256CBC;
          } else if (_i_has_openid_config_parameter_value(i_session, sign_alg_values, "A128GCM")) {
            enc = R_JWA_ENC_A128GCM;
          } else if (_i_has_openid_config_parameter_value(i_session, sign_alg_values, "A192GCM")) {
            enc = R_JWA_ENC_A192GCM;
          } else if (_i_has_openid_config_parameter_value(i_session, sign_alg_values, "A256GCM")) {
            enc = R_JWA_ENC_A256GCM;
          }
        }
        if (i_session->client_enc_alg == R_JWA_ALG_UNKNOWN && json_array_size(json_object_get(i_session->openid_config, enc_alg_values))) {
          // no signtature alg specified, use one supported by the server
          if (_i_has_openid_config_parameter_value(i_session, enc_alg_values, "A128KW")) {
            enc_alg = R_JWA_ALG_A128KW;
          } else if (_i_has_openid_config_parameter_value(i_session, sign_alg_values, "A192KW")) {
            enc_alg = R_JWA_ALG_A192KW;
          } else if (_i_has_openid_config_parameter_value(i_session, sign_alg_values, "A256KW")) {
            enc_alg = R_JWA_ALG_A256KW;
          } else if (_i_has_openid_config_parameter_value(i_session, sign_alg_values, "A128GCMKW")) {
            enc_alg = R_JWA_ALG_A128GCMKW;
          } else if (_i_has_openid_config_parameter_value(i_session, sign_alg_values, "A192GCMKW")) {
            enc_alg = R_JWA_ALG_A192GCMKW;
          } else if (_i_has_openid_config_parameter_value(i_session, sign_alg_values, "A256GCMKW")) {
            enc_alg = R_JWA_ALG_A256GCMKW;
          } else if (_i_has_openid_config_parameter_value(i_session, sign_alg_values, "dir")) {
            enc_alg = R_JWA_ALG_DIR;
          } else if (_i_has_openid_config_parameter_value(i_session, sign_alg_values, "PBES2-HS256+A128KW")) {
            enc_alg = R_JWA_ALG_PBES2_H256;
          } else if (_i_has_openid_config_parameter_value(i_session, sign_alg_values, "PBES2-HS384+A192KW")) {
            enc_alg = R_JWA_ALG_PBES2_H384;
          } else if (_i_has_openid_config_parameter_value(i_session, sign_alg_values, "PBES2-HS512+A256KW")) {
            enc_alg = R_JWA_ALG_PBES2_H512;
          }
        }
        if (enc_alg != R_JWA_ALG_UNKNOWN && enc != R_JWA_ENC_UNKNOWN) {
          r_jwt_set_enc_alg(jwt, enc_alg);
          r_jwt_set_enc(jwt, enc);
          r_jwk_init(&jwk_enc);
          r_jwk_import_from_symmetric_key(jwk_enc, (const unsigned char *)i_session->client_secret, o_strlen(i_session->client_secret));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "Invalid encrypt key parameters (secret)");
          ret = I_ERROR_PARAM;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "Client has no secret");
        ret = I_ERROR_PARAM;
      }
    } else if (i_session->token_method & I_TOKEN_AUTH_METHOD_JWT_ENCRYPT_PUBKEY) {
      if ((i_session->server_kid != NULL && (jwk_enc = r_jwks_get_by_kid(i_session->server_jwks, i_session->server_kid)) != NULL) || (r_jwks_size(i_session->server_jwks) == 1 && (jwk_enc = r_jwks_get_at(i_session->server_jwks, 0)) != NULL)) {
        if (i_session->client_enc == R_JWA_ENC_UNKNOWN && json_array_size(json_object_get(i_session->openid_config, enc_values))) {
          if (_i_has_openid_config_parameter_value(i_session, enc_values, "A128CBC-HS256")) {
            enc = R_JWA_ENC_A128CBC;
          } else if (_i_has_openid_config_parameter_value(i_session, enc_values, "A192CBC-HS384")) {
            enc = R_JWA_ENC_A192CBC;
          } else if (_i_has_openid_config_parameter_value(i_session, enc_values, "A256CBC-HS512")) {
            enc = R_JWA_ENC_A256CBC;
          } else if (_i_has_openid_config_parameter_value(i_session, enc_values, "A128GCM")) {
            enc = R_JWA_ENC_A128GCM;
          } else if (_i_has_openid_config_parameter_value(i_session, enc_values, "A192GCM")) {
            enc = R_JWA_ENC_A192GCM;
          } else if (_i_has_openid_config_parameter_value(i_session, enc_values, "A256GCM")) {
            enc = R_JWA_ENC_A256GCM;
          }
        }
        if ((enc_alg == R_JWA_ALG_RSA1_5 ||
             enc_alg == R_JWA_ALG_RSA_OAEP ||
             enc_alg == R_JWA_ALG_RSA_OAEP_256) && _i_has_openid_config_parameter_value(i_session, enc_alg_values, r_jwa_alg_to_str(enc_alg))) {
          if (!(r_jwk_key_type(jwk_enc, NULL, i_session->x5u_flags) & (R_KEY_TYPE_RSA|R_KEY_TYPE_PRIVATE))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "Invalid encrypt key type");
            ret = I_ERROR_PARAM;
          }
        } else if ((enc_alg == R_JWA_ALG_ECDH_ES ||
                    enc_alg == R_JWA_ALG_ECDH_ES_A128KW ||
                    enc_alg == R_JWA_ALG_ECDH_ES_A192KW ||
                    enc_alg == R_JWA_ALG_ECDH_ES_A256KW) && _i_has_openid_config_parameter_value(i_session, enc_alg_values, r_jwa_alg_to_str(enc_alg))) {
          if (!(r_jwk_key_type(jwk_enc, NULL, i_session->x5u_flags) & (R_KEY_TYPE_EC|R_KEY_TYPE_PRIVATE))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "Invalid encrypt key type");
            ret = I_ERROR_PARAM;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_generate_client_assertion - Invalid encrypt key parameters (pubkey)");
          ret = I_ERROR_PARAM;
        }
      } else if (!r_jwks_size(i_session->client_jwks)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "Server has no public key ");
        ret = I_ERROR_PARAM;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "Server has more than one public key, please specify one with the parameter I_OPT_SERVER_KID");
        ret = I_ERROR_PARAM;
      }
      if (enc_alg != R_JWA_ALG_UNKNOWN && enc != R_JWA_ENC_UNKNOWN) {
        r_jwt_set_enc_alg(jwt, enc_alg);
        r_jwt_set_enc(jwt, enc);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "Invalid enc or sig_enc value");
        ret = I_ERROR_PARAM;
      }
    }
    if (ret == I_OK) {
      if (enc_alg != R_JWA_ALG_UNKNOWN && enc != R_JWA_ENC_UNKNOWN) {
        token = r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT, jwk_sign, i_session->x5u_flags, jwk_enc, i_session->x5u_flags);
      } else {
        token = r_jwt_serialize_signed(jwt, jwk_sign, i_session->x5u_flags);
      }
    }
    r_jwk_free(jwk_sign);
    r_jwt_free(jwt);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "_i_generate_client_assertion - jti required");
    ret = I_ERROR_PARAM;
  }
  return token;
}

static int _i_add_token_authentication(struct _i_session * i_session, const char * aud, struct _u_request * request, jwa_alg sign_alg, jwa_alg enc_alg, jwa_enc enc) {
  int ret = I_OK;
  char * jwt_str = NULL;

  if (i_session->token_method & I_TOKEN_AUTH_METHOD_SECRET_BASIC) {
    if (i_session->client_secret != NULL) {
      ulfius_set_request_properties(request, U_OPT_AUTH_BASIC_USER, i_session->client_id, U_OPT_AUTH_BASIC_PASSWORD, i_session->client_secret, U_OPT_NONE);
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "_i_add_token_authentication - client_secret required");
      ret = I_ERROR_PARAM;
    }
  } else if (i_session->token_method & I_TOKEN_AUTH_METHOD_SECRET_POST) {
    if (i_session->client_secret != NULL) {
      ulfius_set_request_properties(request, U_OPT_POST_BODY_PARAMETER, "client_id", i_session->client_id,
                                             U_OPT_POST_BODY_PARAMETER, "client_secret", i_session->client_secret,
                                             U_OPT_NONE);
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "_i_add_token_authentication - client_secret required");
      ret = I_ERROR_PARAM;
    }
  } else if (i_session->token_method & I_TOKEN_AUTH_METHOD_TLS_CERTIFICATE) {
    if (i_session->client_id != NULL && i_session->key_file != NULL && i_session->cert_file != NULL) {
      ulfius_set_request_properties(request, U_OPT_CLIENT_CERT_FILE, i_session->cert_file,
                                             U_OPT_CLIENT_KEY_FILE, i_session->key_file,
                                             U_OPT_POST_BODY_PARAMETER, "client_id", i_session->client_id,
                                             U_OPT_NONE);
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "_i_add_token_authentication - key_file and cert_file required");
      ret = I_ERROR_PARAM;
    }
  } else if (i_session->token_method & I_TOKEN_AUTH_METHOD_JWT_SIGN_SECRET || i_session->token_method & I_TOKEN_AUTH_METHOD_JWT_SIGN_PRIVKEY) {
    if ((jwt_str = _i_generate_client_assertion(i_session, aud, sign_alg, enc_alg, enc)) != NULL) {
      ulfius_set_request_properties(request, U_OPT_POST_BODY_PARAMETER, "client_assertion", jwt_str,
                                             U_OPT_POST_BODY_PARAMETER, "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                             U_OPT_NONE);
      o_free(jwt_str);
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "_i_add_token_authentication - Error _i_generate_client_assertion");
      ret = I_ERROR_PARAM;
    }
  } else {
    ulfius_set_request_properties(request, U_OPT_POST_BODY_PARAMETER, "client_id", i_session->client_id,
                                           U_OPT_NONE);
  }
  return ret;
}

int i_global_init() {
  if (ulfius_global_init() == U_OK && r_global_init() == RHN_OK) {
    return RHN_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "i_global_init - Error ulfius_global_init or r_global_init");
    return RHN_ERROR;
  }
}

void i_global_close() {
  ulfius_global_close();
  r_global_close();
}

void i_free(void * data) {
  o_free(data);
}

int i_init_session(struct _i_session * i_session) {
  int res;

  if (i_session != NULL) {
    i_session->response_type = I_RESPONSE_TYPE_NONE;
    i_session->scope = NULL;
    i_session->nonce = NULL;
    i_session->redirect_uri = NULL;
    i_session->redirect_to = NULL;
    i_session->state = NULL;
    i_session->client_id = NULL;
    i_session->client_secret = NULL;
    i_session->username = NULL;
    i_session->user_password = NULL;
    i_session->authorization_endpoint = NULL;
    i_session->token_endpoint = NULL;
    i_session->openid_config_endpoint = NULL;
    i_session->userinfo_endpoint = NULL;
    i_session->refresh_token = NULL;
    i_session->access_token = NULL;
    i_session->access_token_payload = NULL;
    i_session->token_target = NULL;
    i_session->token_target_type_hint = NULL;
    i_session->token_type = NULL;
    i_session->expires_in = 0;
    i_session->expires_at = 0;
    i_session->id_token = NULL;
    i_session->id_token_payload = NULL;
    i_session->code = NULL;
    i_session->result = I_OK;
    i_session->error = NULL;
    i_session->error_description = NULL;
    i_session->error_uri = NULL;
    i_session->auth_method = I_AUTH_METHOD_GET;
    i_session->token_method = I_TOKEN_AUTH_METHOD_NONE;
    i_session->x5u_flags = 0;
    i_session->openid_config = NULL;
    i_session->openid_config_strict = I_STRICT_NO;
    i_session->issuer = NULL;
    i_session->userinfo = NULL;
    i_session->j_userinfo = NULL;
    i_session->server_kid = NULL;
    i_session->server_enc_alg = R_JWA_ALG_UNKNOWN;
    i_session->server_enc = R_JWA_ENC_UNKNOWN;
    i_session->client_kid = NULL;
    i_session->client_sign_alg = R_JWA_ALG_UNKNOWN;
    i_session->client_enc_alg = R_JWA_ALG_UNKNOWN;
    i_session->client_enc = R_JWA_ENC_UNKNOWN;
    i_session->token_jti = NULL;
    i_session->token_exp = 600;
    i_session->revocation_endpoint = NULL;
    i_session->introspection_endpoint = NULL;
    i_session->registration_endpoint = NULL;
    i_session->device_authorization_endpoint = NULL;
    i_session->device_auth_code = NULL;
    i_session->device_auth_user_code = NULL;
    i_session->device_auth_verification_uri = NULL;
    i_session->device_auth_verification_uri_complete = NULL;
    i_session->device_auth_expires_in = 0;
    i_session->device_auth_interval = 0;
    i_session->end_session_endpoint = NULL;
    i_session->check_session_iframe = NULL;
    i_session->pushed_authorization_request_endpoint = NULL;
    i_session->require_pushed_authorization_requests = 0;
    i_session->pushed_authorization_request_expires_in = 0;
    i_session->pushed_authorization_request_uri = NULL;
    i_session->use_dpop = 0;
    i_session->dpop_kid = NULL;
    i_session->dpop_sign_alg = R_JWA_ALG_UNKNOWN;
    i_session->decrypt_code = 0;
    i_session->decrypt_refresh_token = 0;
    i_session->decrypt_access_token = 0;
    i_session->key_file = NULL;
    i_session->cert_file = NULL;
    i_session->pkce_code_verifier = NULL;
    i_session->pkce_method = I_PKCE_NONE;
    i_session->remote_cert_flag = I_REMOTE_HOST_VERIFY_PEER|I_REMOTE_HOST_VERIFY_HOSTNAME|I_REMOTE_PROXY_VERIFY_PEER|I_REMOTE_PROXY_VERIFY_HOSTNAME;
    i_session->j_claims = json_pack("{s{}s{}}", "userinfo", "id_token");
    i_session->resource_indicator = NULL;
    i_session->access_token_signing_alg = R_JWA_ALG_UNKNOWN;
    i_session->access_token_encryption_alg = R_JWA_ALG_UNKNOWN;
    i_session->access_token_encryption_enc = R_JWA_ENC_UNKNOWN;
    i_session->id_token_signing_alg = R_JWA_ALG_UNKNOWN;
    i_session->id_token_encryption_alg = R_JWA_ALG_UNKNOWN;
    i_session->id_token_encryption_enc = R_JWA_ENC_UNKNOWN;
    i_session->userinfo_signing_alg = R_JWA_ALG_UNKNOWN;
    i_session->userinfo_encryption_alg = R_JWA_ALG_UNKNOWN;
    i_session->userinfo_encryption_enc = R_JWA_ENC_UNKNOWN;
    i_session->request_object_signing_alg = R_JWA_ALG_UNKNOWN;
    i_session->request_object_encryption_alg = R_JWA_ALG_UNKNOWN;
    i_session->request_object_encryption_enc = R_JWA_ENC_UNKNOWN;
    i_session->token_endpoint_signing_alg = R_JWA_ALG_UNKNOWN;
    i_session->token_endpoint_encryption_alg = R_JWA_ALG_UNKNOWN;
    i_session->token_endpoint_encryption_enc = R_JWA_ENC_UNKNOWN;
    i_session->ciba_request_signing_alg = R_JWA_ALG_UNKNOWN;
    i_session->ciba_request_encryption_alg = R_JWA_ALG_UNKNOWN;
    i_session->ciba_request_encryption_enc = R_JWA_ENC_UNKNOWN;
    i_session->auth_response_signing_alg = R_JWA_ALG_UNKNOWN;
    i_session->auth_response_encryption_alg = R_JWA_ALG_UNKNOWN;
    i_session->auth_response_encryption_enc = R_JWA_ENC_UNKNOWN;
    i_session->ciba_endpoint = NULL;
    i_session->ciba_mode = I_CIBA_MODE_NONE;
    i_session->ciba_user_code = NULL;
    i_session->ciba_login_hint = NULL;
    i_session->ciba_login_hint_format = I_CIBA_LOGIN_HINT_FORMAT_JSON;
    i_session->ciba_login_hint_kid = NULL;
    i_session->ciba_binding_message = NULL;
    i_session->ciba_client_notification_token = NULL;
    i_session->ciba_auth_req_id = NULL;
    i_session->ciba_client_notification_endpoint = NULL;
    i_session->ciba_auth_req_expires_in = 0;
    i_session->ciba_auth_req_interval = 0;
    i_session->frontchannel_logout_uri = NULL;
    i_session->frontchannel_logout_session_required = 0;
    i_session->backchannel_logout_uri = NULL;
    i_session->backchannel_logout_session_required = 0;
    i_session->post_logout_redirect_uri = NULL;
    i_session->id_token_sid = NULL;
    if ((res = u_map_init(&i_session->additional_parameters)) == U_OK) {
      if ((res = u_map_init(&i_session->additional_response)) == U_OK) {
        if ((res = r_jwks_init(&i_session->server_jwks)) == RHN_OK) {
          if ((res = r_jwks_init(&i_session->client_jwks)) == RHN_OK) {
            if ((i_session->j_authorization_details = json_array()) != NULL) {
              return I_OK;
            } else {
              return I_ERROR_MEMORY;
            }
          } else if (res == U_ERROR_MEMORY) {
            return I_ERROR_MEMORY;
          } else {
            return I_ERROR;
          }
        } else if (res == U_ERROR_MEMORY) {
          return I_ERROR_MEMORY;
        } else {
          return I_ERROR;
        }
      } else if (res == U_ERROR_MEMORY) {
        return I_ERROR_MEMORY;
      } else {
        return I_ERROR;
      }
    } else if (res == U_ERROR_MEMORY) {
      return I_ERROR_MEMORY;
    } else {
      return I_ERROR;
    }
  } else {
    return I_ERROR_PARAM;
  }
}

void i_clean_session(struct _i_session * i_session) {
  if (i_session != NULL) {
    o_free(i_session->scope);
    o_free(i_session->nonce);
    o_free(i_session->redirect_uri);
    o_free(i_session->redirect_to);
    o_free(i_session->state);
    o_free(i_session->client_id);
    o_free(i_session->client_secret);
    o_free(i_session->username);
    o_free(i_session->user_password);
    o_free(i_session->authorization_endpoint);
    o_free(i_session->token_endpoint);
    o_free(i_session->openid_config_endpoint);
    o_free(i_session->code);
    o_free(i_session->error);
    o_free(i_session->error_description);
    o_free(i_session->error_uri);
    o_free(i_session->refresh_token);
    o_free(i_session->access_token);
    o_free(i_session->token_type);
    o_free(i_session->id_token);
    o_free(i_session->userinfo_endpoint);
    o_free(i_session->issuer);
    o_free(i_session->userinfo);
    o_free(i_session->server_kid);
    o_free(i_session->client_kid);
    o_free(i_session->token_jti);
    o_free(i_session->revocation_endpoint);
    o_free(i_session->introspection_endpoint);
    o_free(i_session->registration_endpoint);
    o_free(i_session->token_target);
    o_free(i_session->token_target_type_hint);
    o_free(i_session->device_authorization_endpoint);
    o_free(i_session->device_auth_code);
    o_free(i_session->device_auth_user_code);
    o_free(i_session->device_auth_verification_uri);
    o_free(i_session->device_auth_verification_uri_complete);
    o_free(i_session->end_session_endpoint);
    o_free(i_session->check_session_iframe);
    o_free(i_session->pushed_authorization_request_endpoint);
    o_free(i_session->pushed_authorization_request_uri);
    o_free(i_session->dpop_kid);
    o_free(i_session->key_file);
    o_free(i_session->cert_file);
    o_free(i_session->pkce_code_verifier);
    o_free(i_session->resource_indicator);
    o_free(i_session->ciba_endpoint);
    o_free(i_session->ciba_user_code);
    o_free(i_session->ciba_login_hint);
    o_free(i_session->ciba_login_hint_kid);
    o_free(i_session->ciba_binding_message);
    o_free(i_session->ciba_client_notification_token );
    o_free(i_session->ciba_auth_req_id);
    o_free(i_session->ciba_client_notification_endpoint);
    o_free(i_session->frontchannel_logout_uri);
    o_free(i_session->backchannel_logout_uri);
    o_free(i_session->post_logout_redirect_uri);
    o_free(i_session->id_token_sid);
    u_map_clean(&i_session->additional_parameters);
    u_map_clean(&i_session->additional_response);
    r_jwks_free(i_session->server_jwks);
    r_jwks_free(i_session->client_jwks);
    json_decref(i_session->id_token_payload);
    json_decref(i_session->access_token_payload);
    json_decref(i_session->openid_config);
    json_decref(i_session->j_userinfo);
    json_decref(i_session->j_authorization_details);
    json_decref(i_session->j_claims);
  }
}

int i_set_response_type(struct _i_session * i_session, unsigned int i_value) {
  return i_set_int_parameter(i_session, I_OPT_RESPONSE_TYPE, i_value);
}

int i_set_result(struct _i_session * i_session, unsigned int i_value) {
  return i_set_int_parameter(i_session, I_OPT_RESULT, i_value);
}

int i_set_int_parameter(struct _i_session * i_session, i_option option, unsigned int i_value) {
  int ret = I_OK;
  if (i_session != NULL) {
    switch (option) {
      case I_OPT_RESPONSE_TYPE:
        switch (i_value) {
          case I_RESPONSE_TYPE_NONE:
          case I_RESPONSE_TYPE_CODE:
          case I_RESPONSE_TYPE_TOKEN:
          case I_RESPONSE_TYPE_ID_TOKEN:
          case I_RESPONSE_TYPE_PASSWORD:
          case I_RESPONSE_TYPE_CLIENT_CREDENTIALS:
          case I_RESPONSE_TYPE_REFRESH_TOKEN:
          case I_RESPONSE_TYPE_DEVICE_CODE:
          case I_RESPONSE_TYPE_CIBA:
          case I_RESPONSE_TYPE_CODE|I_RESPONSE_TYPE_ID_TOKEN:
          case I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_ID_TOKEN:
          case I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_CODE:
          case I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_CODE|I_RESPONSE_TYPE_ID_TOKEN:
            i_session->response_type = i_value;
            break;
          default:
            y_log_message(Y_LOG_LEVEL_DEBUG, "i_set_int_parameter - Error unknown response type");
            ret = I_ERROR_PARAM;
            break;
        }
        break;
      case I_OPT_RESULT:
        switch (i_value) {
          case I_OK:
          case I_ERROR:
          case I_ERROR_PARAM:
          case I_ERROR_UNAUTHORIZED:
          case I_ERROR_SERVER:
            i_session->result = i_value;
            break;
          default:
            y_log_message(Y_LOG_LEVEL_DEBUG, "i_set_int_parameter - Error unknown result");
            ret = I_ERROR_PARAM;
            break;
        }
        break;
      case I_OPT_AUTH_METHOD:
        i_session->auth_method = i_value;
        break;
      case I_OPT_TOKEN_METHOD:
        i_session->token_method = i_value;
        break;
      case I_OPT_EXPIRES_IN:
        i_session->expires_in = i_value;
        break;
      case I_OPT_EXPIRES_AT:
        i_session->expires_at = (time_t)i_value;
        break;
      case I_OPT_OPENID_CONFIG_STRICT:
        i_session->openid_config_strict = i_value;
        break;
      case I_OPT_STATE_GENERATE:
        if (i_value > 0) {
          char value[i_value+1];
          value[0] = '\0';
          rand_string_nonce(value, i_value);
          value[i_value] = '\0';
          ret = i_set_str_parameter(i_session, I_OPT_STATE, value);
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "i_set_int_parameter - Error invalid state length");
          ret = I_ERROR_PARAM;
        }
        break;
      case I_OPT_NONCE_GENERATE:
        if (i_value) {
          char value[i_value+1];
          value[0] = '\0';
          rand_string_nonce(value, i_value);
          value[i_value] = '\0';
          ret = i_set_str_parameter(i_session, I_OPT_NONCE, value);
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "i_set_int_parameter - Error invalid nonce length");
          ret = I_ERROR_PARAM;
        }
        break;
      case I_OPT_TOKEN_JTI_GENERATE:
        if (i_value) {
          char value[i_value+1];
          value[0] = '\0';
          rand_string_nonce(value, i_value);
          value[i_value] = '\0';
          ret = i_set_str_parameter(i_session, I_OPT_TOKEN_JTI, value);
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "i_set_int_parameter - Error invalid nonce length");
          ret = I_ERROR_PARAM;
        }
        break;
      case I_OPT_X5U_FLAGS:
        i_session->x5u_flags = i_value;
        break;
      case I_OPT_TOKEN_EXP:
        if (i_value) {
          i_session->token_exp = i_value;
        } else {
          ret = I_ERROR_PARAM;
        }
        break;
      case I_OPT_DEVICE_AUTH_EXPIRES_IN:
        i_session->device_auth_expires_in = i_value;
        break;
      case I_OPT_DEVICE_AUTH_INTERVAL:
        i_session->device_auth_interval = i_value;
        break;
      case I_OPT_PUSHED_AUTH_REQ_REQUIRED:
        i_session->require_pushed_authorization_requests = i_value;
        break;
      case I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN:
        i_session->pushed_authorization_request_expires_in = i_value;
        break;
      case I_OPT_USE_DPOP:
        i_session->use_dpop = i_value;
        break;
      case I_OPT_DECRYPT_CODE:
        i_session->decrypt_code = i_value;
        break;
      case I_OPT_DECRYPT_REFRESH_TOKEN:
        i_session->decrypt_refresh_token = i_value;
        break;
      case I_OPT_DECRYPT_ACCESS_TOKEN:
        i_session->decrypt_access_token = i_value;
        break;
      case I_OPT_REMOTE_CERT_FLAG:
        i_session->remote_cert_flag = i_value;
        break;
      case I_OPT_PKCE_CODE_VERIFIER_GENERATE:
        if (i_value >= 43) {
          char value[i_value+1];
          value[0] = '\0';
          rand_string_nonce(value, i_value);
          value[i_value] = '\0';
          ret = i_set_str_parameter(i_session, I_OPT_PKCE_CODE_VERIFIER, value);
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "i_set_int_parameter - Error invalid PKCE length");
          ret = I_ERROR_PARAM;
        }
        break;
      case I_OPT_PKCE_METHOD:
        i_session->pkce_method = i_value;
        break;
      case I_OPT_CIBA_MODE:
        i_session->ciba_mode = i_value;
        break;
      case I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN_GENERATE:
        if (i_value >= 22 && i_value <= 1024) {
          char value[i_value+1];
          value[0] = '\0';
          rand_string_nonce(value, i_value);
          value[i_value] = '\0';
          ret = i_set_str_parameter(i_session, I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN, value);
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "i_set_int_parameter - Error invalid client_notification_token length");
          ret = I_ERROR_PARAM;
        }
        break;
      case I_OPT_CIBA_LOGIN_HINT_FORMAT:
        i_session->ciba_login_hint_format = i_value;
        break;
      case I_OPT_CIBA_AUTH_REQ_EXPIRES_IN:
        i_session->ciba_auth_req_expires_in = i_value;
        break;
      case I_OPT_CIBA_AUTH_REQ_INTERVAL:
        i_session->ciba_auth_req_interval = i_value;
        break;
      case I_OPT_FRONTCHANNEL_LOGOUT_SESSION_REQUIRED:
        i_session->frontchannel_logout_session_required = i_value;
        break;
      case I_OPT_BACKCHANNEL_LOGOUT_SESSION_REQUIRED:
        i_session->backchannel_logout_session_required = i_value;
        break;
      default:
        y_log_message(Y_LOG_LEVEL_DEBUG, "i_set_int_parameter - Error option");
        ret = I_ERROR_PARAM;
        break;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "i_set_int_parameter - Error input parameter");
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_set_str_parameter(struct _i_session * i_session, i_option option, const char * s_value) {
  int ret = I_OK;
  if (i_session != NULL) {
    switch (option) {
      case I_OPT_SCOPE:
        o_free(i_session->scope);
        if (o_strlen(s_value)) {
          i_session->scope = o_strdup(s_value);
        } else {
          i_session->scope = NULL;
        }
        break;
      case I_OPT_SCOPE_APPEND:
        if (o_strlen(s_value)) {
          if (i_session->scope == NULL) {
            i_session->scope = o_strdup(s_value);
          } else {
            i_session->scope = mstrcatf(i_session->scope, " %s", s_value);
          }
        }
        break;
      case I_OPT_STATE:
        o_free(i_session->state);
        if (o_strlen(s_value)) {
          i_session->state = o_strdup(s_value);
        } else {
          i_session->state = NULL;
        }
        break;
      case I_OPT_NONCE:
        o_free(i_session->nonce);
        if (o_strlen(s_value)) {
          i_session->nonce = o_strdup(s_value);
        } else {
          i_session->nonce = NULL;
        }
        break;
      case I_OPT_REDIRECT_URI:
        o_free(i_session->redirect_uri);
        if (o_strlen(s_value)) {
          i_session->redirect_uri = o_strdup(s_value);
        } else {
          i_session->redirect_uri = NULL;
        }
        break;
      case I_OPT_REDIRECT_TO:
        o_free(i_session->redirect_to);
        if (o_strlen(s_value)) {
          i_session->redirect_to = o_strdup(s_value);
        } else {
          i_session->redirect_to = NULL;
        }
        break;
      case I_OPT_CLIENT_ID:
        o_free(i_session->client_id);
        if (o_strlen(s_value)) {
          i_session->client_id = o_strdup(s_value);
        } else {
          i_session->client_id = NULL;
        }
        break;
      case I_OPT_CLIENT_SECRET:
        o_free(i_session->client_secret);
        if (o_strlen(s_value)) {
          i_session->client_secret = o_strdup(s_value);
        } else {
          i_session->client_secret = NULL;
        }
        break;
      case I_OPT_AUTH_ENDPOINT:
        o_free(i_session->authorization_endpoint);
        if (o_strlen(s_value)) {
          i_session->authorization_endpoint = o_strdup(s_value);
        } else {
          i_session->authorization_endpoint = NULL;
        }
        break;
      case I_OPT_TOKEN_ENDPOINT:
        o_free(i_session->token_endpoint);
        if (o_strlen(s_value)) {
          i_session->token_endpoint = o_strdup(s_value);
        } else {
          i_session->token_endpoint = NULL;
        }
        break;
      case I_OPT_OPENID_CONFIG_ENDPOINT:
        o_free(i_session->openid_config_endpoint);
        if (o_strlen(s_value)) {
          i_session->openid_config_endpoint = o_strdup(s_value);
        } else {
          i_session->openid_config_endpoint = NULL;
        }
        break;
      case I_OPT_USERINFO_ENDPOINT:
        o_free(i_session->userinfo_endpoint);
        if (o_strlen(s_value)) {
          i_session->userinfo_endpoint = o_strdup(s_value);
        } else {
          i_session->userinfo_endpoint = NULL;
        }
        break;
      case I_OPT_ERROR:
        o_free(i_session->error);
        if (o_strlen(s_value)) {
          i_session->error = o_strdup(s_value);
        } else {
          i_session->error = NULL;
        }
        break;
      case I_OPT_ERROR_DESCRIPTION:
        o_free(i_session->error_description);
        if (o_strlen(s_value)) {
          i_session->error_description = o_strdup(s_value);
        } else {
          i_session->error_description = NULL;
        }
        break;
      case I_OPT_ERROR_URI:
        o_free(i_session->error_uri);
        if (o_strlen(s_value)) {
          i_session->error_uri = o_strdup(s_value);
        } else {
          i_session->error_uri = NULL;
        }
        break;
      case I_OPT_CODE:
        o_free(i_session->code);
        if (o_strlen(s_value)) {
          i_session->code = o_strdup(s_value);
        } else {
          i_session->code = NULL;
        }
        break;
      case I_OPT_REFRESH_TOKEN:
        o_free(i_session->refresh_token);
        if (o_strlen(s_value)) {
          i_session->refresh_token = o_strdup(s_value);
        } else {
          i_session->refresh_token = NULL;
        }
        break;
      case I_OPT_ACCESS_TOKEN:
        json_decref(i_session->access_token_payload);
        i_session->access_token_payload = NULL;
        o_free(i_session->access_token);
        if (o_strlen(s_value)) {
          i_session->access_token = o_strdup(s_value);
        } else {
          i_session->access_token = NULL;
        }
        break;
      case I_OPT_ID_TOKEN:
        o_free(i_session->id_token);
        if (o_strlen(s_value)) {
          i_session->id_token = o_strdup(s_value);
        } else {
          i_session->id_token = NULL;
        }
        break;
      case I_OPT_TOKEN_TYPE:
        o_free(i_session->token_type);
        if (o_strlen(s_value)) {
          i_session->token_type = o_strdup(s_value);
        } else {
          i_session->token_type = NULL;
        }
        break;
      case I_OPT_USERNAME:
        o_free(i_session->username);
        if (o_strlen(s_value)) {
          i_session->username = o_strdup(s_value);
        } else {
          i_session->username = NULL;
        }
        break;
      case I_OPT_USER_PASSWORD:
        o_free(i_session->user_password);
        if (o_strlen(s_value)) {
          i_session->user_password = o_strdup(s_value);
        } else {
          i_session->user_password = NULL;
        }
        break;
      case I_OPT_OPENID_CONFIG:
        json_decref(i_session->openid_config);
        if (o_strlen(s_value)) {
          if ((i_session->openid_config = json_loads(s_value, JSON_DECODE_ANY, NULL)) != NULL) {
            if (_i_parse_openid_config(i_session, 0) == I_OK) {
              ret = I_OK;
            } else {
              json_decref(i_session->openid_config);
              i_session->openid_config = NULL;
              ret = I_ERROR;
            }
          } else {
            ret = I_ERROR;
          }
        } else {
          i_session->openid_config = NULL;
        }
        break;
      case I_OPT_ISSUER:
        o_free(i_session->issuer);
        if (o_strlen(s_value)) {
          i_session->issuer = o_strdup(s_value);
        } else {
          i_session->issuer = NULL;
        }
        break;
      case I_OPT_USERINFO:
        o_free(i_session->userinfo);
        json_decref(i_session->j_userinfo);
        i_session->j_userinfo = NULL;
        if (o_strlen(s_value)) {
          i_session->userinfo = o_strdup(s_value);
          i_session->j_userinfo = json_loads(s_value, JSON_DECODE_ANY, NULL);
        } else {
          i_session->userinfo = NULL;
        }
        break;
      case I_OPT_SERVER_KID:
        o_free(i_session->server_kid);
        if (o_strlen(s_value)) {
          i_session->server_kid = o_strdup(s_value);
        } else {
          i_session->server_kid = NULL;
        }
        break;
      case I_OPT_SERVER_ENC_ALG:
        if (o_strlen(s_value)) {
          i_session->server_enc_alg = r_str_to_jwa_alg(s_value);
        } else {
          i_session->server_enc_alg = R_JWA_ALG_UNKNOWN;
        }
        break;
      case I_OPT_SERVER_ENC:
        if (o_strlen(s_value)) {
          i_session->server_enc = r_str_to_jwa_enc(s_value);
        } else {
          i_session->server_enc = R_JWA_ENC_UNKNOWN;
        }
        break;
      case I_OPT_CLIENT_KID:
        o_free(i_session->client_kid);
        if (o_strlen(s_value)) {
          i_session->client_kid = o_strdup(s_value);
        } else {
          i_session->client_kid = NULL;
        }
        break;
      case I_OPT_CLIENT_SIGN_ALG:
        if (o_strlen(s_value)) {
          i_session->client_sign_alg = r_str_to_jwa_alg(s_value);
        } else {
          i_session->client_sign_alg = R_JWA_ALG_UNKNOWN;
        }
        break;
      case I_OPT_CLIENT_ENC_ALG:
        if (o_strlen(s_value)) {
          i_session->client_enc_alg = r_str_to_jwa_alg(s_value);
        } else {
          i_session->client_enc_alg = R_JWA_ALG_UNKNOWN;
        }
        break;
      case I_OPT_CLIENT_ENC:
        if (o_strlen(s_value)) {
          i_session->client_enc = r_str_to_jwa_enc(s_value);
        } else {
          i_session->client_enc = R_JWA_ENC_UNKNOWN;
        }
        break;
      case I_OPT_TOKEN_JTI:
        o_free(i_session->token_jti);
        if (o_strlen(s_value)) {
          i_session->token_jti = o_strdup(s_value);
        } else {
          i_session->token_jti = NULL;
        }
        break;
      case I_OPT_TOKEN_TARGET:
        o_free(i_session->token_target);
        if (o_strlen(s_value)) {
          i_session->token_target = o_strdup(s_value);
        } else {
          i_session->token_target = NULL;
        }
        break;
      case I_OPT_TOKEN_TARGET_TYPE_HINT:
        o_free(i_session->token_target_type_hint);
        if (o_strlen(s_value)) {
          i_session->token_target_type_hint = o_strdup(s_value);
        } else {
          i_session->token_target_type_hint = NULL;
        }
        break;
      case I_OPT_REVOCATION_ENDPOINT:
        o_free(i_session->revocation_endpoint);
        if (o_strlen(s_value)) {
          i_session->revocation_endpoint = o_strdup(s_value);
        } else {
          i_session->revocation_endpoint = NULL;
        }
        break;
      case I_OPT_INTROSPECTION_ENDPOINT:
        o_free(i_session->introspection_endpoint);
        if (o_strlen(s_value)) {
          i_session->introspection_endpoint = o_strdup(s_value);
        } else {
          i_session->introspection_endpoint = NULL;
        }
        break;
      case I_OPT_REGISTRATION_ENDPOINT:
        o_free(i_session->registration_endpoint);
        if (o_strlen(s_value)) {
          i_session->registration_endpoint = o_strdup(s_value);
        } else {
          i_session->registration_endpoint = NULL;
        }
        break;
      case I_OPT_DEVICE_AUTHORIZATION_ENDPOINT:
        o_free(i_session->device_authorization_endpoint);
        if (o_strlen(s_value)) {
          i_session->device_authorization_endpoint = o_strdup(s_value);
        } else {
          i_session->device_authorization_endpoint = NULL;
        }
        break;
      case I_OPT_DEVICE_AUTH_CODE:
        o_free(i_session->device_auth_code);
        if (o_strlen(s_value)) {
          i_session->device_auth_code = o_strdup(s_value);
        } else {
          i_session->device_auth_code = NULL;
        }
        break;
      case I_OPT_DEVICE_AUTH_USER_CODE:
        o_free(i_session->device_auth_user_code);
        if (o_strlen(s_value)) {
          i_session->device_auth_user_code = o_strdup(s_value);
        } else {
          i_session->device_auth_user_code = NULL;
        }
        break;
      case I_OPT_DEVICE_AUTH_VERIFICATION_URI:
        o_free(i_session->device_auth_verification_uri);
        if (o_strlen(s_value)) {
          i_session->device_auth_verification_uri = o_strdup(s_value);
        } else {
          i_session->device_auth_verification_uri = NULL;
        }
        break;
      case I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE:
        o_free(i_session->device_auth_verification_uri_complete);
        if (o_strlen(s_value)) {
          i_session->device_auth_verification_uri_complete = o_strdup(s_value);
        } else {
          i_session->device_auth_verification_uri_complete = NULL;
        }
        break;
      case I_OPT_END_SESSION_ENDPOINT:
        o_free(i_session->end_session_endpoint);
        if (o_strlen(s_value)) {
          i_session->end_session_endpoint = o_strdup(s_value);
        } else {
          i_session->end_session_endpoint = NULL;
        }
        break;
      case I_OPT_CHECK_SESSION_IRAME:
        o_free(i_session->check_session_iframe);
        if (o_strlen(s_value)) {
          i_session->check_session_iframe = o_strdup(s_value);
        } else {
          i_session->check_session_iframe = NULL;
        }
        break;
      case I_OPT_PUSHED_AUTH_REQ_ENDPOINT:
        o_free(i_session->pushed_authorization_request_endpoint);
        if (o_strlen(s_value)) {
          i_session->pushed_authorization_request_endpoint = o_strdup(s_value);
        } else {
          i_session->pushed_authorization_request_endpoint = NULL;
        }
        break;
      case I_OPT_PUSHED_AUTH_REQ_URI:
        o_free(i_session->pushed_authorization_request_uri);
        if (o_strlen(s_value)) {
          i_session->pushed_authorization_request_uri = o_strdup(s_value);
        } else {
          i_session->pushed_authorization_request_uri = NULL;
        }
        break;
      case I_OPT_DPOP_KID:
        o_free(i_session->dpop_kid);
        if (o_strlen(s_value)) {
          i_session->dpop_kid = o_strdup(s_value);
        } else {
          i_session->dpop_kid = NULL;
        }
        break;
      case I_OPT_DPOP_SIGN_ALG:
        if (o_strlen(s_value)) {
          i_session->dpop_sign_alg = r_str_to_jwa_alg(s_value);
        } else {
          i_session->dpop_sign_alg = R_JWA_ALG_UNKNOWN;
        }
        break;
      case I_OPT_TLS_KEY_FILE:
        o_free(i_session->key_file);
        if (o_strlen(s_value)) {
          i_session->key_file = o_strdup(s_value);
        } else {
          i_session->key_file = NULL;
        }
        break;
      case I_OPT_TLS_CERT_FILE:
        o_free(i_session->cert_file);
        if (o_strlen(s_value)) {
          i_session->cert_file = o_strdup(s_value);
        } else {
          i_session->cert_file = NULL;
        }
        break;
      case I_OPT_PKCE_CODE_VERIFIER:
        o_free(i_session->pkce_code_verifier);
        i_session->pkce_code_verifier = NULL;
        if (o_strlen(s_value)) {
          if (o_strlen(s_value) >= 43 && string_use_char_list_only(s_value, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")) {
            i_session->pkce_code_verifier = o_strdup(s_value);
          } else {
            y_log_message(Y_LOG_LEVEL_DEBUG, "i_set_str_parameter - Error invalid PCKCE code verifier");
            ret = I_ERROR_PARAM;
          }
        }
        break;
      case I_OPT_RESOURCE_INDICATOR:
        o_free(i_session->resource_indicator);
        if (o_strlen(s_value)) {
          i_session->resource_indicator = o_strdup(s_value);
        } else {
          i_session->resource_indicator = NULL;
        }
        break;
      case I_OPT_ACCESS_TOKEN_SIGNING_ALG:
        if (o_strlen(s_value)) {
          i_session->access_token_signing_alg = r_str_to_jwa_alg(s_value);
        } else {
          i_session->access_token_signing_alg = R_JWA_ALG_UNKNOWN;
        }
        break;
      case I_OPT_ACCESS_TOKEN_ENCRYPTION_ALG:
        if (o_strlen(s_value)) {
          i_session->access_token_encryption_alg = r_str_to_jwa_alg(s_value);
        } else {
          i_session->access_token_encryption_alg = R_JWA_ALG_UNKNOWN;
        }
        break;
      case I_OPT_ACCESS_TOKEN_ENCRYPTION_ENC:
        if (o_strlen(s_value)) {
          i_session->access_token_encryption_enc = r_str_to_jwa_enc(s_value);
        } else {
          i_session->access_token_encryption_enc = R_JWA_ENC_UNKNOWN;
        }
        break;
      case I_OPT_ID_TOKEN_SIGNING_ALG:
        if (o_strlen(s_value)) {
          i_session->id_token_signing_alg = r_str_to_jwa_alg(s_value);
        } else {
          i_session->id_token_signing_alg = R_JWA_ALG_UNKNOWN;
        }
        break;
      case I_OPT_ID_TOKEN_ENCRYPTION_ALG:
        if (o_strlen(s_value)) {
          i_session->id_token_encryption_alg = r_str_to_jwa_alg(s_value);
        } else {
          i_session->id_token_encryption_alg = R_JWA_ALG_UNKNOWN;
        }
        break;
      case I_OPT_ID_TOKEN_ENCRYPTION_ENC:
        if (o_strlen(s_value)) {
          i_session->id_token_encryption_enc = r_str_to_jwa_enc(s_value);
        } else {
          i_session->id_token_encryption_enc = R_JWA_ENC_UNKNOWN;
        }
        break;
      case I_OPT_USERINFO_SIGNING_ALG:
        if (o_strlen(s_value)) {
          i_session->userinfo_signing_alg = r_str_to_jwa_alg(s_value);
        } else {
          i_session->userinfo_signing_alg = R_JWA_ALG_UNKNOWN;
        }
        break;
      case I_OPT_USERINFO_ENCRYPTION_ALG:
        if (o_strlen(s_value)) {
          i_session->userinfo_encryption_alg = r_str_to_jwa_alg(s_value);
        } else {
          i_session->userinfo_encryption_alg = R_JWA_ALG_UNKNOWN;
        }
        break;
      case I_OPT_USERINFO_ENCRYPTION_ENC:
        if (o_strlen(s_value)) {
          i_session->userinfo_encryption_enc = r_str_to_jwa_enc(s_value);
        } else {
          i_session->userinfo_encryption_enc = R_JWA_ENC_UNKNOWN;
        }
        break;
      case I_OPT_REQUEST_OBJECT_SIGNING_ALG:
        if (o_strlen(s_value)) {
          i_session->request_object_signing_alg = r_str_to_jwa_alg(s_value);
        } else {
          i_session->request_object_signing_alg = R_JWA_ALG_UNKNOWN;
        }
        break;
      case I_OPT_REQUEST_OBJECT_ENCRYPTION_ALG:
        if (o_strlen(s_value)) {
          i_session->request_object_encryption_alg = r_str_to_jwa_alg(s_value);
        } else {
          i_session->request_object_encryption_alg = R_JWA_ALG_UNKNOWN;
        }
        break;
      case I_OPT_REQUEST_OBJECT_ENCRYPTION_ENC:
        if (o_strlen(s_value)) {
          i_session->request_object_encryption_enc = r_str_to_jwa_enc(s_value);
        } else {
          i_session->request_object_encryption_enc = R_JWA_ENC_UNKNOWN;
        }
        break;
      case I_OPT_TOKEN_ENDPOINT_SIGNING_ALG:
        if (o_strlen(s_value)) {
          i_session->token_endpoint_signing_alg = r_str_to_jwa_alg(s_value);
        } else {
          i_session->token_endpoint_signing_alg = R_JWA_ALG_UNKNOWN;
        }
        break;
      case I_OPT_TOKEN_ENDPOINT_ENCRYPTION_ALG:
        if (o_strlen(s_value)) {
          i_session->token_endpoint_encryption_alg = r_str_to_jwa_alg(s_value);
        } else {
          i_session->token_endpoint_encryption_alg = R_JWA_ALG_UNKNOWN;
        }
        break;
      case I_OPT_TOKEN_ENDPOINT_ENCRYPTION_ENC:
        if (o_strlen(s_value)) {
          i_session->token_endpoint_encryption_enc = r_str_to_jwa_enc(s_value);
        } else {
          i_session->token_endpoint_encryption_enc = R_JWA_ENC_UNKNOWN;
        }
        break;
      case I_OPT_CIBA_REQUEST_SIGNING_ALG:
        if (o_strlen(s_value)) {
          i_session->ciba_request_signing_alg = r_str_to_jwa_alg(s_value);
        } else {
          i_session->ciba_request_signing_alg = R_JWA_ALG_UNKNOWN;
        }
        break;
      case I_OPT_CIBA_REQUEST_ENCRYPTION_ALG:
        if (o_strlen(s_value)) {
          i_session->ciba_request_encryption_alg = r_str_to_jwa_alg(s_value);
        } else {
          i_session->ciba_request_encryption_alg = R_JWA_ALG_UNKNOWN;
        }
        break;
      case I_OPT_CIBA_REQUEST_ENCRYPTION_ENC:
        if (o_strlen(s_value)) {
          i_session->ciba_request_encryption_enc = r_str_to_jwa_enc(s_value);
        } else {
          i_session->ciba_request_encryption_enc = R_JWA_ENC_UNKNOWN;
        }
        break;
      case I_OPT_AUTH_RESPONSE_SIGNING_ALG:
        if (o_strlen(s_value)) {
          i_session->auth_response_signing_alg = r_str_to_jwa_alg(s_value);
        } else {
          i_session->auth_response_signing_alg = R_JWA_ALG_UNKNOWN;
        }
        break;
      case I_OPT_AUTH_RESPONSE_ENCRYPTION_ALG:
        if (o_strlen(s_value)) {
          i_session->auth_response_encryption_alg = r_str_to_jwa_alg(s_value);
        } else {
          i_session->auth_response_encryption_alg = R_JWA_ALG_UNKNOWN;
        }
        break;
      case I_OPT_AUTH_RESPONSE_ENCRYPTION_ENC:
        if (o_strlen(s_value)) {
          i_session->auth_response_encryption_enc = r_str_to_jwa_enc(s_value);
        } else {
          i_session->auth_response_encryption_enc = R_JWA_ENC_UNKNOWN;
        }
        break;
      case I_OPT_CIBA_ENDPOINT:
        o_free(i_session->ciba_endpoint);
        if (o_strlen(s_value)) {
          i_session->ciba_endpoint = o_strdup(s_value);
        } else {
          i_session->ciba_endpoint = NULL;
        }
        break;
      case I_OPT_CIBA_USER_CODE:
        o_free(i_session->ciba_user_code);
        if (o_strlen(s_value)) {
          i_session->ciba_user_code = o_strdup(s_value);
        } else {
          i_session->ciba_user_code = NULL;
        }
        break;
      case I_OPT_CIBA_LOGIN_HINT:
        o_free(i_session->ciba_login_hint);
        if (o_strlen(s_value)) {
          i_session->ciba_login_hint = o_strdup(s_value);
        } else {
          i_session->ciba_login_hint = NULL;
        }
        break;
      case I_OPT_CIBA_LOGIN_HINT_KID:
        o_free(i_session->ciba_login_hint_kid);
        if (o_strlen(s_value)) {
          i_session->ciba_login_hint_kid = o_strdup(s_value);
        } else {
          i_session->ciba_login_hint_kid = NULL;
        }
        break;
      case I_OPT_CIBA_BINDING_MESSAGE:
        o_free(i_session->ciba_binding_message);
        if (o_strlen(s_value)) {
          i_session->ciba_binding_message = o_strdup(s_value);
        } else {
          i_session->ciba_binding_message = NULL;
        }
        break;
      case I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN:
        o_free(i_session->ciba_client_notification_token);
        if (o_strlen(s_value)) {
          i_session->ciba_client_notification_token = o_strdup(s_value);
        } else {
          i_session->ciba_client_notification_token = NULL;
        }
        break;
      case I_OPT_CIBA_AUTH_REQ_ID:
        o_free(i_session->ciba_auth_req_id);
        if (o_strlen(s_value)) {
          i_session->ciba_auth_req_id = o_strdup(s_value);
        } else {
          i_session->ciba_auth_req_id = NULL;
        }
        break;
      case I_OPT_CIBA_CLIENT_NOTIFICATION_ENDPOINT:
        o_free(i_session->ciba_client_notification_endpoint);
        if (o_strlen(s_value)) {
          i_session->ciba_client_notification_endpoint = o_strdup(s_value);
        } else {
          i_session->ciba_client_notification_endpoint = NULL;
        }
        break;
      case I_OPT_FRONTCHANNEL_LOGOUT_URI:
        o_free(i_session->frontchannel_logout_uri);
        if (o_strlen(s_value)) {
          i_session->frontchannel_logout_uri = o_strdup(s_value);
        } else {
          i_session->frontchannel_logout_uri = NULL;
        }
        break;
      case I_OPT_BACKCHANNEL_LOGOUT_URI:
        o_free(i_session->backchannel_logout_uri);
        if (o_strlen(s_value)) {
          i_session->backchannel_logout_uri = o_strdup(s_value);
        } else {
          i_session->backchannel_logout_uri = NULL;
        }
        break;
      case I_OPT_POST_LOGOUT_REDIRECT_URI:
        o_free(i_session->post_logout_redirect_uri);
        if (o_strlen(s_value)) {
          i_session->post_logout_redirect_uri = o_strdup(s_value);
        } else {
          i_session->post_logout_redirect_uri = NULL;
        }
        break;
      case I_OPT_ID_TOKEN_SID:
        o_free(i_session->id_token_sid);
        if (o_strlen(s_value)) {
          i_session->id_token_sid = o_strdup(s_value);
        } else {
          i_session->id_token_sid = NULL;
        }
        break;
      default:
        y_log_message(Y_LOG_LEVEL_DEBUG, "i_set_str_parameter - Error unknown option %d", option);
        ret = I_ERROR_PARAM;
        break;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "i_set_str_parameter - Error input parameter");
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_set_additional_parameter(struct _i_session * i_session, const char * s_key, const char * s_value) {
  int ret = I_OK;
  if (i_session != NULL && s_key != NULL) {
    if (u_map_put(&i_session->additional_parameters, s_key, s_value) != U_OK) {
      ret = I_ERROR;
    }
  } else {
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_set_additional_response(struct _i_session * i_session, const char * s_key, const char * s_value) {
  int ret = I_OK;
  if (i_session != NULL && s_key != NULL) {
    if (u_map_put(&i_session->additional_response, s_key, s_value) != U_OK) {
      ret = I_ERROR;
    }
  } else {
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_add_claim_request(struct _i_session * i_session, int target, const char * claim, int essential, const char * value) {
  int ret = I_OK;
  json_t * j_value = NULL;
  
  if (i_session != NULL && o_strlen(claim)) {
    if (target == I_CLAIM_TARGET_ALL || target == I_CLAIM_TARGET_USERINFO || target == I_CLAIM_TARGET_ID_TOKEN) {
      if (value != NULL) {
        if ((j_value = json_loads(value, JSON_DECODE_ANY, NULL)) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_add_claim_request - Error parsing value");
          ret = I_ERROR_PARAM;
        }
      } else {
        if (essential == I_CLAIM_ESSENTIAL_NULL) {
          j_value = json_null();
        } else if (essential == I_CLAIM_ESSENTIAL_TRUE) {
          j_value = json_pack("{so}", "essential", json_true());
        } else if (essential == I_CLAIM_ESSENTIAL_FALSE) {
          j_value = json_pack("{so}", "essential", json_false());
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_add_claim_request - Invalid essential value");
          ret = I_ERROR_PARAM;
        }
      }
      if (j_value != NULL) {
        if (target == I_CLAIM_TARGET_ALL || target == I_CLAIM_TARGET_USERINFO) {
          json_object_set(json_object_get(i_session->j_claims, "userinfo"), claim, j_value);
        }
        if (target == I_CLAIM_TARGET_ALL || target == I_CLAIM_TARGET_ID_TOKEN) {
          json_object_set(json_object_get(i_session->j_claims, "id_token"), claim, j_value);
        }
        json_decref(j_value);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_add_claim_request - Invalid target value");
      ret = I_ERROR_PARAM;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "i_add_claim_request - Error input parameters");
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_remove_claim_request(struct _i_session * i_session, int target, const char * claim) {
  int ret = I_OK, found;
  
  if (i_session != NULL && o_strlen(claim)) {
    if (target == I_CLAIM_TARGET_ALL || target == I_CLAIM_TARGET_USERINFO || target == I_CLAIM_TARGET_ID_TOKEN) {
      found = 0;
      if (target == I_CLAIM_TARGET_ALL || target == I_CLAIM_TARGET_USERINFO) {
        if (json_object_get(json_object_get(i_session->j_claims, "userinfo"), claim) != NULL) {
          json_object_del(json_object_get(i_session->j_claims, "userinfo"), claim);
          found = 1;
        }
      }
      if (target == I_CLAIM_TARGET_ALL || target == I_CLAIM_TARGET_ID_TOKEN) {
        if (json_object_get(json_object_get(i_session->j_claims, "id_token"), claim) != NULL) {
          json_object_del(json_object_get(i_session->j_claims, "id_token"), claim);
          found = 1;
        }
      }
      if (!found) {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_remove_claim_request - Invalid claim value");
        ret = I_ERROR_PARAM;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_add_claim_request - Invalid target value");
      ret = I_ERROR_PARAM;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "i_remove_claim_request - Error input parameters");
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_set_parameter_list(struct _i_session * i_session, ...) {
  unsigned int option, i_value, ret = I_OK;
  const char * str_key, * str_value;
  va_list vl;

  if (i_session != NULL) {
    va_start(vl, i_session);
    for (option = va_arg(vl, unsigned int); option != I_OPT_NONE && ret == I_OK; option = va_arg(vl, unsigned int)) {
      switch (option) {
        case I_OPT_RESPONSE_TYPE:
        case I_OPT_RESULT:
        case I_OPT_AUTH_METHOD:
        case I_OPT_TOKEN_METHOD:
        case I_OPT_EXPIRES_IN:
        case I_OPT_EXPIRES_AT:
        case I_OPT_STATE_GENERATE:
        case I_OPT_NONCE_GENERATE:
        case I_OPT_X5U_FLAGS:
        case I_OPT_OPENID_CONFIG_STRICT:
        case I_OPT_TOKEN_JTI_GENERATE:
        case I_OPT_TOKEN_EXP:
        case I_OPT_DEVICE_AUTH_EXPIRES_IN:
        case I_OPT_DEVICE_AUTH_INTERVAL:
        case I_OPT_PUSHED_AUTH_REQ_REQUIRED:
        case I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN:
        case I_OPT_USE_DPOP:
        case I_OPT_DECRYPT_CODE:
        case I_OPT_DECRYPT_REFRESH_TOKEN:
        case I_OPT_DECRYPT_ACCESS_TOKEN:
        case I_OPT_REMOTE_CERT_FLAG:
        case I_OPT_PKCE_CODE_VERIFIER_GENERATE:
        case I_OPT_PKCE_METHOD:
        case I_OPT_CIBA_MODE:
        case I_OPT_CIBA_LOGIN_HINT_FORMAT:
        case I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN_GENERATE:
        case I_OPT_CIBA_AUTH_REQ_EXPIRES_IN:
        case I_OPT_CIBA_AUTH_REQ_INTERVAL:
        case I_OPT_FRONTCHANNEL_LOGOUT_SESSION_REQUIRED:
        case I_OPT_BACKCHANNEL_LOGOUT_SESSION_REQUIRED:
          i_value = va_arg(vl, unsigned int);
          ret = i_set_int_parameter(i_session, option, i_value);
          break;
        case I_OPT_SCOPE:
        case I_OPT_SCOPE_APPEND:
        case I_OPT_STATE:
        case I_OPT_NONCE:
        case I_OPT_REDIRECT_URI:
        case I_OPT_REDIRECT_TO:
        case I_OPT_CLIENT_ID:
        case I_OPT_CLIENT_SECRET:
        case I_OPT_AUTH_ENDPOINT:
        case I_OPT_TOKEN_ENDPOINT:
        case I_OPT_OPENID_CONFIG_ENDPOINT:
        case I_OPT_OPENID_CONFIG:
        case I_OPT_USERINFO_ENDPOINT:
        case I_OPT_ERROR:
        case I_OPT_ERROR_DESCRIPTION:
        case I_OPT_ERROR_URI:
        case I_OPT_CODE:
        case I_OPT_REFRESH_TOKEN:
        case I_OPT_ACCESS_TOKEN:
        case I_OPT_ID_TOKEN:
        case I_OPT_TOKEN_TYPE:
        case I_OPT_USERNAME:
        case I_OPT_USER_PASSWORD:
        case I_OPT_ISSUER:
        case I_OPT_USERINFO:
        case I_OPT_SERVER_KID:
        case I_OPT_SERVER_ENC_ALG:
        case I_OPT_SERVER_ENC:
        case I_OPT_CLIENT_KID:
        case I_OPT_CLIENT_SIGN_ALG:
        case I_OPT_CLIENT_ENC_ALG:
        case I_OPT_CLIENT_ENC:
        case I_OPT_TOKEN_JTI:
        case I_OPT_TOKEN_TARGET:
        case I_OPT_TOKEN_TARGET_TYPE_HINT:
        case I_OPT_REVOCATION_ENDPOINT:
        case I_OPT_INTROSPECTION_ENDPOINT:
        case I_OPT_REGISTRATION_ENDPOINT:
        case I_OPT_DEVICE_AUTHORIZATION_ENDPOINT:
        case I_OPT_DEVICE_AUTH_CODE:
        case I_OPT_DEVICE_AUTH_USER_CODE:
        case I_OPT_DEVICE_AUTH_VERIFICATION_URI:
        case I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE:
        case I_OPT_END_SESSION_ENDPOINT:
        case I_OPT_CHECK_SESSION_IRAME:
        case I_OPT_PUSHED_AUTH_REQ_ENDPOINT:
        case I_OPT_PUSHED_AUTH_REQ_URI:
        case I_OPT_DPOP_KID:
        case I_OPT_DPOP_SIGN_ALG:
        case I_OPT_TLS_KEY_FILE:
        case I_OPT_TLS_CERT_FILE:
        case I_OPT_PKCE_CODE_VERIFIER:
        case I_OPT_RESOURCE_INDICATOR:
        case I_OPT_ACCESS_TOKEN_SIGNING_ALG:
        case I_OPT_ACCESS_TOKEN_ENCRYPTION_ALG:
        case I_OPT_ACCESS_TOKEN_ENCRYPTION_ENC:
        case I_OPT_ID_TOKEN_SIGNING_ALG:
        case I_OPT_ID_TOKEN_ENCRYPTION_ALG:
        case I_OPT_ID_TOKEN_ENCRYPTION_ENC:
        case I_OPT_USERINFO_SIGNING_ALG:
        case I_OPT_USERINFO_ENCRYPTION_ALG:
        case I_OPT_USERINFO_ENCRYPTION_ENC:
        case I_OPT_REQUEST_OBJECT_SIGNING_ALG:
        case I_OPT_REQUEST_OBJECT_ENCRYPTION_ALG:
        case I_OPT_REQUEST_OBJECT_ENCRYPTION_ENC:
        case I_OPT_TOKEN_ENDPOINT_SIGNING_ALG:
        case I_OPT_TOKEN_ENDPOINT_ENCRYPTION_ALG:
        case I_OPT_TOKEN_ENDPOINT_ENCRYPTION_ENC:
        case I_OPT_CIBA_REQUEST_SIGNING_ALG:
        case I_OPT_CIBA_REQUEST_ENCRYPTION_ALG:
        case I_OPT_CIBA_REQUEST_ENCRYPTION_ENC:
        case I_OPT_AUTH_RESPONSE_SIGNING_ALG:
        case I_OPT_AUTH_RESPONSE_ENCRYPTION_ALG:
        case I_OPT_AUTH_RESPONSE_ENCRYPTION_ENC:
        case I_OPT_CIBA_ENDPOINT:
        case I_OPT_CIBA_USER_CODE:
        case I_OPT_CIBA_LOGIN_HINT:
        case I_OPT_CIBA_LOGIN_HINT_KID:
        case I_OPT_CIBA_BINDING_MESSAGE:
        case I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN:
        case I_OPT_CIBA_AUTH_REQ_ID:
        case I_OPT_CIBA_CLIENT_NOTIFICATION_ENDPOINT:
        case I_OPT_FRONTCHANNEL_LOGOUT_URI:
        case I_OPT_BACKCHANNEL_LOGOUT_URI:
        case I_OPT_POST_LOGOUT_REDIRECT_URI:
        case I_OPT_ID_TOKEN_SID:
          str_value = va_arg(vl, const char *);
          ret = i_set_str_parameter(i_session, option, str_value);
          break;
        case I_OPT_ADDITIONAL_PARAMETER:
          str_key = va_arg(vl, const char *);
          str_value = va_arg(vl, const char *);
          ret = i_set_additional_parameter(i_session, str_key, str_value);
          break;
        case I_OPT_ADDITIONAL_RESPONSE:
          str_key = va_arg(vl, const char *);
          str_value = va_arg(vl, const char *);
          ret = i_set_additional_response(i_session, str_key, str_value);
          break;
        default:
          y_log_message(Y_LOG_LEVEL_DEBUG, "i_set_parameter_list - Error unknown option %d", option);
          ret = I_ERROR_PARAM;
          break;
      }
    }
    va_end(vl);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "i_set_parameter_list - Error input parameter");
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_get_openid_config(struct _i_session * i_session) {
  int ret;
  struct _u_request request;
  struct _u_response response;

  if (i_session != NULL && i_session->openid_config_endpoint != NULL) {
    _i_init_request(i_session, &request);
    ulfius_init_response(&response);

    ulfius_set_request_properties(&request, U_OPT_HEADER_PARAMETER, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR,
                                            U_OPT_HEADER_PARAMETER, "Accept", "application/json",
                                            U_OPT_HTTP_URL, i_session->openid_config_endpoint,
                                            U_OPT_NONE);
    if (ulfius_send_http_request(&request, &response) == U_OK) {
      if (response.status == 200) {
        if ((i_session->openid_config = ulfius_get_json_body_response(&response, NULL)) != NULL) {
          if ((ret = _i_parse_openid_config(i_session, 1)) == I_OK) {
            ret = I_OK;
          } else if (ret == I_ERROR) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_get_openid_config - Error _i_parse_openid_config");
            ret = I_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_get_openid_config - Error response not in JSON format");
          ret = I_ERROR;
        }
      } else if (response.status >= 400 && response.status < 500) {
        ret = I_ERROR_PARAM;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_get_openid_config - Error invalid response status: %d", response.status);
        ret = I_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_get_openid_config - Error getting config_endpoint");
      ret = I_ERROR;
    }
    ulfius_clean_request(&request);
    ulfius_clean_response(&response);
  } else {
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_get_userinfo(struct _i_session * i_session, int get_jwt) {
  struct _u_map header;
  int ret;

  u_map_init(&header);

  if (get_jwt) {
    u_map_put(&header, "Accept", "application/token-userinfo+jwt");
  } else {
    u_map_put(&header, "Accept", "application/json");
  }
  ret = i_get_userinfo_custom(i_session, NULL, NULL, &header);
  u_map_clean(&header);

  return ret;
}

int i_get_userinfo_custom(struct _i_session * i_session, const char * http_method, struct _u_map * additional_query, struct _u_map * additional_headers) {
  int ret;
  struct _u_request request;
  struct _u_response response;
  char * bearer = NULL, * token = NULL, * dpop_token = NULL;
  const char ** keys;
  size_t i;
  jwt_t * jwt = NULL;
  json_t * j_response;

  if (i_session != NULL && i_session->userinfo_endpoint != NULL && i_session->access_token != NULL) {
    _i_init_request(i_session, &request);
    ulfius_init_response(&response);

    if (o_strlen(http_method)) {
      ulfius_set_request_properties(&request, U_OPT_HTTP_VERB, http_method, U_OPT_NONE);
    }
    if (additional_headers != NULL) {
      keys = u_map_enum_keys(additional_headers);
      for (i=0; keys[i]!=NULL; i++) {
        ulfius_set_request_properties(&request, U_OPT_HEADER_PARAMETER, keys[i], u_map_get(additional_headers, keys[i]), U_OPT_NONE);
      }
    }

    ulfius_set_request_properties(&request, U_OPT_HTTP_URL, i_session->userinfo_endpoint, U_OPT_NONE);
    if (additional_query != NULL) {
      keys = u_map_enum_keys(additional_query);
      for (i=0; keys[i]!=NULL; i++) {
        ulfius_set_request_properties(&request, U_OPT_URL_PARAMETER, keys[i], u_map_get(additional_query, keys[i]), U_OPT_NONE);
      }
    }

    bearer = msprintf("Bearer %s", i_session->access_token);
    if (ulfius_set_request_properties(&request, U_OPT_HEADER_PARAMETER, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR, U_OPT_HEADER_PARAMETER, "Authorization", bearer, U_OPT_NONE) == U_OK) {
      // Set DPoP
      if (i_session->use_dpop) {
        if ((dpop_token = i_generate_dpop_token(i_session, http_method!=NULL?http_method:"GET", i_session->userinfo_endpoint, 0, 1)) != NULL) {
          if (ulfius_set_request_properties(&request, U_OPT_HEADER_PARAMETER, I_HEADER_DPOP, dpop_token, U_OPT_NONE) != U_OK) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "i_get_userinfo_custom - Error setting DPoP in header");
            ret = I_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "i_get_userinfo_custom - Error i_generate_dpop_token");
          ret = I_ERROR;
        }
        o_free(dpop_token);
      }
      if (ulfius_send_http_request(&request, &response) == U_OK) {
        j_response = ulfius_get_json_body_response(&response, NULL);
        if (response.status == 200) {
          if (NULL != o_strstr(u_map_get_case(response.map_header, "Content-Type"), "application/jwt")) {
            if (r_jwt_init(&jwt) == RHN_OK) {
              token = o_strndup(response.binary_body, response.binary_body_length);
              if (_i_verify_jwt_sig_enc(i_session, token, I_TOKEN_TYPE_USERINFO, jwt) != I_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "i_get_userinfo_custom - Error _i_verify_jwt_sig_enc");
                ret = I_ERROR;
              } else {
                json_decref(i_session->j_userinfo);
                i_session->j_userinfo = r_jwt_get_full_claims_json_t(jwt);
                o_free(i_session->userinfo);
                i_session->userinfo = r_jwt_get_full_claims_str(jwt);
                ret = I_OK;
              }
              o_free(token);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_get_userinfo_custom - Error r_jwt_init");
              ret = I_ERROR;
            }
            r_jwt_free(jwt);
          } else {
            o_free(i_session->userinfo);
            if ((i_session->userinfo = o_strndup(response.binary_body, response.binary_body_length)) != NULL) {
              json_decref(i_session->j_userinfo);
              i_session->j_userinfo = json_loads(i_session->userinfo, JSON_DECODE_ANY, NULL);
              ret = I_OK;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_get_userinfo_custom - Error getting response");
              ret = I_ERROR;
            }
          }
        } else if (response.status == 404) {
          ret = I_ERROR_PARAM;
        } else if (response.status == 400) {
          if (_i_parse_error_response(i_session, j_response) != I_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_get_userinfo_custom - Error _i_parse_error_response (1)");
          }
          ret = I_ERROR_PARAM;
        } else if (response.status == 401 || response.status == 403) {
          if (_i_parse_error_response(i_session, j_response) != I_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_get_userinfo_custom - Error _i_parse_error_response (1)");
          }
          ret = I_ERROR_UNAUTHORIZED;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_get_userinfo_custom - Error invalid response status: %d", response.status);
          ret = I_ERROR;
        }
        json_decref(j_response);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_get_userinfo_custom - Error getting userinfo_endpoint");
        ret = I_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_get_userinfo_custom - Error u_map_put");
      ret = I_ERROR;
    }
    o_free(bearer);
    ulfius_clean_request(&request);
    ulfius_clean_response(&response);
  } else {
    ret = I_ERROR_PARAM;
  }
  return ret;
}

unsigned int i_get_response_type(struct _i_session * i_session) {
  return i_get_int_parameter(i_session, I_OPT_RESPONSE_TYPE);
}

unsigned int i_get_result(struct _i_session * i_session) {
  return i_get_int_parameter(i_session, I_OPT_RESULT);
}

unsigned int i_get_int_parameter(struct _i_session * i_session, i_option option) {
  if (i_session != NULL) {
    switch (option) {
      case I_OPT_RESPONSE_TYPE:
        return i_session->response_type;
        break;
      case I_OPT_RESULT:
        return i_session->result;
        break;
      case I_OPT_AUTH_METHOD:
        return i_session->auth_method;
        break;
      case I_OPT_TOKEN_METHOD:
        return i_session->token_method;
        break;
      case I_OPT_EXPIRES_IN:
        return i_session->expires_in;
        break;
      case I_OPT_EXPIRES_AT:
        return (unsigned int)i_session->expires_at;
        break;
      case I_OPT_X5U_FLAGS:
        return i_session->x5u_flags;
        break;
      case I_OPT_OPENID_CONFIG_STRICT:
        return i_session->openid_config_strict;
        break;
      case I_OPT_TOKEN_EXP:
        return i_session->token_exp;
        break;
      case I_OPT_DEVICE_AUTH_EXPIRES_IN:
        return i_session->device_auth_expires_in;
        break;
      case I_OPT_DEVICE_AUTH_INTERVAL:
        return i_session->device_auth_interval;
        break;
      case I_OPT_PUSHED_AUTH_REQ_REQUIRED:
        return i_session->require_pushed_authorization_requests;
        break;
      case I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN:
        return i_session->pushed_authorization_request_expires_in;
        break;
      case I_OPT_USE_DPOP:
        return i_session->use_dpop;
        break;
      case I_OPT_DECRYPT_CODE:
        return i_session->decrypt_code;
        break;
      case I_OPT_DECRYPT_REFRESH_TOKEN:
        return i_session->decrypt_refresh_token;
        break;
      case I_OPT_DECRYPT_ACCESS_TOKEN:
        return i_session->decrypt_access_token;
        break;
      case I_OPT_REMOTE_CERT_FLAG:
        return i_session->remote_cert_flag;
        break;
      case I_OPT_PKCE_METHOD:
        return i_session->pkce_method;
        break;
      case I_OPT_CIBA_MODE:
        return i_session->ciba_mode;
        break;
      case I_OPT_CIBA_LOGIN_HINT_FORMAT:
        return i_session->ciba_login_hint_format;
        break;
      case I_OPT_CIBA_AUTH_REQ_EXPIRES_IN:
        return i_session->ciba_auth_req_expires_in;
        break;
      case I_OPT_CIBA_AUTH_REQ_INTERVAL:
        return i_session->ciba_auth_req_interval;
        break;
      case I_OPT_FRONTCHANNEL_LOGOUT_SESSION_REQUIRED:
        return i_session->frontchannel_logout_session_required;
        break;
      case I_OPT_BACKCHANNEL_LOGOUT_SESSION_REQUIRED:
        return i_session->backchannel_logout_session_required;
        break;
      default:
        return 0;
        break;
    }
  }
  return 0;
}

int i_parse_redirect_to(struct _i_session * i_session) {
  int ret = I_OK, query_parsed = 0;
  struct _u_map map;
  const char * fragment = NULL, * query = NULL, * redirect_to = i_get_str_parameter(i_session, I_OPT_REDIRECT_TO);
  char * query_dup = NULL, * state = NULL;

  if (o_strncmp(redirect_to, i_session->redirect_uri, o_strlen(i_session->redirect_uri)) == 0) {
    query_dup = o_strdup(redirect_to + o_strlen(i_session->redirect_uri));
    
    query = query_dup;
    if (o_strlen(query) && query[0] == '?') {
      query++;
    }

    fragment = o_strnchr(query, o_strlen(query), '#');
    if (fragment) {
      *((char *)fragment) = '\0';
      fragment++;
    }

    if (o_strlen(query) && _i_has_openid_config_parameter_value(i_session, "response_modes_supported", "query")) {
      query_parsed = 1;
      u_map_init(&map);
      if (_i_extract_parameters(i_session, query, &map) == I_OK) {
        if ((ret = _i_parse_redirect_to_parameters(i_session, &map)) == I_OK) {
         if (i_session->id_token != NULL && r_jwks_size(i_session->server_jwks) && i_verify_id_token(i_session) != I_OK) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "i_parse_redirect_to query - Error id_token invalid");
            ret = I_ERROR_SERVER;
          }
        }
      }
      if (u_map_get(&map, "state") != NULL && state == NULL) {
        state = o_strdup(u_map_get(&map, "state"));
      }
      u_map_clean(&map);
    }

    // I assume that if the query string has been parsed, the fragment must not be parsed
    if (!query_parsed && fragment != NULL && _i_has_openid_config_parameter_value(i_session, "response_modes_supported", "fragment")) {
      u_map_init(&map);
      if (_i_extract_parameters(i_session, fragment, &map) == I_OK) {
        if ((ret = _i_parse_redirect_to_parameters(i_session, &map)) == I_OK) {
          if (i_session->id_token != NULL && r_jwks_size(i_session->server_jwks) && i_verify_id_token(i_session) != I_OK) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "i_parse_redirect_to fragment - Error id_token invalid");
            ret = I_ERROR_SERVER;
          }
        }
      }
      state = o_strdup(u_map_get(&map, "state"));
      u_map_clean(&map);
    }
    o_free(query_dup);

    if (ret == I_OK) {
      if (i_get_str_parameter(i_session, I_OPT_STATE) != NULL) {
        if (0 != o_strcmp(i_get_str_parameter(i_session, I_OPT_STATE), state)) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "i_parse_redirect_to query - Error state invalid %s %s", state, i_get_str_parameter(i_session, I_OPT_STATE));
          ret = I_ERROR_SERVER;
        }
      }

      if (i_get_response_type(i_session) & I_RESPONSE_TYPE_CODE && i_get_str_parameter(i_session, I_OPT_ERROR) == NULL && i_get_str_parameter(i_session, I_OPT_CODE) == NULL) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "i_parse_redirect_to query - Error expected code");
        ret = I_ERROR_SERVER;
      }

      if (i_get_response_type(i_session) & I_RESPONSE_TYPE_TOKEN && i_get_str_parameter(i_session, I_OPT_ERROR) == NULL && i_get_str_parameter(i_session, I_OPT_ACCESS_TOKEN) == NULL) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "i_parse_redirect_to query - Error expected access_token");
        ret = I_ERROR_SERVER;
      }

      if (i_get_response_type(i_session) & I_RESPONSE_TYPE_ID_TOKEN && i_get_str_parameter(i_session, I_OPT_ERROR) == NULL && i_get_str_parameter(i_session, I_OPT_ID_TOKEN) == NULL) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "i_parse_redirect_to query - Error expected id_token");
        ret = I_ERROR_SERVER;
      }
    }
    o_free(state);
  }
  return ret;
}

const char * i_get_str_parameter(struct _i_session * i_session, i_option option) {
  const char * result = NULL;
  if (i_session != NULL) {
    switch (option) {
      case I_OPT_SCOPE:
      case I_OPT_SCOPE_APPEND:
        result = (const char *)i_session->scope;
        break;
      case I_OPT_STATE:
        result = (const char *)i_session->state;
        break;
      case I_OPT_NONCE:
        result = (const char *)i_session->nonce;
        break;
      case I_OPT_REDIRECT_URI:
        result = (const char *)i_session->redirect_uri;
        break;
      case I_OPT_REDIRECT_TO:
        result = (const char *)i_session->redirect_to;
        break;
      case I_OPT_CLIENT_ID:
        result = (const char *)i_session->client_id;
        break;
      case I_OPT_CLIENT_SECRET:
        result = (const char *)i_session->client_secret;
        break;
      case I_OPT_AUTH_ENDPOINT:
        result = (const char *)i_session->authorization_endpoint;
        break;
      case I_OPT_TOKEN_ENDPOINT:
        result = (const char *)i_session->token_endpoint;
        break;
      case I_OPT_OPENID_CONFIG_ENDPOINT:
        result = (const char *)i_session->openid_config_endpoint;
        break;
      case I_OPT_USERINFO_ENDPOINT:
        result = (const char *)i_session->userinfo_endpoint;
        break;
      case I_OPT_ERROR:
        result = (const char *)i_session->error;
        break;
      case I_OPT_ERROR_DESCRIPTION:
        result = (const char *)i_session->error_description;
        break;
      case I_OPT_ERROR_URI:
        result = (const char *)i_session->error_uri;
        break;
      case I_OPT_CODE:
        result = (const char *)i_session->code;
        break;
      case I_OPT_REFRESH_TOKEN:
        result = (const char *)i_session->refresh_token;
        break;
      case I_OPT_ACCESS_TOKEN:
        result = (const char *)i_session->access_token;
        break;
      case I_OPT_ID_TOKEN:
        result = (const char *)i_session->id_token;
        break;
      case I_OPT_TOKEN_TYPE:
        result = (const char *)i_session->token_type;
        break;
      case I_OPT_USERNAME:
        result = (const char *)i_session->username;
        break;
      case I_OPT_USER_PASSWORD:
        result = (const char *)i_session->user_password;
        break;
      case I_OPT_ISSUER:
        result = (const char *)i_session->issuer;
        break;
      case I_OPT_USERINFO:
        result = (const char *)i_session->userinfo;
        break;
      case I_OPT_SERVER_KID:
        result = (const char *)i_session->server_kid;
        break;
      case I_OPT_SERVER_ENC_ALG:
        result = r_jwa_alg_to_str(i_session->server_enc_alg);
        break;
      case I_OPT_SERVER_ENC:
        result = r_jwa_enc_to_str(i_session->server_enc);
        break;
      case I_OPT_CLIENT_KID:
        result = (const char *)i_session->client_kid;
        break;
      case I_OPT_CLIENT_SIGN_ALG:
        result = r_jwa_alg_to_str(i_session->client_sign_alg);
        break;
      case I_OPT_CLIENT_ENC_ALG:
        result = r_jwa_alg_to_str(i_session->client_enc_alg);
        break;
      case I_OPT_CLIENT_ENC:
        result = r_jwa_enc_to_str(i_session->client_enc);
        break;
      case I_OPT_TOKEN_JTI:
        result = (const char *)i_session->token_jti;
        break;
      case I_OPT_TOKEN_TARGET:
        result = (const char *)i_session->token_target;
        break;
      case I_OPT_TOKEN_TARGET_TYPE_HINT:
        result = (const char *)i_session->token_target_type_hint;
        break;
      case I_OPT_REVOCATION_ENDPOINT:
        result = (const char *)i_session->revocation_endpoint;
        break;
      case I_OPT_INTROSPECTION_ENDPOINT:
        result = (const char *)i_session->introspection_endpoint;
        break;
      case I_OPT_REGISTRATION_ENDPOINT:
        result = (const char *)i_session->registration_endpoint;
        break;
      case I_OPT_DEVICE_AUTHORIZATION_ENDPOINT:
        result = (const char *)i_session->device_authorization_endpoint;
        break;
      case I_OPT_DEVICE_AUTH_CODE:
        result = (const char *)i_session->device_auth_code;
        break;
      case I_OPT_DEVICE_AUTH_USER_CODE:
        result = (const char *)i_session->device_auth_user_code;
        break;
      case I_OPT_DEVICE_AUTH_VERIFICATION_URI:
        result = (const char *)i_session->device_auth_verification_uri;
        break;
      case I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE:
        result = (const char *)i_session->device_auth_verification_uri_complete;
        break;
      case I_OPT_END_SESSION_ENDPOINT:
        result = (const char *)i_session->end_session_endpoint;
        break;
      case I_OPT_CHECK_SESSION_IRAME:
        result = (const char *)i_session->check_session_iframe;
        break;
      case I_OPT_PUSHED_AUTH_REQ_ENDPOINT:
        result = (const char *)i_session->pushed_authorization_request_endpoint;
        break;
      case I_OPT_PUSHED_AUTH_REQ_URI:
        result = (const char *)i_session->pushed_authorization_request_uri;
        break;
      case I_OPT_DPOP_KID:
        result = (const char *)i_session->dpop_kid;
        break;
      case I_OPT_DPOP_SIGN_ALG:
        result = r_jwa_alg_to_str(i_session->dpop_sign_alg);
        break;
      case I_OPT_TLS_KEY_FILE:
        result = (const char *)i_session->key_file;
        break;
      case I_OPT_TLS_CERT_FILE:
        result = (const char *)i_session->cert_file;
        break;
      case I_OPT_PKCE_CODE_VERIFIER:
        result = (const char *)i_session->pkce_code_verifier;
        break;
      case I_OPT_RESOURCE_INDICATOR:
        result = (const char *)i_session->resource_indicator;
        break;
      case I_OPT_ACCESS_TOKEN_SIGNING_ALG:
        result = r_jwa_alg_to_str(i_session->access_token_signing_alg);
        break;
      case I_OPT_ACCESS_TOKEN_ENCRYPTION_ALG:
        result = r_jwa_alg_to_str(i_session->access_token_encryption_alg);
        break;
      case I_OPT_ACCESS_TOKEN_ENCRYPTION_ENC:
        result = r_jwa_enc_to_str(i_session->access_token_encryption_enc);
        break;
      case I_OPT_ID_TOKEN_SIGNING_ALG:
        result = r_jwa_alg_to_str(i_session->id_token_signing_alg);
        break;
      case I_OPT_ID_TOKEN_ENCRYPTION_ALG:
        result = r_jwa_alg_to_str(i_session->id_token_encryption_alg);
        break;
      case I_OPT_ID_TOKEN_ENCRYPTION_ENC:
        result = r_jwa_enc_to_str(i_session->id_token_encryption_enc);
        break;
      case I_OPT_USERINFO_SIGNING_ALG:
        result = r_jwa_alg_to_str(i_session->userinfo_signing_alg);
        break;
      case I_OPT_USERINFO_ENCRYPTION_ALG:
        result = r_jwa_alg_to_str(i_session->userinfo_encryption_alg);
        break;
      case I_OPT_USERINFO_ENCRYPTION_ENC:
        result = r_jwa_enc_to_str(i_session->userinfo_encryption_enc);
        break;
      case I_OPT_REQUEST_OBJECT_SIGNING_ALG:
        result = r_jwa_alg_to_str(i_session->request_object_signing_alg);
        break;
      case I_OPT_REQUEST_OBJECT_ENCRYPTION_ALG:
        result = r_jwa_alg_to_str(i_session->request_object_encryption_alg);
        break;
      case I_OPT_REQUEST_OBJECT_ENCRYPTION_ENC:
        result = r_jwa_enc_to_str(i_session->request_object_encryption_enc);
        break;
      case I_OPT_TOKEN_ENDPOINT_SIGNING_ALG:
        result = r_jwa_alg_to_str(i_session->token_endpoint_signing_alg);
        break;
      case I_OPT_TOKEN_ENDPOINT_ENCRYPTION_ALG:
        result = r_jwa_alg_to_str(i_session->token_endpoint_encryption_alg);
        break;
      case I_OPT_TOKEN_ENDPOINT_ENCRYPTION_ENC:
        result = r_jwa_enc_to_str(i_session->token_endpoint_encryption_enc);
        break;
      case I_OPT_CIBA_REQUEST_SIGNING_ALG:
        result = r_jwa_alg_to_str(i_session->ciba_request_signing_alg);
        break;
      case I_OPT_CIBA_REQUEST_ENCRYPTION_ALG:
        result = r_jwa_alg_to_str(i_session->ciba_request_encryption_alg);
        break;
      case I_OPT_CIBA_REQUEST_ENCRYPTION_ENC:
        result = r_jwa_enc_to_str(i_session->ciba_request_encryption_enc);
        break;
      case I_OPT_AUTH_RESPONSE_SIGNING_ALG:
        result = r_jwa_alg_to_str(i_session->auth_response_signing_alg);
        break;
      case I_OPT_AUTH_RESPONSE_ENCRYPTION_ALG:
        result = r_jwa_alg_to_str(i_session->auth_response_encryption_alg);
        break;
      case I_OPT_AUTH_RESPONSE_ENCRYPTION_ENC:
        result = r_jwa_enc_to_str(i_session->auth_response_encryption_enc);
        break;
      case I_OPT_CIBA_ENDPOINT:
        result = (const char *)i_session->ciba_endpoint;
        break;
      case I_OPT_CIBA_USER_CODE:
        result = (const char *)i_session->ciba_user_code;
        break;
      case I_OPT_CIBA_LOGIN_HINT:
        result = (const char *)i_session->ciba_login_hint;
        break;
      case I_OPT_CIBA_LOGIN_HINT_KID:
        result = (const char *)i_session->ciba_login_hint_kid;
        break;
      case I_OPT_CIBA_BINDING_MESSAGE:
        result = (const char *)i_session->ciba_binding_message;
        break;
      case I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN:
        result = (const char *)i_session->ciba_client_notification_token;
        break;
      case I_OPT_CIBA_AUTH_REQ_ID:
        result = (const char *)i_session->ciba_auth_req_id;
        break;
      case I_OPT_CIBA_CLIENT_NOTIFICATION_ENDPOINT:
        result = (const char *)i_session->ciba_client_notification_endpoint;
        break;
      case I_OPT_FRONTCHANNEL_LOGOUT_URI:
        result = (const char *)i_session->frontchannel_logout_uri;
        break;
      case I_OPT_BACKCHANNEL_LOGOUT_URI:
        result = (const char *)i_session->backchannel_logout_uri;
        break;
      case I_OPT_POST_LOGOUT_REDIRECT_URI:
        result = (const char *)i_session->post_logout_redirect_uri;
        break;
      case I_OPT_ID_TOKEN_SID:
        result = (const char *)i_session->id_token_sid;
        break;
      default:
        break;
    }
  }
  return result;
}

const char * i_get_additional_parameter(struct _i_session * i_session, const char * s_key) {
  if (i_session != NULL) {
    return u_map_get(&i_session->additional_parameters, s_key);
  } else {
    return NULL;
  }
}

const char * i_get_additional_response(struct _i_session * i_session, const char * s_key) {
  if (i_session != NULL) {
    return u_map_get(&i_session->additional_response, s_key);
  } else {
    return NULL;
  }
}

json_t * i_get_server_configuration(struct _i_session * i_session) {
  if (i_session != NULL) {
    return json_deep_copy(i_session->openid_config);
  } else {
    return NULL;
  }
}

json_t * i_get_server_jwks(struct _i_session * i_session) {
  if (i_session != NULL) {
    return r_jwks_export_to_json_t(i_session->server_jwks);
  } else {
    return NULL;
  }
}

int i_set_server_jwks(struct _i_session * i_session, json_t * j_jwks) {
  int ret;
  if (i_session != NULL) {
    if (r_jwks_empty(i_session->server_jwks) == RHN_OK && r_jwks_import_from_json_t(i_session->server_jwks, j_jwks) == RHN_OK) {
      ret = I_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_set_server_jwks - Error importing jwks");
      ret = I_ERROR;
    }
  } else {
    ret = I_ERROR_PARAM;
  }
  return ret;
}

json_t * i_get_client_jwks(struct _i_session * i_session) {
  if (i_session != NULL) {
    return r_jwks_export_to_json_t(i_session->client_jwks);
  } else {
    return NULL;
  }
}

int i_set_client_jwks(struct _i_session * i_session, json_t * j_jwks) {
  int ret;
  if (i_session != NULL) {
    if (r_jwks_empty(i_session->client_jwks) == RHN_OK && r_jwks_import_from_json_t(i_session->client_jwks, j_jwks) == RHN_OK) {
      ret = I_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_set_client_jwks - Error importing jwks");
      ret = I_ERROR;
    }
  } else {
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_build_auth_url_get(struct _i_session * i_session) {
  int ret;
  char * url = NULL, * escaped = NULL, * tmp = NULL, * jwt = NULL;
  const char ** keys = NULL;
  unsigned int i;
  unsigned char code_challenge[32] = {0}, code_challenge_encoded[64] = {0};
  size_t code_challenge_len = 32, code_challenge_encoded_len = 0;
  gnutls_datum_t hash_data;

  if (i_session != NULL && i_session->client_id != NULL) {
    if (i_session->pushed_authorization_request_uri != NULL) {
      escaped = ulfius_url_encode(i_session->pushed_authorization_request_uri);
      url = msprintf("%s?request_uri=%s", i_session->authorization_endpoint, escaped);
      o_free(escaped);

      escaped = ulfius_url_encode(i_session->client_id);
      url = mstrcatf(url, "&client_id=%s", escaped);
      o_free(escaped);

      ret = i_set_str_parameter(i_session, I_OPT_REDIRECT_TO, url);
      o_free(url);
    } else if (i_session->response_type != I_RESPONSE_TYPE_NONE &&
               i_session->response_type != I_RESPONSE_TYPE_PASSWORD &&
               i_session->response_type != I_RESPONSE_TYPE_CLIENT_CREDENTIALS &&
               i_session->response_type != I_RESPONSE_TYPE_REFRESH_TOKEN &&
               i_session->response_type != I_RESPONSE_TYPE_DEVICE_CODE &&
               i_session->redirect_uri != NULL &&
               i_session->authorization_endpoint != NULL &&
               _i_check_strict_parameters(i_session) &&
               (_i_has_openid_config_parameter_value(i_session, "grant_types_supported", "implicit") || _i_has_openid_config_parameter_value(i_session, "grant_types_supported", "authorization_code")) &&
               i_session->auth_method & I_AUTH_METHOD_GET) {
      if (i_session->auth_method & (I_AUTH_METHOD_JWT_SIGN_SECRET|I_AUTH_METHOD_JWT_SIGN_PRIVKEY|I_AUTH_METHOD_JWT_ENCRYPT_SECRET|I_AUTH_METHOD_JWT_ENCRYPT_PUBKEY)) {
        if ((jwt = _i_generate_auth_jwt(i_session)) != NULL) {
          url = msprintf("%s?request=%s", i_session->authorization_endpoint, jwt);
          o_free(jwt);
          ret = i_set_str_parameter(i_session, I_OPT_REDIRECT_TO, url);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_build_auth_url_get - Error _i_generate_auth_jwt");
          ret = I_ERROR;
        }
      } else {
        escaped = ulfius_url_encode(i_session->redirect_uri);
        url = msprintf("%s?redirect_uri=%s", i_session->authorization_endpoint, escaped);
        o_free(escaped);

        escaped = ulfius_url_encode(_i_get_response_type(i_session->response_type));
        url = mstrcatf(url, "&response_type=%s", escaped);
        o_free(escaped);

        escaped = ulfius_url_encode(i_session->client_id);
        url = mstrcatf(url, "&client_id=%s", escaped);
        o_free(escaped);

        if (i_session->state != NULL) {
          escaped = ulfius_url_encode(i_session->state);
          url = mstrcatf(url, "&state=%s", escaped);
          o_free(escaped);
        }

        if (i_session->scope != NULL) {
          escaped = ulfius_url_encode(i_session->scope);
          url = mstrcatf(url, "&scope=%s", escaped);
          o_free(escaped);
        }

        if (i_session->nonce != NULL) {
          escaped = ulfius_url_encode(i_session->nonce);
          url = mstrcatf(url, "&nonce=%s", escaped);
          o_free(escaped);
        }

        if (_i_has_claims(i_session)) {
          tmp = json_dumps(i_session->j_claims, JSON_COMPACT);
          escaped = ulfius_url_encode(tmp);
          url = mstrcatf(url, "&claims=%s", escaped);
          o_free(escaped);
          o_free(tmp);
        }

        if (i_session->resource_indicator != NULL) {
          escaped = ulfius_url_encode(i_session->resource_indicator);
          url = mstrcatf(url, "&resource=%s", escaped);
          o_free(escaped);
        }

        if (i_session->pkce_method != I_PKCE_NONE) {
          if (i_session->pkce_method == I_PKCE_METHOD_PLAIN) {
            escaped = ulfius_url_encode(i_session->pkce_code_verifier);
            url = mstrcatf(url, "&code_challenge_method=plain&code_challenge=%s", escaped);
            o_free(escaped);
          } else if (i_session->pkce_method == I_PKCE_METHOD_S256) {
            hash_data.data = (unsigned char *)i_session->pkce_code_verifier;
            hash_data.size = o_strlen(i_session->pkce_code_verifier);
            if (gnutls_fingerprint(GNUTLS_DIG_SHA256, &hash_data, code_challenge, &code_challenge_len) == GNUTLS_E_SUCCESS) {
              if (o_base64url_encode(code_challenge, code_challenge_len, code_challenge_encoded, &code_challenge_encoded_len)) {
                code_challenge_encoded[code_challenge_encoded_len] = '\0';
                url = mstrcatf(url, "&code_challenge_method=S256&code_challenge=%s", code_challenge_encoded);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "i_build_auth_url_get - Error o_base64url_encode");
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_build_auth_url_get - Error gnutls_fingerprint");
            }
          }
        }

        if (json_array_size(i_session->j_authorization_details)) {
          tmp = json_dumps(i_session->j_authorization_details, JSON_COMPACT);
          escaped = ulfius_url_encode(tmp);
          url = mstrcatf(url, "&authorization_details=%s", escaped);
          o_free(escaped);
          o_free(tmp);
        }

        keys = u_map_enum_keys(&i_session->additional_parameters);

        for (i=0; keys[i] != NULL; i++) {
          if (o_strlen(u_map_get(&i_session->additional_parameters, keys[i]))) {
            escaped = ulfius_url_encode(u_map_get(&i_session->additional_parameters, keys[i]));
            url = mstrcatf(url, "&%s=%s", keys[i], escaped);
            o_free(escaped);
          } else {
            url = mstrcatf(url, "&%s", keys[i]);
          }
        }
        ret = i_set_str_parameter(i_session, I_OPT_REDIRECT_TO, url);
        o_free(url);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_build_auth_url_get - Error input parameter");
      if (i_session->response_type == I_RESPONSE_TYPE_NONE ||
          i_session->response_type == I_RESPONSE_TYPE_PASSWORD ||
          i_session->response_type == I_RESPONSE_TYPE_CLIENT_CREDENTIALS ||
          i_session->response_type == I_RESPONSE_TYPE_REFRESH_TOKEN ||
          i_session->response_type == I_RESPONSE_TYPE_DEVICE_CODE) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "i_build_auth_url_get - response_type invalid");
      }
      if (i_session->redirect_uri == NULL) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "i_build_auth_url_get - redirect_uri invalid");
      }
      if (i_session->authorization_endpoint == NULL) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "i_build_auth_url_get - authorization_endpoint invalid");
      }
      if (!_i_check_strict_parameters(i_session)) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "i_build_auth_url_get - strict parameters invalid");
      }
      if (!_i_has_openid_config_parameter_value(i_session, "grant_types_supported", "implicit") || !_i_has_openid_config_parameter_value(i_session, "grant_types_supported", "authorization_code")) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "i_build_auth_url_get - grant_types not supported");
      }
      if (!(i_session->auth_method & I_AUTH_METHOD_GET)) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "i_build_auth_url_get - auth method invalid");
      }
      ret = I_ERROR_PARAM;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "i_build_auth_url_get - Error input parameter");
    if (i_session == NULL) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "i_build_auth_url_get - i_session NULL");
    }
    if (i_session->client_id == NULL) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "i_build_auth_url_get - client_id NULL");
    }
    ret = I_ERROR_PARAM;
  }

  return ret;
}

int i_run_auth_request(struct _i_session * i_session) {
  int ret = I_OK;
  struct _u_request request;
  struct _u_response response;
  const char ** keys = NULL;
  unsigned int i;
  char * jwt = NULL;

  if (i_session != NULL &&
      i_session->response_type != I_RESPONSE_TYPE_NONE &&
      i_session->response_type != I_RESPONSE_TYPE_PASSWORD &&
      i_session->response_type != I_RESPONSE_TYPE_CLIENT_CREDENTIALS &&
      i_session->response_type != I_RESPONSE_TYPE_REFRESH_TOKEN &&
      i_session->response_type != I_RESPONSE_TYPE_DEVICE_CODE &&
      i_session->redirect_uri != NULL &&
      i_session->client_id != NULL &&
      i_session->authorization_endpoint != NULL &&
      _i_check_strict_parameters(i_session) &&
      (_i_has_openid_config_parameter_value(i_session, "grant_types_supported", "implicit") || _i_has_openid_config_parameter_value(i_session, "grant_types_supported", "authorization_code"))) {
    if (_i_init_request(i_session, &request) != U_OK || ulfius_init_response(&response) != U_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_run_auth_request - Error initializing request or response");
      ret = I_ERROR;
    } else {
      ulfius_set_request_properties(&request, U_OPT_HEADER_PARAMETER, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR, U_OPT_NONE);
      if (i_session->auth_method & I_AUTH_METHOD_GET) {
        if (i_session->auth_method & (I_AUTH_METHOD_JWT_SIGN_SECRET|I_AUTH_METHOD_JWT_SIGN_PRIVKEY|I_AUTH_METHOD_JWT_ENCRYPT_SECRET|I_AUTH_METHOD_JWT_ENCRYPT_PUBKEY)) {
          if ((jwt = _i_generate_auth_jwt(i_session)) != NULL) {
            if (ulfius_set_request_properties(&request, U_OPT_HTTP_VERB, "GET",
                                                        U_OPT_HTTP_URL, i_session->authorization_endpoint,
                                                        U_OPT_URL_PARAMETER, "request", jwt,
                                                        U_OPT_NONE) != U_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_run_auth_request - Error setting request properties");
              ret = I_ERROR;
            }
            o_free(jwt);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_run_auth_request - Error generating jwt");
            ret = I_ERROR_PARAM;
          }
        } else if ((ret = i_build_auth_url_get(i_session)) == I_OK) {
          if (ulfius_set_request_properties(&request, U_OPT_HTTP_VERB, "GET",
                                                      U_OPT_HTTP_URL, i_get_str_parameter(i_session, I_OPT_REDIRECT_TO),
                                                      U_OPT_NONE) != U_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_run_auth_request - Error setting request properties");
            ret = I_ERROR;
          }
        }
      } else if (i_session->auth_method & I_AUTH_METHOD_POST) {
        if (ulfius_set_request_properties(&request, U_OPT_HTTP_VERB, "POST",
                                                    U_OPT_HTTP_URL, i_session->authorization_endpoint,
                                                    U_OPT_NONE) != U_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_run_auth_request - Error setting request properties");
          ret = I_ERROR;
        }
        if (i_session->auth_method & (I_AUTH_METHOD_JWT_SIGN_SECRET|I_AUTH_METHOD_JWT_SIGN_PRIVKEY|I_AUTH_METHOD_JWT_ENCRYPT_SECRET|I_AUTH_METHOD_JWT_ENCRYPT_PUBKEY)) {
          if ((jwt = _i_generate_auth_jwt(i_session)) != NULL) {
            ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "request", jwt, U_OPT_NONE);
            o_free(jwt);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_run_auth_request - Error generating jwt");
            ret = I_ERROR_PARAM;
          }
        } else {
          ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "redirect_uri", i_session->redirect_uri,
                                                  U_OPT_POST_BODY_PARAMETER, "response_type", _i_get_response_type(i_session->response_type),
                                                  U_OPT_POST_BODY_PARAMETER, "client_id", i_session->client_id,
                                                  U_OPT_NONE);
          if (i_session->state != NULL) {
            ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "state", i_session->state, U_OPT_NONE);
          }
          if (i_session->scope != NULL) {
            ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "scope", i_session->scope, U_OPT_NONE);
          }
          if (i_session->nonce != NULL) {
            ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "nonce", i_session->nonce, U_OPT_NONE);
          }

          keys = u_map_enum_keys(&i_session->additional_parameters);

          for (i=0; keys[i] != NULL; i++) {
            ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, keys[i], u_map_get(&i_session->additional_parameters, keys[i]), U_OPT_NONE);
          }
        }
      } else {
        // Unsupported auth_method
        y_log_message(Y_LOG_LEVEL_DEBUG, "i_run_auth_request - Unsupported auth_method");
        ret = I_ERROR_PARAM;
      }

      if (ret == I_OK) {
        if (ulfius_send_http_request(&request, &response) == U_OK) {
          if (response.status == 302 && o_strlen(u_map_get_case(response.map_header, "Location"))) {
            if (i_set_str_parameter(i_session, I_OPT_REDIRECT_TO, u_map_get_case(response.map_header, "Location")) == I_OK) {
              ret = i_parse_redirect_to(i_session);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_run_auth_request - Error setting redirect url");
            }
          } else if (response.status == 400) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_run_auth_request - Server response 400");
            y_log_message(Y_LOG_LEVEL_DEBUG, "%.*s", response.binary_body_length, response.binary_body);
            ret = I_ERROR_PARAM;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_run_auth_request - Error http request: %d", response.status);
            ret = I_ERROR;
          }
        } else {
          ret = I_ERROR;
        }
      }
      ulfius_clean_request(&request);
      ulfius_clean_response(&response);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "i_run_auth_request - Invalid input parameters");
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_parse_token_response(struct _i_session * i_session, int http_status, json_t * j_response) {
  int ret = I_OK, res;
  const char * key = NULL;
  json_t * j_element = NULL;
  char * value, * payload_dup = NULL;
  jwt_t * jwt = NULL;

  if (i_session != NULL && json_is_object(j_response)) {
    if (http_status == 200) {
      if (json_string_length(json_object_get(j_response, "access_token")) &&
          json_string_length(json_object_get(j_response, "token_type"))) {
        if (i_session->decrypt_access_token) {
          if ((payload_dup = _i_decrypt_jwe_token(i_session, json_string_value(json_object_get(j_response, "access_token")))) != NULL) {
            res = i_set_str_parameter(i_session, I_OPT_ACCESS_TOKEN, payload_dup);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_parse_token_response - Error _i_decrypt_jwe_token access_token");
            res = I_ERROR;
          }
          o_free(payload_dup);
          payload_dup = NULL;
        } else {
          res = i_set_str_parameter(i_session, I_OPT_ACCESS_TOKEN, json_string_value(json_object_get(j_response, "access_token")));
        }
        if (res == I_OK && i_set_str_parameter(i_session, I_OPT_TOKEN_TYPE, json_string_value(json_object_get(j_response, "token_type"))) == I_OK) {
          // Validate access token signature and decrypt if necessary if it's a JWT
          if (r_jwt_token_type(i_get_str_parameter(i_session, I_OPT_ACCESS_TOKEN)) != R_JWT_TYPE_NONE &&
              (jwt = r_jwt_quick_parse(i_get_str_parameter(i_session, I_OPT_ACCESS_TOKEN), R_PARSE_NONE, i_session->x5u_flags)) != NULL) {
            if (_i_verify_jwt_sig_enc(i_session, i_get_str_parameter(i_session, I_OPT_ACCESS_TOKEN), I_TOKEN_TYPE_ACCESS_TOKEN, jwt) != I_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_parse_token_response - Error _i_verify_jwt_sig_enc");
              ret = I_ERROR;
            } else {
              json_decref(i_session->access_token_payload);
              i_session->access_token_payload = r_jwt_get_full_claims_json_t(jwt);
            }
          }
          r_jwt_free(jwt);
          if (json_integer_value(json_object_get(j_response, "expires_in")) && i_set_int_parameter(i_session, I_OPT_EXPIRES_IN, json_integer_value(json_object_get(j_response, "expires_in"))) != I_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_parse_token_response - Error setting expires_in");
            ret = I_ERROR;
          }
          if (json_string_length(json_object_get(j_response, "refresh_token"))) {
            if (i_session->decrypt_refresh_token) {
              if ((payload_dup = _i_decrypt_jwe_token(i_session, json_string_value(json_object_get(j_response, "refresh_token")))) != NULL) {
                res = i_set_str_parameter(i_session, I_OPT_REFRESH_TOKEN, payload_dup);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "i_parse_token_response - Error _i_decrypt_jwe_token refresh_token");
                res = I_ERROR;
              }
              o_free(payload_dup);
              payload_dup = NULL;
            } else {
              res = i_set_str_parameter(i_session, I_OPT_REFRESH_TOKEN, json_string_value(json_object_get(j_response, "refresh_token")));
            }
            if (res != I_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_parse_token_response - Error setting refresh_token");
              ret = I_ERROR;
            }
          }
          if (json_string_length(json_object_get(j_response, "id_token"))) {
            if (i_set_str_parameter(i_session, I_OPT_ID_TOKEN, json_string_value(json_object_get(j_response, "id_token"))) != I_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_parse_token_response - Error setting id_token");
              ret = I_ERROR;
            }
            if (r_jwks_size(i_session->server_jwks) && i_verify_id_token(i_session) != I_OK) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "i_parse_token_response - Error id_token invalid");
              ret = I_ERROR_SERVER;
            }
          }
          json_object_foreach(j_response, key, j_element) {
            if (0 != o_strcmp("access_token", key) &&
                0 != o_strcmp("token_type", key) &&
                0 != o_strcmp("expires_in", key) &&
                0 != o_strcmp("refresh_token", key) &&
                0 != o_strcmp("id_token", key)) {
              if (json_is_string(j_element)) {
                if (i_set_additional_response(i_session, key, json_string_value(j_element)) != I_OK) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "i_parse_token_response - Error i_set_additional_response %s - %s", key, json_string_value(j_element));
                  ret = I_ERROR;
                }
              } else {
                value = json_dumps(j_element, JSON_ENCODE_ANY);
                if (i_set_additional_response(i_session, key, value) != I_OK) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "i_parse_token_response - Error i_set_additional_response %s - %s", key, json_string_value(j_element));
                  ret = I_ERROR;
                }
                o_free(value);
              }
            }
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_parse_token_response - Error setting response parameters (1)");
          ret = I_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_parse_token_response - required response parameters missing (1)");
        ret = I_ERROR_PARAM;
      }
    } else if (http_status == 400) {
      if (_i_parse_error_response(i_session, j_response) != I_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_parse_token_response - _i_parse_error_response (1)");
        ret = I_ERROR;
      }
    } else if (http_status == 401 || http_status == 403) {
      if (_i_parse_error_response(i_session, j_response) != I_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_parse_token_response - _i_parse_error_response (2)");
        ret = I_ERROR;
      }
    }
  } else {
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_run_token_request(struct _i_session * i_session) {
  int ret = I_OK, res;
  struct _u_request request;
  struct _u_response response;
  json_t * j_response;
  char * dpop_token;
  jwa_alg sign_alg = R_JWA_ALG_UNKNOWN, enc_alg = R_JWA_ALG_UNKNOWN;
  jwa_enc enc = R_JWA_ENC_UNKNOWN;

  if (i_session != NULL && i_session->token_endpoint != NULL) {
    if (i_session->client_sign_alg != R_JWA_ALG_UNKNOWN) {
      sign_alg = i_session->client_sign_alg;
    } else if (i_session->token_endpoint_signing_alg != R_JWA_ALG_UNKNOWN) {
      sign_alg = i_session->token_endpoint_signing_alg;
    }
    if (i_session->client_enc_alg != R_JWA_ALG_UNKNOWN) {
      enc_alg = i_session->client_enc_alg;
    } else if (i_session->token_endpoint_encryption_alg != R_JWA_ALG_UNKNOWN) {
      enc_alg = i_session->token_endpoint_encryption_alg;
    }
    if (i_session->client_enc != R_JWA_ENC_UNKNOWN) {
      enc = i_session->client_enc;
    } else if (i_session->token_endpoint_encryption_enc != R_JWA_ENC_UNKNOWN) {
      enc = i_session->token_endpoint_encryption_enc;
    }
    if (i_session->response_type & I_RESPONSE_TYPE_CODE) {
      if (i_session->redirect_uri != NULL &&
          (i_session->client_id != NULL || i_session->token_method & I_TOKEN_AUTH_METHOD_TLS_CERTIFICATE) &&
          i_session->code != NULL &&
          _i_check_strict_parameters(i_session) &&
          _i_has_openid_config_parameter_value(i_session, "grant_types_supported", "authorization_code")) {
        _i_init_request(i_session, &request);
        ulfius_init_response(&response);
        if (ulfius_set_request_properties(&request, U_OPT_HTTP_VERB, "POST",
                                                    U_OPT_HTTP_URL, _i_get_endpoint(i_session, "token"),
                                                    U_OPT_HEADER_PARAMETER, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR,
                                                    U_OPT_HEADER_PARAMETER, "Accept", "application/json",
                                                    U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                    U_OPT_POST_BODY_PARAMETER, "code", i_session->code,
                                                    U_OPT_POST_BODY_PARAMETER, "redirect_uri", i_session->redirect_uri,
                                                    U_OPT_POST_BODY_PARAMETER, "client_id", i_session->client_id,
                                                    U_OPT_NONE) != U_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request code - Error setting request properties");
          ret = I_ERROR;
        }
        if (i_session->scope != NULL) {
          if (ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "scope", i_session->scope, U_OPT_NONE) != U_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request code - Error setting scope property");
            ret = I_ERROR;
          }
        }
        if (i_session->pkce_method != I_PKCE_NONE && o_strlen(i_session->pkce_code_verifier)) {
          ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "code_verifier", i_session->pkce_code_verifier);
        }
        if (i_session->use_dpop) {
          dpop_token = i_generate_dpop_token(i_session, "POST", _i_get_endpoint(i_session, "token"), 0, 0);
          if (ulfius_set_request_properties(&request, U_OPT_HEADER_PARAMETER, "DPoP", dpop_token, U_OPT_NONE) != U_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request code - Error setting DPoP header");
            ret = I_ERROR;
          }
          o_free(dpop_token);
        }
        if ((res = _i_add_token_authentication(i_session, i_session->token_endpoint, &request, sign_alg, enc_alg, enc)) == I_OK) {
          if (ulfius_send_http_request(&request, &response) == U_OK) {
            if (response.status == 200 || response.status == 400) {
              j_response = ulfius_get_json_body_response(&response, NULL);
              if (j_response != NULL) {
                if (i_parse_token_response(i_session, response.status, j_response) == I_OK) {
                  ret = response.status == 200?I_OK:I_ERROR_PARAM;
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request code - Error i_parse_token_response (1)");
                  ret = I_ERROR_PARAM;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request code - Error parsing JSON response %.*s", response.binary_body_length, response.binary_body);
                ret = I_ERROR;
              }
              json_decref(j_response);
            } else if (response.status == 401 || response.status == 403) {
              j_response = ulfius_get_json_body_response(&response, NULL);
              ret = I_ERROR_UNAUTHORIZED;
              if (i_parse_token_response(i_session, response.status, j_response) == I_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request code - Unauthorized");
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request code - Error i_parse_token_response (2)");
              }
              json_decref(j_response);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request code - Invalid response status: %d", response.status);
              y_log_message(Y_LOG_LEVEL_DEBUG, "response body %.*s", response.binary_body_length, response.binary_body);
              ret = I_ERROR;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request code - Error sending token request");
            ret = I_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request code - Error _i_add_token_authentication");
          ret = res;
        }
        ulfius_clean_request(&request);
        ulfius_clean_response(&response);
      } else {
        y_log_message(Y_LOG_LEVEL_DEBUG, "i_run_token_request code - Error input parameters");
        if (i_session->redirect_uri == NULL) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "i_run_token_request code - redirect_uri NULL");
        }
        if (i_session->client_id == NULL && !(i_session->token_method & I_TOKEN_AUTH_METHOD_TLS_CERTIFICATE)) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "i_run_token_request code - client_id NULL");
        }
        if (i_session->code == NULL) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "i_run_token_request code - code NULL");
        }
        ret = I_ERROR_PARAM;
      }
    } else {
      switch (i_session->response_type) {
        case I_RESPONSE_TYPE_PASSWORD:
          if (i_session->username != NULL && i_session->user_password != NULL) {
            _i_init_request(i_session, &request);
            ulfius_init_response(&response);
            if (ulfius_set_request_properties(&request, U_OPT_HTTP_VERB, "POST",
                                                        U_OPT_HTTP_URL, _i_get_endpoint(i_session, "token"),
                                                        U_OPT_HEADER_PARAMETER, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR,
                                                        U_OPT_HEADER_PARAMETER, "Accept", "application/json",
                                                        U_OPT_POST_BODY_PARAMETER, "grant_type", "password",
                                                        U_OPT_POST_BODY_PARAMETER, "username", i_session->username,
                                                        U_OPT_POST_BODY_PARAMETER, "password", i_session->user_password,
                                                        U_OPT_NONE) != U_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request password - Error setting request properties");
              ret = I_ERROR;
            }
            if (i_session->scope != NULL) {
              if (ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "scope", i_session->scope, U_OPT_NONE) != U_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request password - Error setting scope property");
                ret = I_ERROR;
              }
            }
            if ((res = _i_add_token_authentication(i_session, i_session->token_endpoint, &request, sign_alg, enc_alg, enc)) == I_OK) {
              if (ulfius_send_http_request(&request, &response) == U_OK) {
                if (response.status == 200 || response.status == 400) {
                  j_response = ulfius_get_json_body_response(&response, NULL);
                  if (j_response != NULL) {
                    if (i_parse_token_response(i_session, response.status, j_response) == I_OK) {
                      ret = response.status == 200?I_OK:I_ERROR_PARAM;
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request password - Error i_parse_token_response");
                      ret = I_ERROR_PARAM;
                    }
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request password - Error parsing JSON response");
                    ret = I_ERROR;
                  }
                  json_decref(j_response);
                } else if (response.status == 403 || response.status == 401) {
                  j_response = ulfius_get_json_body_response(&response, NULL);
                  if (i_parse_token_response(i_session, response.status, j_response) == I_OK) {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request password - Unauthorized");
                    ret = I_ERROR_UNAUTHORIZED;
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request password - Error i_parse_token_response");
                    ret = I_ERROR_PARAM;
                  }
                  json_decref(j_response);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request password - Invalid response status");
                  ret = I_ERROR;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request password - Error sending token request");
                ret = I_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request password - Error _i_add_token_authentication");
              ret = res;
            }
            ulfius_clean_request(&request);
            ulfius_clean_response(&response);
          } else {
            ret = I_ERROR_PARAM;
          }
          break;
        case I_RESPONSE_TYPE_CLIENT_CREDENTIALS:
          if (i_session->client_id != NULL) {
            _i_init_request(i_session, &request);
            ulfius_init_response(&response);
            if (ulfius_set_request_properties(&request, U_OPT_HTTP_VERB, "POST",
                                                        U_OPT_HTTP_URL, _i_get_endpoint(i_session, "token"),
                                                        U_OPT_HEADER_PARAMETER, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR,
                                                        U_OPT_HEADER_PARAMETER, "Accept", "application/json",
                                                        U_OPT_POST_BODY_PARAMETER, "grant_type", "client_credentials",
                                                        U_OPT_NONE) != U_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request client_credentials - Error setting request properties");
              ret = I_ERROR;
            }
            if (i_session->scope != NULL) {
              if (ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "scope", i_session->scope, U_OPT_NONE) != U_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request client_credentials - Error setting scope property");
                ret = I_ERROR;
              }
            }
            if ((res = _i_add_token_authentication(i_session, i_session->token_endpoint, &request, sign_alg, enc_alg, enc)) == I_OK) {
              if (ulfius_send_http_request(&request, &response) == U_OK) {
                if (response.status == 200 || response.status == 400) {
                  j_response = ulfius_get_json_body_response(&response, NULL);
                  if (j_response != NULL) {
                    if (i_parse_token_response(i_session, response.status, j_response) == I_OK) {
                      ret = response.status == 200?I_OK:I_ERROR_PARAM;
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request client_credentials - Error i_parse_token_response");
                      ret = I_ERROR_PARAM;
                    }
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request client_credentials - Error parsing JSON response");
                    ret = I_ERROR;
                  }
                  json_decref(j_response);
                } else if (response.status == 403 || response.status == 401) {
                  j_response = ulfius_get_json_body_response(&response, NULL);
                  if (i_parse_token_response(i_session, response.status, j_response) == I_OK) {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request client_credentials - Unauthorized");
                    ret = I_ERROR_UNAUTHORIZED;
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request client_credentials - Error i_parse_token_response");
                    ret = I_ERROR_PARAM;
                  }
                  json_decref(j_response);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request client_credentials - Invalid response status");
                  ret = I_ERROR;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request client_credentials - Error sending token request");
                ret = I_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request client_credentials - Error _i_add_token_authentication");
              ret = res;
            }
            ulfius_clean_request(&request);
            ulfius_clean_response(&response);
          } else {
            ret = I_ERROR_PARAM;
          }
          break;
        case I_RESPONSE_TYPE_REFRESH_TOKEN:
          if (i_session->refresh_token != NULL) {
            _i_init_request(i_session, &request);
            ulfius_init_response(&response);
            if (ulfius_set_request_properties(&request, U_OPT_HTTP_VERB, "POST",
                                                        U_OPT_HTTP_URL, _i_get_endpoint(i_session, "token"),
                                                        U_OPT_HEADER_PARAMETER, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR,
                                                        U_OPT_HEADER_PARAMETER, "Accept", "application/json",
                                                        U_OPT_POST_BODY_PARAMETER, "grant_type", "refresh_token",
                                                        U_OPT_POST_BODY_PARAMETER, "refresh_token", i_session->refresh_token,
                                                        U_OPT_NONE) != U_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request refresh - Error setting request properties");
              ret = I_ERROR;
            }
            if (i_session->scope != NULL) {
              if (ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "scope", i_session->scope, U_OPT_NONE) != U_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request refresh - Error setting scope property");
                ret = I_ERROR;
              }
            }
            if ((res = _i_add_token_authentication(i_session, i_session->token_endpoint, &request, sign_alg, enc_alg, enc)) == I_OK) {
              if (ulfius_send_http_request(&request, &response) == U_OK) {
                if (response.status == 200 || response.status == 400) {
                  j_response = ulfius_get_json_body_response(&response, NULL);
                  if (j_response != NULL) {
                    if (i_parse_token_response(i_session, response.status, j_response) == I_OK) {
                      ret = response.status == 200?I_OK:I_ERROR_PARAM;
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request refresh - Error i_parse_token_response");
                      ret = I_ERROR_PARAM;
                    }
                  } else {
                    ret = I_ERROR_PARAM;
                  }
                  json_decref(j_response);
                } else if (response.status == 403 || response.status == 401) {
                  j_response = ulfius_get_json_body_response(&response, NULL);
                  if (i_parse_token_response(i_session, response.status, j_response) == I_OK) {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request refresh - Unauthorized");
                    ret = I_ERROR_UNAUTHORIZED;
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request refresh - Error i_parse_token_response");
                    ret = I_ERROR_PARAM;
                  }
                  json_decref(j_response);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request refresh - Invalid response status");
                  ret = I_ERROR;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request refresh - Error sending token request");
                ret = I_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request refresh - Error _i_add_token_authentication");
              ret = res;
            }
            ulfius_clean_request(&request);
            ulfius_clean_response(&response);
          } else {
            ret = I_ERROR_PARAM;
          }
          break;
        case I_RESPONSE_TYPE_DEVICE_CODE:
          if (i_session->device_auth_code != NULL && i_session->device_auth_code != NULL) {
            _i_init_request(i_session, &request);
            ulfius_init_response(&response);
            ulfius_set_request_properties(&request,
                                          U_OPT_HTTP_VERB, "POST",
                                          U_OPT_HTTP_URL, _i_get_endpoint(i_session, "token"),
                                          U_OPT_HEADER_PARAMETER, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR,
                                          U_OPT_HEADER_PARAMETER, "Accept", "application/json",
                                          U_OPT_POST_BODY_PARAMETER, "grant_type", "urn:ietf:params:oauth:grant-type:device_code",
                                          U_OPT_POST_BODY_PARAMETER, "device_code", i_session->device_auth_code,
                                          U_OPT_NONE);
            if ((res = _i_add_token_authentication(i_session, i_session->token_endpoint, &request, sign_alg, enc_alg, enc)) == I_OK) {
              if (ulfius_send_http_request(&request, &response) == U_OK) {
                if (response.status == 200 || response.status == 400) {
                  j_response = ulfius_get_json_body_response(&response, NULL);
                  if (j_response != NULL) {
                    if (i_parse_token_response(i_session, response.status, j_response) == I_OK) {
                      ret = response.status == 200?I_OK:I_ERROR_PARAM;
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request device - Error i_parse_token_response");
                      ret = I_ERROR_PARAM;
                    }
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request device - Error parsing JSON response");
                    ret = I_ERROR;
                  }
                  json_decref(j_response);
                } else if (response.status == 403 || response.status == 401) {
                  j_response = ulfius_get_json_body_response(&response, NULL);
                  if (i_parse_token_response(i_session, response.status, j_response) == I_OK) {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request device - Unauthorized");
                    ret = I_ERROR_UNAUTHORIZED;
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request device - Error i_parse_token_response");
                    ret = I_ERROR_PARAM;
                  }
                  json_decref(j_response);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request device - Invalid response status");
                  ret = I_ERROR;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request device - Error sending token request");
                ret = I_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request device - Error _i_add_token_authentication");
              ret = res;
            }
            ulfius_clean_request(&request);
            ulfius_clean_response(&response);
          } else {
            ret = I_ERROR_PARAM;
          }
          break;
        case I_RESPONSE_TYPE_CIBA:
          if (i_session->ciba_auth_req_id != NULL) {
            _i_init_request(i_session, &request);
            ulfius_init_response(&response);
            ulfius_set_request_properties(&request,
                                          U_OPT_HTTP_VERB, "POST",
                                          U_OPT_HTTP_URL, _i_get_endpoint(i_session, "token"),
                                          U_OPT_HEADER_PARAMETER, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR,
                                          U_OPT_HEADER_PARAMETER, "Accept", "application/json",
                                          U_OPT_POST_BODY_PARAMETER, "grant_type", "urn:openid:params:grant-type:ciba",
                                          U_OPT_POST_BODY_PARAMETER, "auth_req_id", i_session->ciba_auth_req_id,
                                          U_OPT_NONE);
            if ((res = _i_add_token_authentication(i_session, i_session->token_endpoint, &request, sign_alg, enc_alg, enc)) == I_OK) {
              if (ulfius_send_http_request(&request, &response) == U_OK) {
                if (response.status == 200 || response.status == 400) {
                  j_response = ulfius_get_json_body_response(&response, NULL);
                  if (j_response != NULL) {
                    if (i_parse_token_response(i_session, response.status, j_response) == I_OK) {
                      ret = response.status == 200?I_OK:I_ERROR_PARAM;
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request ciba - Error i_parse_token_response");
                      ret = I_ERROR_PARAM;
                    }
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request ciba - Error parsing JSON response");
                    ret = I_ERROR;
                  }
                  json_decref(j_response);
                } else if (response.status == 403 || response.status == 401) {
                  j_response = ulfius_get_json_body_response(&response, NULL);
                  if (i_parse_token_response(i_session, response.status, j_response) == I_OK) {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request ciba - Unauthorized");
                    ret = I_ERROR_UNAUTHORIZED;
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request ciba - Error i_parse_token_response");
                    ret = I_ERROR_PARAM;
                  }
                  json_decref(j_response);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request ciba - Invalid response status");
                  ret = I_ERROR;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request ciba - Error sending token request");
                ret = I_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request ciba - Error _i_add_token_authentication");
              ret = res;
            }
            ulfius_clean_request(&request);
            ulfius_clean_response(&response);
          } else {
            ret = I_ERROR_PARAM;
          }
          break;
        default:
          ret = I_ERROR_PARAM;
          break;
      }
    }
  } else {
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_verify_id_token(struct _i_session * i_session) {
  int ret = I_ERROR_PARAM;
  jwt_t * jwt = NULL;
  size_t hash_len = 128, hash_encoded_len = 128;
  unsigned char hash[128], hash_encoded[128] = {0};
  int alg = GNUTLS_DIG_UNKNOWN;
  gnutls_datum_t hash_data;

  if (i_session != NULL && i_session->id_token != NULL) {
    if (r_jwt_init(&jwt) == RHN_OK) {
      if (_i_verify_jwt_sig_enc(i_session, i_session->id_token, I_TOKEN_TYPE_ID_TOKEN, jwt) != I_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_id_token - Error _i_verify_jwt_sig_enc");
        ret = I_ERROR;
      } else {
        json_decref(i_session->id_token_payload);
        if ((i_session->id_token_payload = r_jwt_get_full_claims_json_t(jwt)) != NULL) {
          if (r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, i_session->issuer,
                                         R_JWT_CLAIM_SUB, NULL,
                                         R_JWT_CLAIM_AUD, NULL,
                                         R_JWT_CLAIM_EXP, R_JWT_CLAIM_NOW,
                                         R_JWT_CLAIM_IAT, R_JWT_CLAIM_NOW,
                                         R_JWT_CLAIM_NOP) == RHN_OK &&
              (!o_strlen(i_session->nonce) || r_jwt_validate_claims(jwt, R_JWT_CLAIM_STR, "nonce", i_session->nonce,R_JWT_CLAIM_NOP) == RHN_OK)) {
            switch (r_jwt_get_sign_alg(jwt)) {
              case R_JWA_ALG_HS256:
              case R_JWA_ALG_RS256:
              case R_JWA_ALG_ES256:
              case R_JWA_ALG_PS256:
              case R_JWA_ALG_EDDSA:
              case R_JWA_ALG_ES256K:
                alg = GNUTLS_DIG_SHA256;
                break;
              case R_JWA_ALG_HS384:
              case R_JWA_ALG_RS384:
              case R_JWA_ALG_ES384:
              case R_JWA_ALG_PS384:
                alg = GNUTLS_DIG_SHA384;
                break;
              case R_JWA_ALG_HS512:
              case R_JWA_ALG_RS512:
              case R_JWA_ALG_ES512:
              case R_JWA_ALG_PS512:
                alg = GNUTLS_DIG_SHA384;
                break;
              default:
                alg = GNUTLS_DIG_UNKNOWN;
                break;
            }
            ret = I_OK;
            if (json_object_get(i_session->id_token_payload, "at_hash") != NULL) {
              if (i_session->access_token != NULL) {
                if (alg != GNUTLS_DIG_UNKNOWN) {
                  hash_data.data = (unsigned char*)i_session->access_token;
                  hash_data.size = o_strlen(i_session->access_token);
                  if (gnutls_fingerprint(alg, &hash_data, hash, &hash_len) == GNUTLS_E_SUCCESS) {
                    if (o_base64url_encode(hash, hash_len/2, hash_encoded, &hash_encoded_len)) {
                      if (o_strncmp((const char *)hash_encoded, json_string_value(json_object_get(i_session->id_token_payload, "at_hash")), hash_encoded_len) != 0) {
                        y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_id_token at - at_hash invalid");
                        ret = I_ERROR_PARAM;
                      }
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_id_token at - Error o_base64url_encode at_hash");
                      ret = I_ERROR;
                    }
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_id_token at - Error gnutls_fingerprint at_hash");
                    ret = I_ERROR;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_id_token at - Invalid alg");
                  ret = I_ERROR_PARAM;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_id_token at - missing input");
                ret = I_ERROR_PARAM;
              }
            }
            if (json_object_get(i_session->id_token_payload, "c_hash") != NULL) {
              if (i_session->code != NULL) {
                if (alg != GNUTLS_DIG_UNKNOWN) {
                  hash_data.data = (unsigned char*)i_session->code;
                  hash_data.size = o_strlen(i_session->code);
                  if (gnutls_fingerprint(alg, &hash_data, hash, &hash_len) == GNUTLS_E_SUCCESS) {
                    if (o_base64url_encode(hash, hash_len/2, hash_encoded, &hash_encoded_len)) {
                      if (o_strncmp((const char *)hash_encoded, json_string_value(json_object_get(i_session->id_token_payload, "c_hash")), hash_encoded_len) != 0) {
                        y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_id_token - c_hash invalid");
                        ret = I_ERROR_PARAM;
                      }
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_id_token c - Error o_base64url_encode c_hash");
                      ret = I_ERROR;
                    }
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_id_token c - Error gnutls_fingerprint c_hash");
                    ret = I_ERROR;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_id_token c - unknown alg");
                  ret = I_ERROR_PARAM;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_id_token c - missing input");
                ret = I_ERROR_PARAM;
              }
            }
            if (json_object_get(i_session->id_token_payload, "s_hash") != NULL) {
              if (i_session->state != NULL) {
                if (alg != GNUTLS_DIG_UNKNOWN) {
                  hash_data.data = (unsigned char*)i_session->state;
                  hash_data.size = o_strlen(i_session->state);
                  if (gnutls_fingerprint(alg, &hash_data, hash, &hash_len) == GNUTLS_E_SUCCESS) {
                    if (o_base64url_encode(hash, hash_len/2, hash_encoded, &hash_encoded_len)) {
                      if (o_strncmp((const char *)hash_encoded, json_string_value(json_object_get(i_session->id_token_payload, "s_hash")), hash_encoded_len) != 0) {
                        y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_id_token - s_hash invalid");
                        ret = I_ERROR_PARAM;
                      }
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_id_token c - Error o_base64url_encode s_hash");
                      ret = I_ERROR;
                    }
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_id_token c - Error gnutls_fingerprint s_hash");
                    ret = I_ERROR;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_id_token c - unknown alg");
                  ret = I_ERROR_PARAM;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_id_token c - missing input");
                ret = I_ERROR_PARAM;
              }
            }
            if (json_string_length(json_object_get(i_session->id_token_payload, "sid"))) {
              if ((ret = i_set_str_parameter(i_session, I_OPT_ID_TOKEN_SID, json_string_value(json_object_get(i_session->id_token_payload, "sid")))) != I_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_id_token c - Error setting sid");
              }
            }
          } else {
            y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_id_token - invalid JWT claims");
            ret = I_ERROR_PARAM;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_id_token - Error extracting claims from id_token");
          ret = I_ERROR;
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_id_token - Error r_jwt_init");
      ret = I_ERROR;
    }
    r_jwt_free(jwt);
  } else {
    ret = I_ERROR_PARAM;
  }

  return ret;
}

int i_verify_jwt_access_token(struct _i_session * i_session, const char * aud) {
  int ret, res;
  jwt_t * jwt = NULL;

  if (r_jwt_init(&jwt) == RHN_OK) {
    if ((res = _i_verify_jwt_sig_enc(i_session, i_get_str_parameter(i_session, I_OPT_ACCESS_TOKEN), I_TOKEN_TYPE_ACCESS_TOKEN, jwt)) == I_OK) {
      if (0 != o_strcmp("at+jwt", r_jwt_get_header_str_value(jwt, "typ")) && 0 != o_strcmp("application/at+jwt", r_jwt_get_header_str_value(jwt, "typ"))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_i_verify_jwt_access_token_claims - invalid typ");
        ret = I_ERROR_PARAM;
      } else if (r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, i_get_str_parameter(i_session, I_OPT_ISSUER),
                                            R_JWT_CLAIM_EXP, R_JWT_CLAIM_NOW,
                                            R_JWT_CLAIM_SUB, NULL,
                                            R_JWT_CLAIM_IAT, R_JWT_CLAIM_NOW,
                                            R_JWT_CLAIM_JTI, NULL,
                                            R_JWT_CLAIM_STR, "client_id", NULL,
                                            R_JWT_CLAIM_NOP) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_i_verify_jwt_access_token_claims - invalid claims");
        ret = I_ERROR_PARAM;
      } else {
        if (!o_strlen(aud) || r_jwt_validate_claims(jwt, R_JWT_CLAIM_AUD, aud, R_JWT_CLAIM_NOP) == RHN_OK) {
          json_decref(i_session->access_token_payload);
          i_session->access_token_payload = r_jwt_get_full_claims_json_t(jwt);
          ret = I_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_verify_jwt_access_token_claims - invalid claim aud");
          ret = I_ERROR_PARAM;
        }
      }
    } else if (res == I_ERROR) {
      y_log_message(Y_LOG_LEVEL_ERROR, "_i_verify_jwt_access_token_claims - Error _i_verify_jwt_sig_enc");
      ret = I_ERROR_PARAM;
    } else {
      ret = res;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "_i_verify_jwt_access_token_claims - Error r_jwt_init");
    ret = I_ERROR;
  }
  r_jwt_free(jwt);
  return ret;
}

int i_revoke_token(struct _i_session * i_session, int authentication) {
  int ret;
  struct _u_request request;
  struct _u_response response;
  char * bearer = NULL, * dpop_token = NULL;
  json_t * j_response;
  jwa_alg sign_alg = R_JWA_ALG_UNKNOWN, enc_alg = R_JWA_ALG_UNKNOWN;
  jwa_enc enc = R_JWA_ENC_UNKNOWN;

  if (i_session != NULL && o_strlen(i_session->revocation_endpoint) && o_strlen(i_session->token_target)) {
    if (_i_init_request(i_session, &request) != U_OK || ulfius_init_response(&response) != U_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_revoke_token - Error initializing request or response");
      ret = I_ERROR;
    } else {
      ret = I_OK;
      if (ulfius_set_request_properties(&request, U_OPT_HTTP_VERB, "POST",
                                                  U_OPT_HTTP_URL, _i_get_endpoint(i_session, "revocation"),
                                                  U_OPT_HEADER_PARAMETER, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR,
                                                  U_OPT_POST_BODY_PARAMETER, "token", i_session->token_target,
                                                  U_OPT_NONE) != U_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_revoke_token - Error setting request properties");
        ret = I_ERROR;
      }
      if (authentication == I_INTROSPECT_REVOKE_AUTH_ACCESS_TOKEN) {
        if (o_strlen(i_session->access_token)) {
          // Set DPoP
          if (i_session->use_dpop) {
            if ((dpop_token = i_generate_dpop_token(i_session, "POST", i_session->revocation_endpoint, 0, 1)) != NULL) {
              if (ulfius_set_request_properties(&request, U_OPT_HEADER_PARAMETER, I_HEADER_DPOP, dpop_token, U_OPT_NONE) != U_OK) {
                y_log_message(Y_LOG_LEVEL_DEBUG, "i_revoke_token - Error setting DPoP in header");
                ret = I_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_DEBUG, "i_revoke_token - Error i_generate_dpop_token");
              ret = I_ERROR;
            }
            o_free(dpop_token);
          }
          bearer = msprintf("Bearer %s", i_session->access_token);
          if (ulfius_set_request_properties(&request, U_OPT_HEADER_PARAMETER, "Authorization", bearer, U_OPT_NONE) != U_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_revoke_token - Error setting bearer token");
            ret = I_ERROR;
          }
          o_free(bearer);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_revoke_token - Error no access token available");
          ret = I_ERROR;
        }
      }
      if (authentication == I_INTROSPECT_REVOKE_AUTH_CLIENT_TARGET) {
        if (i_session->client_sign_alg != R_JWA_ALG_UNKNOWN) {
          sign_alg = i_session->client_sign_alg;
        } else if (i_session->token_endpoint_signing_alg != R_JWA_ALG_UNKNOWN) {
          sign_alg = i_session->token_endpoint_signing_alg;
        }
        if (i_session->client_enc_alg != R_JWA_ALG_UNKNOWN) {
          enc_alg = i_session->client_enc_alg;
        } else if (i_session->token_endpoint_encryption_alg != R_JWA_ALG_UNKNOWN) {
          enc_alg = i_session->token_endpoint_encryption_alg;
        }
        if (i_session->client_enc != R_JWA_ENC_UNKNOWN) {
          enc = i_session->client_enc;
        } else if (i_session->token_endpoint_encryption_enc != R_JWA_ENC_UNKNOWN) {
          enc = i_session->token_endpoint_encryption_enc;
        }
        if ((ret = _i_add_token_authentication(i_session, i_session->revocation_endpoint, &request, sign_alg, enc_alg, enc)) != I_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_revoke_token - Error _i_add_token_authentication");
          ret = I_ERROR;
        }
      }
      if (o_strlen(i_session->token_target_type_hint)) {
        if (ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "token_type_hint", i_session->token_target_type_hint, U_OPT_NONE) != U_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_revoke_token - Error setting target token type hint");
          ret = I_ERROR;
        }
      }
      if (ret == I_OK) {
        if (ulfius_send_http_request(&request, &response) == U_OK) {
          j_response = ulfius_get_json_body_response(&response, NULL);
          if (response.status == 404) {
            ret = I_ERROR_PARAM;
          } else if (response.status == 400) {
            if (_i_parse_error_response(i_session, j_response) != I_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_revoke_token - Error _i_parse_error_response (1)");
            }
            ret = I_ERROR_PARAM;
          } else if (response.status == 401 || response.status == 403) {
            if (_i_parse_error_response(i_session, j_response) != I_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_revoke_token - Error _i_parse_error_response (1)");
            }
            ret = I_ERROR_UNAUTHORIZED;
          } else if (response.status != 200) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_revoke_token - Error revoking token");
            ret = I_ERROR;
          }
          json_decref(j_response);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_revoke_token - Error sending http request");
          ret = I_ERROR;
        }
      }
      ulfius_clean_request(&request);
      ulfius_clean_response(&response);
    }
  } else {
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_get_token_introspection(struct _i_session * i_session, json_t ** j_result, int authentication, int get_jwt) {
  int ret;
  struct _u_request request;
  struct _u_response response;
  char * bearer = NULL, * token = NULL, * dpop_token = NULL;
  jwt_t * jwt = NULL;
  json_t * j_claims, * j_response;
  jwa_alg sign_alg = R_JWA_ALG_UNKNOWN, enc_alg = R_JWA_ALG_UNKNOWN;
  jwa_enc enc = R_JWA_ENC_UNKNOWN;

  if (i_session != NULL && o_strlen(i_session->introspection_endpoint) && o_strlen(i_session->token_target) && j_result != NULL) {
    if (_i_init_request(i_session, &request) != U_OK || ulfius_init_response(&response) != U_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_get_token_introspection - Error initializing request or response");
      ret = I_ERROR;
    } else {
      ret = I_OK;
      if (ulfius_set_request_properties(&request, U_OPT_HTTP_VERB, "POST",
                                                  U_OPT_HTTP_URL, _i_get_endpoint(i_session, "introspection"),
                                                  U_OPT_HEADER_PARAMETER, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR,
                                                  U_OPT_HEADER_PARAMETER, "Accept", get_jwt?"application/token-userinfo+jwt":"application/json",
                                                  U_OPT_POST_BODY_PARAMETER, "token", i_session->token_target,
                                                  U_OPT_NONE) != U_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_get_token_introspection - Error setting request properties");
        ret = I_ERROR;
      }
      if (authentication == I_INTROSPECT_REVOKE_AUTH_ACCESS_TOKEN) {
        if (o_strlen(i_session->access_token)) {
          // Set DPoP
          if (i_session->use_dpop) {
            if ((dpop_token = i_generate_dpop_token(i_session, "POST", i_session->introspection_endpoint, 0, 1)) != NULL) {
              if (ulfius_set_request_properties(&request, U_OPT_HEADER_PARAMETER, I_HEADER_DPOP, dpop_token, U_OPT_NONE) != U_OK) {
                y_log_message(Y_LOG_LEVEL_DEBUG, "i_get_token_introspection - Error setting DPoP in header");
                ret = I_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_DEBUG, "i_get_token_introspection - Error i_generate_dpop_token");
              ret = I_ERROR;
            }
            o_free(dpop_token);
          }
          bearer = msprintf("Bearer %s", i_session->access_token);
          if (ulfius_set_request_properties(&request, U_OPT_HEADER_PARAMETER, "Authorization", bearer, U_OPT_NONE) != U_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_get_token_introspection - Error setting bearer token");
            ret = I_ERROR;
          }
          o_free(bearer);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_get_token_introspection - Error no access token available");
          ret = I_ERROR;
        }
      } else if (authentication == I_INTROSPECT_REVOKE_AUTH_CLIENT_TARGET) {
        if (i_session->client_sign_alg != R_JWA_ALG_UNKNOWN) {
          sign_alg = i_session->client_sign_alg;
        } else if (i_session->token_endpoint_signing_alg != R_JWA_ALG_UNKNOWN) {
          sign_alg = i_session->token_endpoint_signing_alg;
        }
        if (i_session->client_enc_alg != R_JWA_ALG_UNKNOWN) {
          enc_alg = i_session->client_enc_alg;
        } else if (i_session->token_endpoint_encryption_alg != R_JWA_ALG_UNKNOWN) {
          enc_alg = i_session->token_endpoint_encryption_alg;
        }
        if (i_session->client_enc != R_JWA_ENC_UNKNOWN) {
          enc = i_session->client_enc;
        } else if (i_session->token_endpoint_encryption_enc != R_JWA_ENC_UNKNOWN) {
          enc = i_session->token_endpoint_encryption_enc;
        }
        if ((ret = _i_add_token_authentication(i_session, i_session->introspection_endpoint, &request, sign_alg, enc_alg, enc)) != I_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_get_token_introspection - Error _i_add_token_authentication");
          ret = I_ERROR;
        }
      }
      if (o_strlen(i_session->token_target_type_hint)) {
        if (ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "token_type_hint", i_session->token_target_type_hint, U_OPT_NONE) != U_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_get_token_introspection - Error setting target token type hint");
          ret = I_ERROR;
        }
      }
      if (ret == I_OK) {
        if (ulfius_send_http_request(&request, &response) == U_OK) {
          j_response = ulfius_get_json_body_response(&response, NULL);
          if (response.status == 200) {
            if (NULL != o_strstr(u_map_get_case(response.map_header, "Content-Type"), "application/jwt")) {
              if (r_jwt_init(&jwt) == RHN_OK) {
                token = o_strndup(response.binary_body, response.binary_body_length);
                if (_i_verify_jwt_sig_enc(i_session, token, I_TOKEN_TYPE_INTROSPECTION, jwt) != I_OK) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "i_get_token_introspection - Error _i_verify_jwt_sig_enc");
                  ret = I_ERROR;
                } else {
                  if (0 != o_strcmp("at+jwt", r_jwt_get_header_str_value(jwt, "typ")) && 0 != o_strcmp("application/at+jwt", r_jwt_get_header_str_value(jwt, "typ"))) {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_get_token_introspection - invalid typ");
                    ret = I_ERROR;
                  } else if (r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, i_get_str_parameter(i_session, I_OPT_ISSUER),
                                                 R_JWT_CLAIM_EXP, R_JWT_CLAIM_NOW,
                                                 R_JWT_CLAIM_NOP) != RHN_OK) {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_get_token_introspection - invalid claims");
                    ret = I_ERROR;
                  } else {
                    j_claims = r_jwt_get_full_claims_json_t(jwt);
                    if ((*j_result = json_incref(json_object_get(j_claims, "token_introspection"))) == NULL) {
                      y_log_message(Y_LOG_LEVEL_ERROR, "i_get_token_introspection - invalid claims, object token_introspection missing");
                      ret = I_ERROR;
                    } else {
                      ret = I_OK;
                    }
                    json_decref(j_claims);
                  }
                }
                o_free(token);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "i_get_token_introspection - Error r_jwt_init");
                ret = I_ERROR;
              }
              r_jwt_free(jwt);
            } else {
              *j_result = json_incref(j_response);
            }
          } else if (response.status == 404) {
            ret = I_ERROR_PARAM;
          } else if (response.status == 400) {
            if (_i_parse_error_response(i_session, j_response) != I_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_get_token_introspection - Error _i_parse_error_response (1)");
            }
            ret = I_ERROR_PARAM;
          } else if (response.status == 401 || response.status == 403) {
            if (_i_parse_error_response(i_session, j_response) != I_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_get_token_introspection - Error _i_parse_error_response (1)");
            }
            ret = I_ERROR_UNAUTHORIZED;
          } else if (response.status != 200) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_get_token_introspection - Error introspecting token");
            ret = I_ERROR;
          }
          json_decref(j_response);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_get_token_introspection - Error sending http request");
          ret = I_ERROR;
        }
      }
      ulfius_clean_request(&request);
      ulfius_clean_response(&response);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "i_get_token_introspection - Error input parameters");
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_register_client(struct _i_session * i_session, json_t * j_parameters, int update_session, json_t ** j_result) {
  int ret;
  struct _u_request request;
  struct _u_response response;
  char * bearer = NULL;
  json_t * j_response, * j_copy_parameters;

  if (j_parameters != NULL) {
    j_copy_parameters = json_deep_copy(j_parameters);
  } else {
    j_copy_parameters = json_object();
  }
  if (i_session != NULL && o_strlen(i_session->registration_endpoint)) {
    if (!json_is_array(json_object_get(j_copy_parameters, "redirect_uris"))) {
      json_object_set_new(j_copy_parameters, "redirect_uris", json_array());
    }
    if (i_session->redirect_uri != NULL && !_i_json_array_has_string(json_object_get(j_copy_parameters, "redirect_uris"), i_session->redirect_uri)) {
      json_array_append_new(json_object_get(j_copy_parameters, "redirect_uris"), json_string(i_session->redirect_uri));
    }
    if (i_session->access_token_signing_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "access_token_signing_alg", json_string(r_jwa_alg_to_str(i_session->access_token_signing_alg)));
    }
    if (i_session->access_token_encryption_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "access_token_encryption_alg", json_string(r_jwa_alg_to_str(i_session->access_token_encryption_alg)));
    }
    if (i_session->access_token_encryption_enc != R_JWA_ENC_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "access_token_encryption_enc", json_string(r_jwa_enc_to_str(i_session->access_token_encryption_enc)));
    }
    if (i_session->id_token_signing_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "id_token_signing_alg", json_string(r_jwa_alg_to_str(i_session->id_token_signing_alg)));
    }
    if (i_session->id_token_encryption_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "id_token_encryption_alg", json_string(r_jwa_alg_to_str(i_session->id_token_encryption_alg)));
    }
    if (i_session->id_token_encryption_enc != R_JWA_ENC_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "id_token_encryption_enc", json_string(r_jwa_enc_to_str(i_session->id_token_encryption_enc)));
    }
    if (i_session->userinfo_signing_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "userinfo_signing_alg", json_string(r_jwa_alg_to_str(i_session->userinfo_signing_alg)));
    }
    if (i_session->userinfo_encryption_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "userinfo_encryption_alg", json_string(r_jwa_alg_to_str(i_session->userinfo_encryption_alg)));
    }
    if (i_session->userinfo_encryption_enc != R_JWA_ENC_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "userinfo_encryption_enc", json_string(r_jwa_enc_to_str(i_session->userinfo_encryption_enc)));
    }
    if (i_session->request_object_signing_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "request_object_signing_alg", json_string(r_jwa_alg_to_str(i_session->request_object_signing_alg)));
    }
    if (i_session->request_object_encryption_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "request_object_encryption_alg", json_string(r_jwa_alg_to_str(i_session->request_object_encryption_alg)));
    }
    if (i_session->request_object_encryption_enc != R_JWA_ENC_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "request_object_encryption_enc", json_string(r_jwa_enc_to_str(i_session->request_object_encryption_enc)));
    }
    if (i_session->token_endpoint_signing_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "token_endpoint_signing_alg", json_string(r_jwa_alg_to_str(i_session->token_endpoint_signing_alg)));
    }
    if (i_session->token_endpoint_encryption_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "token_endpoint_encryption_alg", json_string(r_jwa_alg_to_str(i_session->token_endpoint_encryption_alg)));
    }
    if (i_session->token_endpoint_encryption_enc != R_JWA_ENC_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "token_endpoint_encryption_enc", json_string(r_jwa_enc_to_str(i_session->token_endpoint_encryption_enc)));
    }
    if (i_session->ciba_request_signing_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "ciba_request_signing_alg", json_string(r_jwa_alg_to_str(i_session->ciba_request_signing_alg)));
    }
    if (i_session->ciba_request_encryption_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "ciba_request_encryption_alg", json_string(r_jwa_alg_to_str(i_session->ciba_request_encryption_alg)));
    }
    if (i_session->ciba_request_encryption_enc != R_JWA_ENC_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "ciba_request_encryption_enc", json_string(r_jwa_enc_to_str(i_session->ciba_request_encryption_enc)));
    }
    if (i_session->auth_response_signing_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "auth_response_signing_alg", json_string(r_jwa_alg_to_str(i_session->auth_response_signing_alg)));
    }
    if (i_session->auth_response_encryption_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "auth_response_encryption_alg", json_string(r_jwa_alg_to_str(i_session->auth_response_encryption_alg)));
    }
    if (i_session->auth_response_encryption_enc != R_JWA_ENC_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "auth_response_encryption_enc", json_string(r_jwa_enc_to_str(i_session->auth_response_encryption_enc)));
    }
    if (i_session->ciba_mode == I_CIBA_MODE_POLL) {
      json_object_set_new(j_copy_parameters, "backchannel_token_delivery_mode", json_string("poll"));
    }
    if (i_session->ciba_mode == I_CIBA_MODE_PING) {
      json_object_set_new(j_copy_parameters, "backchannel_token_delivery_mode", json_string("ping"));
    }
    if (i_session->ciba_mode == I_CIBA_MODE_PUSH) {
      json_object_set_new(j_copy_parameters, "backchannel_token_delivery_mode", json_string("push"));
    }
    if (i_session->ciba_client_notification_endpoint != NULL) {
      json_object_set_new(j_copy_parameters, "backchannel_client_notification_endpoint", json_string(i_session->ciba_client_notification_endpoint));
    }
    if (i_session->frontchannel_logout_uri != NULL) {
      json_object_set_new(j_copy_parameters, "frontchannel_logout_uri", json_string(i_session->frontchannel_logout_uri));
      json_object_set_new(j_copy_parameters, "frontchannel_logout_session_required", i_session->frontchannel_logout_session_required?json_true():json_false());
    }
    if (i_session->backchannel_logout_uri != NULL) {
      json_object_set_new(j_copy_parameters, "backchannel_logout_uri", json_string(i_session->backchannel_logout_uri));
      json_object_set_new(j_copy_parameters, "backchannel_logout_session_required", i_session->backchannel_logout_session_required?json_true():json_false());
    }
    if (i_session->post_logout_redirect_uri != NULL) {
      json_object_set_new(j_copy_parameters, "post_logout_redirect_uri", json_string(i_session->post_logout_redirect_uri));
    }
    if (json_string_length(json_array_get(json_object_get(j_copy_parameters, "redirect_uris"), 0))) {
      if (_i_init_request(i_session, &request) != U_OK || ulfius_init_response(&response) != U_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_register_client - Error initializing request or response");
        ret = I_ERROR;
      } else {
        ret = I_OK;
        if (ulfius_set_request_properties(&request, U_OPT_HTTP_VERB, "POST",
                                                    U_OPT_HTTP_URL, i_session->registration_endpoint,
                                                    U_OPT_HEADER_PARAMETER, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR,
                                                    U_OPT_JSON_BODY, j_copy_parameters,
                                                    U_OPT_NONE) != U_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_register_client - Error setting parameters");
          ret = I_ERROR;
        }
        if (o_strlen(i_session->access_token)) {
          bearer = msprintf("Bearer %s", i_session->access_token);
          if (ulfius_set_request_properties(&request, U_OPT_HEADER_PARAMETER, "Authorization", bearer, U_OPT_NONE) != U_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_register_client - Error setting bearer token");
            ret = I_ERROR;
          }
          o_free(bearer);
        }
        if (ret == I_OK) {
          if (ulfius_send_http_request(&request, &response) == U_OK) {
            j_response = ulfius_get_json_body_response(&response, NULL);
            if (response.status == 200) {
              if (update_session) {
                i_set_str_parameter(i_session, I_OPT_CLIENT_ID, json_string_value(json_object_get(j_response, "client_id")));
                i_set_str_parameter(i_session, I_OPT_CLIENT_SECRET, json_string_value(json_object_get(j_response, "client_secret")));
                i_set_str_parameter(i_session, I_OPT_REDIRECT_URI, json_string_value(json_array_get(json_object_get(j_response, "redirect_uris"), 0)));
              }
              if (j_result != NULL) {
                *j_result = json_incref(j_response);
              }
            } else if (response.status == 404) {
              ret = I_ERROR_PARAM;
            } else if (response.status == 400) {
              if (_i_parse_error_response(i_session, j_response) != I_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "i_get_registration_client - Error _i_parse_error_response (1)");
              }
              ret = I_ERROR_PARAM;
            } else if (response.status == 401 || response.status == 403) {
              if (_i_parse_error_response(i_session, j_response) != I_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "i_get_registration_client - Error _i_parse_error_response (1)");
              }
              ret = I_ERROR_UNAUTHORIZED;
            } else if (response.status != 200) {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_register_client - Error registering client");
              ret = I_ERROR;
            }
            json_decref(j_response);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_register_client - Error sending http request");
            ret = I_ERROR;
          }
        }
        ulfius_clean_request(&request);
        ulfius_clean_response(&response);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "i_register_client - Invalid parameters, no redirect_uris specified");
      ret = I_ERROR_PARAM;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "i_register_client - Invalid parameters");
    ret = I_ERROR_PARAM;
  }
  json_decref(j_copy_parameters);
  return ret;
}

int i_get_registration_client(struct _i_session * i_session, json_t ** j_result) {
  int ret;
  struct _u_request request;
  struct _u_response response;
  char * bearer = NULL;
  json_t * j_response;

  if (i_session != NULL && o_strlen(i_session->registration_endpoint) && o_strlen(i_session->client_id)) {
    if (_i_init_request(i_session, &request) != U_OK || ulfius_init_response(&response) != U_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_get_registration_client - Error initializing request or response");
      ret = I_ERROR;
    } else {
      ret = I_OK;
      if (ulfius_set_request_properties(&request, U_OPT_HTTP_VERB, "GET",
                                                  U_OPT_HTTP_URL, i_session->registration_endpoint,
                                                  U_OPT_HTTP_URL_APPEND, "/",
                                                  U_OPT_HTTP_URL_APPEND, i_session->client_id,
                                                  U_OPT_HEADER_PARAMETER, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR,
                                                  U_OPT_NONE) != U_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_get_registration_client - Error setting parameters");
        ret = I_ERROR;
      }
      if (o_strlen(i_session->access_token)) {
        bearer = msprintf("Bearer %s", i_session->access_token);
        if (ulfius_set_request_properties(&request, U_OPT_HEADER_PARAMETER, "Authorization", bearer, U_OPT_NONE) != U_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_get_registration_client - Error setting bearer token");
          ret = I_ERROR;
        }
        o_free(bearer);
      }
      if (ret == I_OK) {
        if (ulfius_send_http_request(&request, &response) == U_OK) {
          j_response = ulfius_get_json_body_response(&response, NULL);
          if (response.status == 200) {
            if (j_result != NULL) {
              *j_result = json_incref(j_response);
            }
          } else if (response.status == 404) {
            ret = I_ERROR_PARAM;
          } else if (response.status == 400) {
            if (_i_parse_error_response(i_session, j_response) != I_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_get_registration_client - Error _i_parse_error_response (1)");
            }
            ret = I_ERROR_PARAM;
          } else if (response.status == 401 || response.status == 403) {
            if (_i_parse_error_response(i_session, j_response) != I_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_get_registration_client - Error _i_parse_error_response (1)");
            }
            ret = I_ERROR_UNAUTHORIZED;
          } else if (response.status != 200) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_get_registration_client - Error registering client %d", response.status);
            ret = I_ERROR;
          }
          json_decref(j_response);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_get_registration_client - Error sending http request");
          ret = I_ERROR;
        }
      }
      ulfius_clean_request(&request);
      ulfius_clean_response(&response);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "i_get_registration_client - Invalid parameters");
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_manage_registration_client(struct _i_session * i_session, json_t * j_parameters, int update_session, json_t ** j_result) {
  int ret;
  struct _u_request request;
  struct _u_response response;
  char * bearer = NULL;
  json_t * j_response, * j_copy_parameters;

  if (j_parameters != NULL) {
    j_copy_parameters = json_deep_copy(j_parameters);
  } else {
    j_copy_parameters = json_object();
  }
  if (i_session != NULL && o_strlen(i_session->registration_endpoint)) {
    if (!json_is_array(json_object_get(j_copy_parameters, "redirect_uris"))) {
      json_object_set_new(j_copy_parameters, "redirect_uris", json_array());
    }
    if (i_session->redirect_uri != NULL && !_i_json_array_has_string(json_object_get(j_copy_parameters, "redirect_uris"), i_session->redirect_uri)) {
      json_array_append_new(json_object_get(j_copy_parameters, "redirect_uris"), json_string(i_session->redirect_uri));
    }
    if (i_session->access_token_signing_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "access_token_signing_alg", json_string(r_jwa_alg_to_str(i_session->access_token_signing_alg)));
    }
    if (i_session->access_token_encryption_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "access_token_encryption_alg", json_string(r_jwa_alg_to_str(i_session->access_token_encryption_alg)));
    }
    if (i_session->access_token_encryption_enc != R_JWA_ENC_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "access_token_encryption_enc", json_string(r_jwa_enc_to_str(i_session->access_token_encryption_enc)));
    }
    if (i_session->id_token_signing_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "id_token_signing_alg", json_string(r_jwa_alg_to_str(i_session->id_token_signing_alg)));
    }
    if (i_session->id_token_encryption_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "id_token_encryption_alg", json_string(r_jwa_alg_to_str(i_session->id_token_encryption_alg)));
    }
    if (i_session->id_token_encryption_enc != R_JWA_ENC_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "id_token_encryption_enc", json_string(r_jwa_enc_to_str(i_session->id_token_encryption_enc)));
    }
    if (i_session->userinfo_signing_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "userinfo_signing_alg", json_string(r_jwa_alg_to_str(i_session->userinfo_signing_alg)));
    }
    if (i_session->userinfo_encryption_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "userinfo_encryption_alg", json_string(r_jwa_alg_to_str(i_session->userinfo_encryption_alg)));
    }
    if (i_session->userinfo_encryption_enc != R_JWA_ENC_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "userinfo_encryption_enc", json_string(r_jwa_enc_to_str(i_session->userinfo_encryption_enc)));
    }
    if (i_session->request_object_signing_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "request_object_signing_alg", json_string(r_jwa_alg_to_str(i_session->request_object_signing_alg)));
    }
    if (i_session->request_object_encryption_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "request_object_encryption_alg", json_string(r_jwa_alg_to_str(i_session->request_object_encryption_alg)));
    }
    if (i_session->request_object_encryption_enc != R_JWA_ENC_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "request_object_encryption_enc", json_string(r_jwa_enc_to_str(i_session->request_object_encryption_enc)));
    }
    if (i_session->token_endpoint_signing_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "token_endpoint_signing_alg", json_string(r_jwa_alg_to_str(i_session->token_endpoint_signing_alg)));
    }
    if (i_session->token_endpoint_encryption_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "token_endpoint_encryption_alg", json_string(r_jwa_alg_to_str(i_session->token_endpoint_encryption_alg)));
    }
    if (i_session->token_endpoint_encryption_enc != R_JWA_ENC_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "token_endpoint_encryption_enc", json_string(r_jwa_enc_to_str(i_session->token_endpoint_encryption_enc)));
    }
    if (i_session->ciba_request_signing_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "ciba_request_signing_alg", json_string(r_jwa_alg_to_str(i_session->ciba_request_signing_alg)));
    }
    if (i_session->ciba_request_encryption_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "ciba_request_encryption_alg", json_string(r_jwa_alg_to_str(i_session->ciba_request_encryption_alg)));
    }
    if (i_session->ciba_request_encryption_enc != R_JWA_ENC_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "ciba_request_encryption_enc", json_string(r_jwa_enc_to_str(i_session->ciba_request_encryption_enc)));
    }
    if (i_session->auth_response_signing_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "auth_response_signing_alg", json_string(r_jwa_alg_to_str(i_session->auth_response_signing_alg)));
    }
    if (i_session->auth_response_encryption_alg != R_JWA_ALG_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "auth_response_encryption_alg", json_string(r_jwa_alg_to_str(i_session->auth_response_encryption_alg)));
    }
    if (i_session->auth_response_encryption_enc != R_JWA_ENC_UNKNOWN) {
      json_object_set_new(j_copy_parameters, "auth_response_encryption_enc", json_string(r_jwa_enc_to_str(i_session->auth_response_encryption_enc)));
    }
    if (i_session->ciba_mode == I_CIBA_MODE_POLL) {
      json_object_set_new(j_copy_parameters, "backchannel_token_delivery_mode", json_string("poll"));
    }
    if (i_session->ciba_mode == I_CIBA_MODE_PING) {
      json_object_set_new(j_copy_parameters, "backchannel_token_delivery_mode", json_string("ping"));
    }
    if (i_session->ciba_mode == I_CIBA_MODE_PUSH) {
      json_object_set_new(j_copy_parameters, "backchannel_token_delivery_mode", json_string("push"));
    }
    if (i_session->ciba_client_notification_endpoint != NULL) {
      json_object_set_new(j_copy_parameters, "backchannel_client_notification_endpoint", json_string(i_session->ciba_client_notification_endpoint));
    }
    if (i_session->frontchannel_logout_uri != NULL) {
      json_object_set_new(j_copy_parameters, "frontchannel_logout_uri", json_string(i_session->frontchannel_logout_uri));
      json_object_set_new(j_copy_parameters, "frontchannel_logout_session_required", i_session->frontchannel_logout_session_required?json_true():json_false());
    }
    if (i_session->backchannel_logout_uri != NULL) {
      json_object_set_new(j_copy_parameters, "backchannel_logout_uri", json_string(i_session->backchannel_logout_uri));
      json_object_set_new(j_copy_parameters, "backchannel_logout_session_required", i_session->backchannel_logout_session_required?json_true():json_false());
    }
    if (_i_init_request(i_session, &request) != U_OK || ulfius_init_response(&response) != U_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_manage_registration_client - Error initializing request or response");
      ret = I_ERROR;
    } else {
      ret = I_OK;
      if (ulfius_set_request_properties(&request, U_OPT_HTTP_VERB, "PUT",
                                                  U_OPT_HTTP_URL, i_session->registration_endpoint,
                                                  U_OPT_HTTP_URL_APPEND, "/",
                                                  U_OPT_HTTP_URL_APPEND, i_session->client_id,
                                                  U_OPT_HEADER_PARAMETER, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR,
                                                  U_OPT_JSON_BODY, j_copy_parameters,
                                                  U_OPT_NONE) != U_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_manage_registration_client - Error setting parameters");
        ret = I_ERROR;
      }
      if (o_strlen(i_session->access_token)) {
        bearer = msprintf("Bearer %s", i_session->access_token);
        if (ulfius_set_request_properties(&request, U_OPT_HEADER_PARAMETER, "Authorization", bearer, U_OPT_NONE) != U_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_manage_registration_client - Error setting bearer token");
          ret = I_ERROR;
        }
        o_free(bearer);
      }
      if (ret == I_OK) {
        if (ulfius_send_http_request(&request, &response) == U_OK) {
          j_response = ulfius_get_json_body_response(&response, NULL);
          if (response.status == 200) {
            if (update_session) {
              i_set_str_parameter(i_session, I_OPT_CLIENT_ID, json_string_value(json_object_get(j_response, "client_id")));
              i_set_str_parameter(i_session, I_OPT_CLIENT_SECRET, json_string_value(json_object_get(j_response, "client_secret")));
              i_set_str_parameter(i_session, I_OPT_REDIRECT_URI, json_string_value(json_array_get(json_object_get(j_response, "redirect_uris"), 0)));
            }
            if (j_result != NULL) {
              *j_result = json_incref(j_response);
            }
          } else if (response.status == 404) {
            ret = I_ERROR_PARAM;
          } else if (response.status == 400) {
            if (_i_parse_error_response(i_session, j_response) != I_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_manage_registration_client - Error _i_parse_error_response (1)");
            }
            ret = I_ERROR_PARAM;
          } else if (response.status == 401 || response.status == 403) {
            if (_i_parse_error_response(i_session, j_response) != I_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_manage_registration_client - Error _i_parse_error_response (1)");
            }
            ret = I_ERROR_UNAUTHORIZED;
          } else if (response.status != 200) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_manage_registration_client - Error registering client");
            ret = I_ERROR;
          }
          json_decref(j_response);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_manage_registration_client - Error sending http request");
          ret = I_ERROR;
        }
      }
      ulfius_clean_request(&request);
      ulfius_clean_response(&response);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "i_manage_registration_client - Invalid parameters");
    ret = I_ERROR_PARAM;
  }
  json_decref(j_copy_parameters);
  return ret;
}

json_t * i_export_session_json_t(struct _i_session * i_session) {
  json_t * j_return = NULL;
  if (i_session != NULL) {
    j_return = json_pack("{ si ss* ss* ss* ss*  ss* ss* ss* ss* ss*  so so ss* ss* ss*  ss* si ss* ss* ss*  ss* ss* ss* ss* si  si ss* sO*  si si so* si sO*  so ss* ss* ss* ss* ss* ss* ss* ss* si  ss* ss* ss* ss* ss* sO  ss* ss* ss* ss* ss*  si si ss* ss* ss*  so si ss* ss* ss*  sO* so ss* so so  so ss* so* ss* ss*  si ss* si sO* ss*  ss* ss* ss*  ss* ss* ss*  ss* ss* ss*  ss* ss* ss*  ss* ss* ss*  ss* ss* ss*  ss* ss* ss*  ss* si ss* ss* si  ss* ss* ss* ss* ss*  si si ss* si ss*  si ss* ss* }",

                         "response_type", i_get_int_parameter(i_session, I_OPT_RESPONSE_TYPE),
                         "scope", i_get_str_parameter(i_session, I_OPT_SCOPE),
                         "state", i_get_str_parameter(i_session, I_OPT_STATE),
                         "nonce", i_get_str_parameter(i_session, I_OPT_NONCE),
                         "redirect_uri", i_get_str_parameter(i_session, I_OPT_REDIRECT_URI),

                         "redirect_to", i_get_str_parameter(i_session, I_OPT_REDIRECT_TO),
                         "client_id", i_get_str_parameter(i_session, I_OPT_CLIENT_ID),
                         "client_secret", i_get_str_parameter(i_session, I_OPT_CLIENT_SECRET),
                         "username", i_get_str_parameter(i_session, I_OPT_USERNAME),
                         "user_password", i_get_str_parameter(i_session, I_OPT_USER_PASSWORD),

                         "additional_parameters", _i_export_u_map(&i_session->additional_parameters),
                         "additional_response", _i_export_u_map(&i_session->additional_response),
                         "authorization_endpoint", i_get_str_parameter(i_session, I_OPT_AUTH_ENDPOINT),
                         "token_endpoint", i_get_str_parameter(i_session, I_OPT_TOKEN_ENDPOINT),
                         "openid_config_endpoint", i_get_str_parameter(i_session, I_OPT_OPENID_CONFIG_ENDPOINT),

                         "userinfo_endpoint", i_get_str_parameter(i_session, I_OPT_USERINFO_ENDPOINT),
                         "result", i_get_int_parameter(i_session, I_OPT_RESULT),
                         "error", i_get_str_parameter(i_session, I_OPT_ERROR),
                         "error_description", i_get_str_parameter(i_session, I_OPT_ERROR_DESCRIPTION),
                         "error_uri", i_get_str_parameter(i_session, I_OPT_ERROR_URI),

                         "code", i_get_str_parameter(i_session, I_OPT_CODE),
                         "refresh_token", i_get_str_parameter(i_session, I_OPT_REFRESH_TOKEN),
                         "access_token", i_get_str_parameter(i_session, I_OPT_ACCESS_TOKEN),
                         "token_type", i_get_str_parameter(i_session, I_OPT_TOKEN_TYPE),
                         "expires_in", i_get_int_parameter(i_session, I_OPT_EXPIRES_IN),

                         "expires_at", i_get_int_parameter(i_session, I_OPT_EXPIRES_AT),
                         "id_token", i_get_str_parameter(i_session, I_OPT_ID_TOKEN),
                         "id_token_payload", i_session->id_token_payload,

                         "auth_method", i_get_int_parameter(i_session, I_OPT_AUTH_METHOD),
                         "token_method", i_get_int_parameter(i_session, I_OPT_TOKEN_METHOD),
                         "server_jwks", r_jwks_export_to_json_t(i_session->server_jwks),
                         "x5u_flags", i_get_int_parameter(i_session, I_OPT_X5U_FLAGS),
                         "openid_config", i_session->openid_config,

                         "openid_config_strict", i_get_int_parameter(i_session, I_OPT_OPENID_CONFIG_STRICT)?json_true():json_false(),
                         "issuer", i_get_str_parameter(i_session, I_OPT_ISSUER),
                         "userinfo", i_get_str_parameter(i_session, I_OPT_USERINFO),
                         "server-kid", i_get_str_parameter(i_session, I_OPT_SERVER_KID),
                         "client-kid", i_get_str_parameter(i_session, I_OPT_CLIENT_KID),

                         "sig-alg", i_get_str_parameter(i_session, I_OPT_CLIENT_SIGN_ALG),
                         "enc-alg", i_get_str_parameter(i_session, I_OPT_CLIENT_ENC_ALG),
                         "enc", i_get_str_parameter(i_session, I_OPT_CLIENT_ENC),
                         "token_jti", i_get_str_parameter(i_session, I_OPT_TOKEN_JTI),
                         "token_exp", i_get_int_parameter(i_session, I_OPT_TOKEN_EXP),

                         "token_target", i_get_str_parameter(i_session, I_OPT_TOKEN_TARGET),
                         "token_target_type_hint", i_get_str_parameter(i_session, I_OPT_TOKEN_TARGET_TYPE_HINT),
                         "revocation_endpoint", i_get_str_parameter(i_session, I_OPT_REVOCATION_ENDPOINT),
                         "introspection_endpoint", i_get_str_parameter(i_session, I_OPT_INTROSPECTION_ENDPOINT),
                         "registration_endpoint", i_get_str_parameter(i_session, I_OPT_REGISTRATION_ENDPOINT),
                         "authorization_details", i_session->j_authorization_details,

                         "device_authorization_endpoint", i_get_str_parameter(i_session, I_OPT_DEVICE_AUTHORIZATION_ENDPOINT),
                         "device_auth_code", i_get_str_parameter(i_session, I_OPT_DEVICE_AUTH_CODE),
                         "device_auth_user_code", i_get_str_parameter(i_session, I_OPT_DEVICE_AUTH_USER_CODE),
                         "device_auth_verification_uri", i_get_str_parameter(i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI),
                         "device_auth_verification_uri_complete", i_get_str_parameter(i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE),

                         "device_auth_expires_in", i_get_int_parameter(i_session, I_OPT_DEVICE_AUTH_EXPIRES_IN),
                         "device_auth_interval", i_get_int_parameter(i_session, I_OPT_DEVICE_AUTH_INTERVAL),
                         "end_session_endpoint", i_get_str_parameter(i_session, I_OPT_END_SESSION_ENDPOINT),
                         "check_session_iframe", i_get_str_parameter(i_session, I_OPT_CHECK_SESSION_IRAME),
                         "pushed_authorization_request_endpoint", i_get_str_parameter(i_session, I_OPT_PUSHED_AUTH_REQ_ENDPOINT),

                         "require_pushed_authorization_requests", i_get_int_parameter(i_session, I_OPT_PUSHED_AUTH_REQ_REQUIRED)?json_true():json_false(),
                         "pushed_authorization_request_expires_in", i_get_int_parameter(i_session, I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN),
                         "pushed_authorization_request_uri", i_get_str_parameter(i_session, I_OPT_PUSHED_AUTH_REQ_URI),
                         "server-enc-alg", i_get_str_parameter(i_session, I_OPT_SERVER_ENC_ALG),
                         "server-enc", i_get_str_parameter(i_session, I_OPT_SERVER_ENC),

                         "access_token_payload", i_session->access_token_payload,
                         "use_dpop", i_get_int_parameter(i_session, I_OPT_USE_DPOP)?json_true():json_false(),
                         "dpop_kid", i_get_str_parameter(i_session, I_OPT_DPOP_KID),
                         "decrypt_code", i_get_int_parameter(i_session, I_OPT_DECRYPT_CODE)?json_true():json_false(),
                         "decrypt_refresh_token", i_get_int_parameter(i_session, I_OPT_DECRYPT_REFRESH_TOKEN)?json_true():json_false(),

                         "decrypt_access_token", i_get_int_parameter(i_session, I_OPT_DECRYPT_ACCESS_TOKEN)?json_true():json_false(),
                         "dpop-sig-alg", i_get_str_parameter(i_session, I_OPT_DPOP_SIGN_ALG),
                         "client_jwks", r_jwks_export_to_json_t(i_session->client_jwks),
                         "key_file", i_get_str_parameter(i_session, I_OPT_TLS_KEY_FILE),
                         "cert_file", i_get_str_parameter(i_session, I_OPT_TLS_CERT_FILE),

                         "remote_cert_flag", i_get_int_parameter(i_session, I_OPT_REMOTE_CERT_FLAG),
                         "pkce_code_verifier", i_get_str_parameter(i_session, I_OPT_PKCE_CODE_VERIFIER),
                         "pkce_method", i_get_int_parameter(i_session, I_OPT_PKCE_METHOD),
                         "claims", i_session->j_claims,
                         "resource_indicator", i_session->resource_indicator,
                         
                         "access_token_signing_alg", i_get_str_parameter(i_session, I_OPT_ACCESS_TOKEN_SIGNING_ALG),
                         "access_token_encryption_alg", i_get_str_parameter(i_session, I_OPT_ACCESS_TOKEN_ENCRYPTION_ALG),
                         "access_token_encryption_enc", i_get_str_parameter(i_session, I_OPT_ACCESS_TOKEN_ENCRYPTION_ENC),
                         
                         "id_token_signing_alg", i_get_str_parameter(i_session, I_OPT_ID_TOKEN_SIGNING_ALG),
                         "id_token_encryption_alg", i_get_str_parameter(i_session, I_OPT_ID_TOKEN_ENCRYPTION_ALG),
                         "id_token_encryption_enc", i_get_str_parameter(i_session, I_OPT_ID_TOKEN_ENCRYPTION_ENC),
                         
                         "userinfo_signing_alg", i_get_str_parameter(i_session, I_OPT_USERINFO_SIGNING_ALG),
                         "userinfo_encryption_alg", i_get_str_parameter(i_session, I_OPT_USERINFO_ENCRYPTION_ALG),
                         "userinfo_encryption_enc", i_get_str_parameter(i_session, I_OPT_USERINFO_ENCRYPTION_ENC),
                         
                         "request_object_signing_alg", i_get_str_parameter(i_session, I_OPT_REQUEST_OBJECT_SIGNING_ALG),
                         "request_object_encryption_alg", i_get_str_parameter(i_session, I_OPT_REQUEST_OBJECT_ENCRYPTION_ALG),
                         "request_object_encryption_enc", i_get_str_parameter(i_session, I_OPT_REQUEST_OBJECT_ENCRYPTION_ENC),
                         
                         "token_endpoint_signing_alg", i_get_str_parameter(i_session, I_OPT_TOKEN_ENDPOINT_SIGNING_ALG),
                         "token_endpoint_encryption_alg", i_get_str_parameter(i_session, I_OPT_TOKEN_ENDPOINT_ENCRYPTION_ALG),
                         "token_endpoint_encryption_enc", i_get_str_parameter(i_session, I_OPT_TOKEN_ENDPOINT_ENCRYPTION_ENC),
                         
                         "ciba_request_signing_alg", i_get_str_parameter(i_session, I_OPT_CIBA_REQUEST_SIGNING_ALG),
                         "ciba_request_encryption_alg", i_get_str_parameter(i_session, I_OPT_CIBA_REQUEST_ENCRYPTION_ALG),
                         "ciba_request_encryption_enc", i_get_str_parameter(i_session, I_OPT_CIBA_REQUEST_ENCRYPTION_ENC),
                         
                         "auth_response_signing_alg", i_get_str_parameter(i_session, I_OPT_AUTH_RESPONSE_SIGNING_ALG),
                         "auth_response_encryption_alg", i_get_str_parameter(i_session, I_OPT_AUTH_RESPONSE_ENCRYPTION_ALG),
                         "auth_response_encryption_enc", i_get_str_parameter(i_session, I_OPT_AUTH_RESPONSE_ENCRYPTION_ENC),
                         
                         "ciba_endpoint", i_get_str_parameter(i_session, I_OPT_CIBA_ENDPOINT),
                         "ciba_mode", i_get_int_parameter(i_session, I_OPT_CIBA_MODE),
                         "ciba_user_code", i_get_str_parameter(i_session, I_OPT_CIBA_USER_CODE),
                         "ciba_login_hint", i_get_str_parameter(i_session, I_OPT_CIBA_LOGIN_HINT),
                         "ciba_login_hint_format", i_get_int_parameter(i_session, I_OPT_CIBA_LOGIN_HINT_FORMAT),
                         
                         "ciba_binding_message", i_get_str_parameter(i_session, I_OPT_CIBA_BINDING_MESSAGE),
                         "ciba_client_notification_token", i_get_str_parameter(i_session, I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN),
                         "ciba_auth_req_id", i_get_str_parameter(i_session, I_OPT_CIBA_AUTH_REQ_ID),
                         "ciba_login_hint_kid", i_get_str_parameter(i_session, I_OPT_CIBA_LOGIN_HINT_KID),
                         "ciba_client_notification_endpoint", i_get_str_parameter(i_session, I_OPT_CIBA_CLIENT_NOTIFICATION_ENDPOINT),
                         
                         "ciba_auth_req_expires_in", i_get_int_parameter(i_session, I_OPT_CIBA_AUTH_REQ_EXPIRES_IN),
                         "ciba_auth_req_interval", i_get_int_parameter(i_session, I_OPT_CIBA_AUTH_REQ_INTERVAL),
                         "frontchannel_logout_uri", i_get_str_parameter(i_session, I_OPT_FRONTCHANNEL_LOGOUT_URI),
                         "frontchannel_logout_session_required", i_get_int_parameter(i_session, I_OPT_FRONTCHANNEL_LOGOUT_SESSION_REQUIRED),
                         "backchannel_logout_uri", i_get_str_parameter(i_session, I_OPT_BACKCHANNEL_LOGOUT_URI),
                         
                         "backchannel_logout_session_required", i_get_int_parameter(i_session, I_OPT_BACKCHANNEL_LOGOUT_SESSION_REQUIRED),
                         "post_logout_redirect_uri", i_get_str_parameter(i_session, I_OPT_POST_LOGOUT_REDIRECT_URI),
                         "id_token_sid", i_get_str_parameter(i_session, I_OPT_ID_TOKEN_SID)
                         );
  }
  return j_return;
}

int i_import_session_json_t(struct _i_session * i_session, json_t * j_import) {
  int ret;
  const char * key = NULL;
  json_t * j_value = NULL;
  char * tmp;

  if (i_session != NULL && json_is_object(j_import)) {
    if ((ret = i_set_parameter_list(i_session,
                                     I_OPT_RESPONSE_TYPE, (int)json_integer_value(json_object_get(j_import, "response_type")),
                                     I_OPT_SCOPE, json_string_value(json_object_get(j_import, "scope")),
                                     I_OPT_STATE, json_string_value(json_object_get(j_import, "state")),
                                     I_OPT_NONCE, json_string_value(json_object_get(j_import, "nonce")),
                                     I_OPT_REDIRECT_URI, json_string_value(json_object_get(j_import, "redirect_uri")),
                                     I_OPT_REDIRECT_TO, json_string_value(json_object_get(j_import, "redirect_to")),
                                     I_OPT_CLIENT_ID, json_string_value(json_object_get(j_import, "client_id")),
                                     I_OPT_CLIENT_SECRET, json_string_value(json_object_get(j_import, "client_secret")),
                                     I_OPT_AUTH_ENDPOINT, json_string_value(json_object_get(j_import, "authorization_endpoint")),
                                     I_OPT_TOKEN_ENDPOINT, json_string_value(json_object_get(j_import, "token_endpoint")),
                                     I_OPT_OPENID_CONFIG_ENDPOINT, json_string_value(json_object_get(j_import, "openid_config_endpoint")),
                                     I_OPT_USERINFO_ENDPOINT, json_string_value(json_object_get(j_import, "userinfo_endpoint")),
                                     I_OPT_RESULT, (int)json_integer_value(json_object_get(j_import, "result")),
                                     I_OPT_ERROR, json_string_value(json_object_get(j_import, "error")),
                                     I_OPT_ERROR_DESCRIPTION, json_string_value(json_object_get(j_import, "error_description")),
                                     I_OPT_ERROR_URI, json_string_value(json_object_get(j_import, "error_uri")),
                                     I_OPT_CODE, json_string_value(json_object_get(j_import, "code")),
                                     I_OPT_REFRESH_TOKEN, json_string_value(json_object_get(j_import, "refresh_token")),
                                     I_OPT_ACCESS_TOKEN, json_string_value(json_object_get(j_import, "access_token")),
                                     I_OPT_TOKEN_TYPE, json_string_value(json_object_get(j_import, "token_type")),
                                     I_OPT_EXPIRES_IN, (int)json_integer_value(json_object_get(j_import, "expires_in")),
                                     I_OPT_EXPIRES_AT, (int)json_integer_value(json_object_get(j_import, "expires_at")),
                                     I_OPT_ID_TOKEN, json_string_value(json_object_get(j_import, "id_token")),
                                     I_OPT_USERNAME, json_string_value(json_object_get(j_import, "username")),
                                     I_OPT_AUTH_METHOD, (int)json_integer_value(json_object_get(j_import, "auth_method")),
                                     I_OPT_TOKEN_METHOD, (int)json_integer_value(json_object_get(j_import, "token_method")),
                                     I_OPT_USER_PASSWORD, json_string_value(json_object_get(j_import, "user_password")),
                                     I_OPT_X5U_FLAGS, (int)json_integer_value(json_object_get(j_import, "x5u_flags")),
                                     I_OPT_OPENID_CONFIG_STRICT, json_object_get(j_import, "openid_config_strict")==json_true(),
                                     I_OPT_ISSUER, json_string_value(json_object_get(j_import, "issuer")),
                                     I_OPT_USERINFO, json_string_value(json_object_get(j_import, "userinfo")),
                                     I_OPT_SERVER_KID, json_string_value(json_object_get(j_import, "server-kid")),
                                     I_OPT_SERVER_ENC_ALG, json_string_value(json_object_get(j_import, "server-enc-alg")),
                                     I_OPT_SERVER_ENC, json_string_value(json_object_get(j_import, "server-enc")),
                                     I_OPT_CLIENT_KID, json_string_value(json_object_get(j_import, "client-kid")),
                                     I_OPT_CLIENT_SIGN_ALG, json_string_value(json_object_get(j_import, "sig-alg")),
                                     I_OPT_CLIENT_ENC_ALG, json_string_value(json_object_get(j_import, "enc-alg")),
                                     I_OPT_CLIENT_ENC, json_string_value(json_object_get(j_import, "enc")),
                                     I_OPT_TOKEN_JTI, json_string_value(json_object_get(j_import, "token_jti")),
                                     I_OPT_TOKEN_EXP, (int)json_integer_value(json_object_get(j_import, "token_exp")),
                                     I_OPT_TOKEN_TARGET, json_string_value(json_object_get(j_import, "token_target")),
                                     I_OPT_TOKEN_TARGET_TYPE_HINT, json_string_value(json_object_get(j_import, "token_target_type_hint")),
                                     I_OPT_REVOCATION_ENDPOINT, json_string_value(json_object_get(j_import, "revocation_endpoint")),
                                     I_OPT_INTROSPECTION_ENDPOINT, json_string_value(json_object_get(j_import, "introspection_endpoint")),
                                     I_OPT_REGISTRATION_ENDPOINT, json_string_value(json_object_get(j_import, "registration_endpoint")),
                                     I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, json_string_value(json_object_get(j_import, "device_authorization_endpoint")),
                                     I_OPT_DEVICE_AUTH_CODE, json_string_value(json_object_get(j_import, "device_auth_code")),
                                     I_OPT_DEVICE_AUTH_USER_CODE, json_string_value(json_object_get(j_import, "device_auth_user_code")),
                                     I_OPT_DEVICE_AUTH_VERIFICATION_URI, json_string_value(json_object_get(j_import, "device_auth_verification_uri")),
                                     I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE, json_string_value(json_object_get(j_import, "device_auth_verification_uri_complete")),
                                     I_OPT_DEVICE_AUTH_EXPIRES_IN, (int)json_integer_value(json_object_get(j_import, "device_auth_expires_in")),
                                     I_OPT_DEVICE_AUTH_INTERVAL, (int)json_integer_value(json_object_get(j_import, "device_auth_interval")),
                                     I_OPT_END_SESSION_ENDPOINT, json_string_value(json_object_get(j_import, "end_session_endpoint")),
                                     I_OPT_CHECK_SESSION_IRAME, json_string_value(json_object_get(j_import, "check_session_iframe")),
                                     I_OPT_PUSHED_AUTH_REQ_ENDPOINT, json_string_value(json_object_get(j_import, "pushed_authorization_request_endpoint")),
                                     I_OPT_PUSHED_AUTH_REQ_REQUIRED, json_object_get(j_import, "require_pushed_authorization_requests")==json_true(),
                                     I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN, (int)json_integer_value(json_object_get(j_import, "pushed_authorization_request_expires_in")),
                                     I_OPT_PUSHED_AUTH_REQ_URI, json_string_value(json_object_get(j_import, "pushed_authorization_request_uri")),
                                     I_OPT_USE_DPOP, json_object_get(j_import, "use_dpop")==json_true(),
                                     I_OPT_DPOP_KID, json_string_value(json_object_get(j_import, "dpop_kid")),
                                     I_OPT_DPOP_SIGN_ALG, json_string_value(json_object_get(j_import, "dpop-sig-alg")),
                                     I_OPT_DECRYPT_CODE, json_object_get(j_import, "decrypt_code")==json_true(),
                                     I_OPT_DECRYPT_REFRESH_TOKEN, json_object_get(j_import, "decrypt_refresh_token")==json_true(),
                                     I_OPT_DECRYPT_ACCESS_TOKEN, json_object_get(j_import, "decrypt_access_token")==json_true(),
                                     I_OPT_TLS_KEY_FILE, json_string_value(json_object_get(j_import, "key_file")),
                                     I_OPT_TLS_CERT_FILE, json_string_value(json_object_get(j_import, "cert_file")),
                                     I_OPT_REMOTE_CERT_FLAG, (int)json_integer_value(json_object_get(j_import, "remote_cert_flag")),
                                     I_OPT_PKCE_CODE_VERIFIER, json_string_value(json_object_get(j_import, "pkce_code_verifier")),
                                     I_OPT_PKCE_METHOD, (int)json_integer_value(json_object_get(j_import, "pkce_method")),
                                     I_OPT_RESOURCE_INDICATOR, json_string_value(json_object_get(j_import, "resource_indicator")),
                                     I_OPT_ACCESS_TOKEN_SIGNING_ALG, json_string_value(json_object_get(j_import, "access_token_signing_alg")),
                                     I_OPT_ACCESS_TOKEN_ENCRYPTION_ALG, json_string_value(json_object_get(j_import, "access_token_encryption_alg")),
                                     I_OPT_ACCESS_TOKEN_ENCRYPTION_ENC, json_string_value(json_object_get(j_import, "access_token_encryption_enc")),
                                     I_OPT_ID_TOKEN_SIGNING_ALG, json_string_value(json_object_get(j_import, "id_token_signing_alg")),
                                     I_OPT_ID_TOKEN_ENCRYPTION_ALG, json_string_value(json_object_get(j_import, "id_token_encryption_alg")),
                                     I_OPT_ID_TOKEN_ENCRYPTION_ENC, json_string_value(json_object_get(j_import, "id_token_encryption_enc")),
                                     I_OPT_USERINFO_SIGNING_ALG, json_string_value(json_object_get(j_import, "userinfo_signing_alg")),
                                     I_OPT_USERINFO_ENCRYPTION_ALG, json_string_value(json_object_get(j_import, "userinfo_encryption_alg")),
                                     I_OPT_USERINFO_ENCRYPTION_ENC, json_string_value(json_object_get(j_import, "userinfo_encryption_enc")),
                                     I_OPT_REQUEST_OBJECT_SIGNING_ALG, json_string_value(json_object_get(j_import, "request_object_signing_alg")),
                                     I_OPT_REQUEST_OBJECT_ENCRYPTION_ALG, json_string_value(json_object_get(j_import, "request_object_encryption_alg")),
                                     I_OPT_REQUEST_OBJECT_ENCRYPTION_ENC, json_string_value(json_object_get(j_import, "request_object_encryption_enc")),
                                     I_OPT_TOKEN_ENDPOINT_SIGNING_ALG, json_string_value(json_object_get(j_import, "token_endpoint_signing_alg")),
                                     I_OPT_TOKEN_ENDPOINT_ENCRYPTION_ALG, json_string_value(json_object_get(j_import, "token_endpoint_encryption_alg")),
                                     I_OPT_TOKEN_ENDPOINT_ENCRYPTION_ENC, json_string_value(json_object_get(j_import, "token_endpoint_encryption_enc")),
                                     I_OPT_CIBA_REQUEST_SIGNING_ALG, json_string_value(json_object_get(j_import, "ciba_request_signing_alg")),
                                     I_OPT_CIBA_REQUEST_ENCRYPTION_ALG, json_string_value(json_object_get(j_import, "ciba_request_encryption_alg")),
                                     I_OPT_CIBA_REQUEST_ENCRYPTION_ENC, json_string_value(json_object_get(j_import, "ciba_request_encryption_enc")),
                                     I_OPT_AUTH_RESPONSE_SIGNING_ALG, json_string_value(json_object_get(j_import, "auth_response_signing_alg")),
                                     I_OPT_AUTH_RESPONSE_ENCRYPTION_ALG, json_string_value(json_object_get(j_import, "auth_response_encryption_alg")),
                                     I_OPT_AUTH_RESPONSE_ENCRYPTION_ENC, json_string_value(json_object_get(j_import, "auth_response_encryption_enc")),
                                     I_OPT_CIBA_ENDPOINT, json_string_value(json_object_get(j_import, "ciba_endpoint")),
                                     I_OPT_CIBA_MODE, (int)json_integer_value(json_object_get(j_import, "ciba_mode")),
                                     I_OPT_CIBA_USER_CODE, json_string_value(json_object_get(j_import, "ciba_user_code")),
                                     I_OPT_CIBA_LOGIN_HINT, json_string_value(json_object_get(j_import, "ciba_login_hint")),
                                     I_OPT_CIBA_LOGIN_HINT_FORMAT, (int)json_integer_value(json_object_get(j_import, "ciba_login_hint_format")),
                                     I_OPT_CIBA_LOGIN_HINT_KID, json_string_value(json_object_get(j_import, "ciba_login_hint_kid")),
                                     I_OPT_CIBA_BINDING_MESSAGE, json_string_value(json_object_get(j_import, "ciba_binding_message")),
                                     I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN, json_string_value(json_object_get(j_import, "ciba_client_notification_token")),
                                     I_OPT_CIBA_AUTH_REQ_ID, json_string_value(json_object_get(j_import, "ciba_auth_req_id")),
                                     I_OPT_CIBA_CLIENT_NOTIFICATION_ENDPOINT, json_string_value(json_object_get(j_import, "ciba_client_notification_endpoint")),
                                     I_OPT_CIBA_AUTH_REQ_EXPIRES_IN, (int)json_integer_value(json_object_get(j_import, "ciba_auth_req_expires_in")),
                                     I_OPT_CIBA_AUTH_REQ_INTERVAL, (int)json_integer_value(json_object_get(j_import, "ciba_auth_req_interval")),
                                     I_OPT_FRONTCHANNEL_LOGOUT_URI, json_string_value(json_object_get(j_import, "frontchannel_logout_uri")),
                                     I_OPT_FRONTCHANNEL_LOGOUT_SESSION_REQUIRED, (int)json_integer_value(json_object_get(j_import, "frontchannel_logout_session_required")),
                                     I_OPT_BACKCHANNEL_LOGOUT_URI, json_string_value(json_object_get(j_import, "backchannel_logout_uri")),
                                     I_OPT_BACKCHANNEL_LOGOUT_SESSION_REQUIRED, (int)json_integer_value(json_object_get(j_import, "backchannel_logout_session_required")),
                                     I_OPT_POST_LOGOUT_REDIRECT_URI, json_string_value(json_object_get(j_import, "post_logout_redirect_uri")),
                                     I_OPT_ID_TOKEN_SID, json_string_value(json_object_get(j_import, "id_token_sid")),
                                     I_OPT_NONE)) == I_OK) {
      json_object_foreach(json_object_get(j_import, "additional_parameters"), key, j_value) {
        if ((ret = i_set_additional_parameter(i_session, key, json_string_value(j_value))) != I_OK) {
          tmp = json_dumps(j_value, JSON_COMPACT);
          y_log_message(Y_LOG_LEVEL_DEBUG, "i_import_session_json_t - Error importing additional_parameters '%s' / '%s'", key, tmp);
          o_free(tmp);
          return ret;
        }
      }
      json_object_foreach(json_object_get(j_import, "additional_response"), key, j_value) {
        if ((ret = i_set_additional_response(i_session, key, json_string_value(j_value))) != I_OK) {
          tmp = json_dumps(j_value, JSON_COMPACT);
          y_log_message(Y_LOG_LEVEL_DEBUG, "i_import_session_json_t - Error importing additional_response '%s' / '%s'", key, tmp);
          o_free(tmp);
          return ret;
        }
      }
      json_decref(i_session->id_token_payload);
      i_session->id_token_payload = json_deep_copy(json_object_get(j_import, "id_token_payload"));
      json_decref(i_session->access_token_payload);
      i_session->access_token_payload = json_deep_copy(json_object_get(j_import, "access_token_payload"));
      json_decref(i_session->openid_config);
      i_session->openid_config = json_deep_copy(json_object_get(j_import, "openid_config"));
      if (json_object_get(j_import, "server_jwks") != NULL && (r_jwks_empty(i_session->server_jwks) != RHN_OK || r_jwks_import_from_json_t(i_session->server_jwks, json_object_get(j_import, "server_jwks")) != RHN_OK)) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "i_import_session_json_t - Error r_jwks_import_from_json_t server_jwks");
        ret = I_ERROR;
      }
      if (json_object_get(j_import, "client_jwks") != NULL && (r_jwks_empty(i_session->client_jwks) != RHN_OK || r_jwks_import_from_json_t(i_session->client_jwks, json_object_get(j_import, "client_jwks")) != RHN_OK)) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "i_import_session_json_t - Error r_jwks_import_from_json_t client_jwks");
        ret = I_ERROR;
      }
      json_decref(i_session->j_claims);
      if (json_object_get(j_import, "claims") != NULL) {
        i_session->j_claims = json_deep_copy(json_object_get(j_import, "claims"));
      } else {
        i_session->j_claims = json_pack("{s{}s{}}", "userinfo", "id_token");
      }
      json_array_extend(i_session->j_authorization_details, json_object_get(j_import, "authorization_details"));
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "i_import_session_json_t - Error i_set_parameter_list");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "i_import_session_json_t - Invalid input parameters");
    ret = I_ERROR_PARAM;
  }
  return ret;
}

char * i_export_session_str(struct _i_session * i_session) {
  json_t * j_export = i_export_session_json_t(i_session);
  char * out = NULL;

  if (j_export != NULL) {
    out = json_dumps(j_export, JSON_COMPACT);
    json_decref(j_export);
  }
  return out;
}

int i_import_session_str(struct _i_session * i_session, const char * str_import) {
  json_t * j_import;
  int ret;

  if (o_strlen(str_import)) {
    j_import = json_loads(str_import, JSON_DECODE_ANY, NULL);
    if (j_import != NULL) {
      ret = i_import_session_json_t(i_session, j_import);
    } else {
      ret = I_ERROR;
    }
    json_decref(j_import);
  } else {
    ret = I_ERROR_PARAM;
  }
  return ret;
}

char * i_generate_dpop_token(struct _i_session * i_session, const char * htm, const char * htu, time_t iat, int add_ath) {
  char * token = NULL;
  jwt_t * jwt_dpop = NULL;
  jwk_t * jwk_sign = NULL, * jwk_pub = NULL;
  json_t * j_dpop_pub = NULL;
  int has_error = 0;
  const char * kid;
  unsigned char ath[32] = {0}, ath_enc[64] = {0};
  size_t ath_len = 32, ath_enc_len = 64;
  gnutls_datum_t hash_data;

  if (i_session != NULL && o_strlen(i_session->token_jti) && o_strlen(htu) && o_strlen(htm)) {
    kid = i_session->dpop_kid!=NULL?i_session->dpop_kid:i_session->client_kid;
    if (r_jwt_init(&jwt_dpop) == RHN_OK) {
      if ((kid != NULL && (jwk_sign = r_jwks_get_by_kid(i_session->client_jwks, kid)) != NULL) ||
          (r_jwks_size(i_session->client_jwks) == 1 && (jwk_sign = r_jwks_get_at(i_session->client_jwks, 0)) != NULL)) {
        if ((i_session->dpop_sign_alg == R_JWA_ALG_RS256 || i_session->dpop_sign_alg == R_JWA_ALG_RS384 || i_session->dpop_sign_alg == R_JWA_ALG_RS512 ||
             i_session->dpop_sign_alg == R_JWA_ALG_PS256 || i_session->dpop_sign_alg == R_JWA_ALG_PS384 || i_session->dpop_sign_alg == R_JWA_ALG_PS512)) {
          if (!(r_jwk_key_type(jwk_sign, NULL, i_session->x5u_flags) & (R_KEY_TYPE_RSA|R_KEY_TYPE_PRIVATE))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_generate_dpop_token - Invalid signing key type");
            has_error = 1;
          }
        } else if (i_session->dpop_sign_alg == R_JWA_ALG_ES256 || i_session->dpop_sign_alg == R_JWA_ALG_ES384 || i_session->dpop_sign_alg == R_JWA_ALG_ES512) {
          if (!(r_jwk_key_type(jwk_sign, NULL, i_session->x5u_flags) & (R_KEY_TYPE_EC|R_KEY_TYPE_PRIVATE))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_generate_dpop_token - Invalid signing key type");
            has_error = 1;
          }
        } else if (i_session->dpop_sign_alg == R_JWA_ALG_EDDSA) {
          if (!(r_jwk_key_type(jwk_sign, NULL, i_session->x5u_flags) & (R_KEY_TYPE_EDDSA|R_KEY_TYPE_PRIVATE))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_generate_dpop_token - Invalid signing key type");
            has_error = 1;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_generate_dpop_token - Invalid signing key parameters");
          has_error = 1;
        }
      } else if (!r_jwks_size(i_session->client_jwks)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_generate_dpop_token - Client has no private key ");
        has_error = 1;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_generate_dpop_token - Client has more than one private key, please specify one with the parameter I_OPT_CLIENT_KID");
        has_error = 1;
      }
      if (jwk_sign != NULL) {
        r_jwt_set_sign_alg(jwt_dpop, i_session->dpop_sign_alg);
        if (r_jwk_init(&jwk_pub) == RHN_OK) {
          if (r_jwk_extract_pubkey(jwk_sign, jwk_pub, i_session->x5u_flags) == RHN_OK) {
            if ((j_dpop_pub = r_jwk_export_to_json_t(jwk_pub)) != NULL) {
              if (add_ath) {
                if (i_get_str_parameter(i_session, I_OPT_ACCESS_TOKEN) != NULL) {
                  hash_data.data = (unsigned char*)i_get_str_parameter(i_session, I_OPT_ACCESS_TOKEN);
                  hash_data.size = o_strlen(i_get_str_parameter(i_session, I_OPT_ACCESS_TOKEN));
                  if (gnutls_fingerprint(GNUTLS_DIG_SHA256, &hash_data, ath, &ath_len) == GNUTLS_E_SUCCESS) {
                    if (!o_base64url_encode(ath, ath_len, ath_enc, &ath_enc_len)) {
                      y_log_message(Y_LOG_LEVEL_ERROR, "i_generate_dpop_token - Error o_base64url_encode ath");
                      has_error = 1;
                    }
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_generate_dpop_token - Error gnutls_fingerprint");
                    has_error = 1;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "i_generate_dpop_token - access token missing");
                  has_error = 1;
                }
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_generate_dpop_token - Error r_jwk_export_to_json_t");
              has_error = 1;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_generate_dpop_token - Error r_jwk_extract_pubkey");
            has_error = 1;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_generate_dpop_token - Error r_jwk_init");
          has_error = 1;
        }
        r_jwk_free(jwk_pub);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_generate_dpop_token - Client has no signing key");
        has_error = 1;
      }
      if (!has_error) {
        r_jwt_set_claim_str_value(jwt_dpop, "jti", i_session->token_jti);
        r_jwt_set_claim_str_value(jwt_dpop, "htu", htu);
        r_jwt_set_claim_str_value(jwt_dpop, "htm", htm);
        r_jwt_set_header_str_value(jwt_dpop, "typ", "dpop+jwt");
        if (iat) {
          r_jwt_set_claim_int_value(jwt_dpop, "iat", iat);
        } else {
          r_jwt_set_claim_int_value(jwt_dpop, "iat", time(NULL));
        }
        if (add_ath) {
          r_jwt_set_claim_str_value(jwt_dpop, "ath", (const char *)ath_enc);
        }
        r_jwt_set_header_json_t_value(jwt_dpop, "jwk", j_dpop_pub);
        token = r_jwt_serialize_signed(jwt_dpop, jwk_sign, i_session->x5u_flags);
      }
      r_jwk_free(jwk_sign);
      json_decref(j_dpop_pub);
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "i_generate_dpop_token - Error r_jwt_init");
    }
    r_jwt_free(jwt_dpop);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "i_generate_dpop_token - Error input parameters");
  }
  return token;
}

int i_perform_resource_service_request(struct _i_session * i_session, struct _u_request * http_request, struct _u_response * http_response, int refresh_if_expired, int bearer_type, int use_dpop, time_t dpop_iat) {
  int ret = I_OK, reset_resp_type = 0;
  unsigned int cur_resp_type;
  char * dpop_token = NULL, * auth_header;
  struct _u_request copy_req;

  if (i_session != NULL && http_request != NULL && i_get_str_parameter(i_session, I_OPT_ACCESS_TOKEN) != NULL) {
    if (refresh_if_expired) {
      // Refresh access token if expired
      if (time(NULL) > (time_t)i_get_int_parameter(i_session, I_OPT_EXPIRES_AT)) {
        reset_resp_type = 1;
        cur_resp_type = i_get_response_type(i_session);
        i_set_response_type(i_session, I_RESPONSE_TYPE_REFRESH_TOKEN);
        if ((ret = i_run_token_request(i_session)) != I_OK) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "i_perform_resource_service_request - Error refresh access token");
        }
      }
    }
    if (I_OK == ret) {
      if (ulfius_init_request(&copy_req) == U_OK) {
        if (ulfius_copy_request(&copy_req, http_request) == U_OK) {
          // Set access token
          switch (bearer_type) {
            case I_BEARER_TYPE_HEADER:
              auth_header = msprintf("%s%s", I_HEADER_PREFIX_BEARER, i_get_str_parameter(i_session, I_OPT_ACCESS_TOKEN));
              if (ulfius_set_request_properties(&copy_req, U_OPT_HEADER_PARAMETER, I_HEADER_AUTHORIZATION, auth_header, U_OPT_NONE) != U_OK) {
                y_log_message(Y_LOG_LEVEL_DEBUG, "i_perform_resource_service_request - Error setting access_token in header");
                ret = I_ERROR;
              }
              o_free(auth_header);
              break;
            case I_BEARER_TYPE_BODY:
              if (ulfius_set_request_properties(&copy_req, U_OPT_POST_BODY_PARAMETER, I_BODY_URL_PARAMETER, i_get_str_parameter(i_session, I_OPT_ACCESS_TOKEN), U_OPT_NONE) != U_OK) {
                y_log_message(Y_LOG_LEVEL_DEBUG, "i_perform_resource_service_request - Error setting access_token in body");
                ret = I_ERROR;
              }
              break;
            case I_BEARER_TYPE_URL:
              if (ulfius_set_request_properties(&copy_req, U_OPT_URL_PARAMETER, I_BODY_URL_PARAMETER, i_get_str_parameter(i_session, I_OPT_ACCESS_TOKEN), U_OPT_NONE) != U_OK) {
                y_log_message(Y_LOG_LEVEL_DEBUG, "i_perform_resource_service_request - Error setting access_token in url");
                ret = I_ERROR;
              }
              break;
            default:
              y_log_message(Y_LOG_LEVEL_DEBUG, "i_perform_resource_service_request - Invalid bearer_type");
              ret = I_ERROR_PARAM;
              break;
          }
          // Set DPoP
          if (use_dpop) {
            if (I_OK == ret) {
              if ((dpop_token = i_generate_dpop_token(i_session, copy_req.http_verb, copy_req.http_url, dpop_iat, 1)) != NULL) {
                if (ulfius_set_request_properties(&copy_req, U_OPT_HEADER_PARAMETER, I_HEADER_DPOP, dpop_token, U_OPT_NONE) != U_OK) {
                  y_log_message(Y_LOG_LEVEL_DEBUG, "i_perform_resource_service_request - Error setting DPoP in header");
                  ret = I_ERROR;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_DEBUG, "i_perform_resource_service_request - Error i_generate_dpop_token");
                ret = I_ERROR;
              }
              o_free(dpop_token);
            }
          }
          // Perform HTTP request
          if (I_OK == ret) {
            ulfius_set_request_properties(&copy_req, U_OPT_HEADER_PARAMETER, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR, U_OPT_NONE);
            if (ulfius_send_http_request(&copy_req, http_response) != U_OK) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "i_perform_resource_service_request - Error ulfius_send_http_request");
              ret = I_ERROR;
            }
          }
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "i_perform_resource_service_request - Error ulfius_copy_request");
          ret = I_ERROR;
        }
        ulfius_clean_request(&copy_req);
      } else {
        y_log_message(Y_LOG_LEVEL_DEBUG, "i_perform_resource_service_request - Error ulfius_init_request");
        ret = I_ERROR;
      }
    }
    if (reset_resp_type && cur_resp_type != I_RESPONSE_TYPE_NONE) {
      i_set_response_type(i_session, cur_resp_type);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "i_perform_resource_service_request - Error input parameters");
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_verify_dpop_proof(const char * dpop_header, const char * htm, const char * htu, time_t max_iat, const char * jkt, const char * access_token) {
  json_t * j_header = NULL;
  jwt_t * dpop_jwt = NULL;
  jwa_alg alg;
  jwk_t * jwk_header = NULL;
  char * jkt_from_token = NULL;
  time_t now;
  int ret;
  unsigned char ath[32] = {0}, ath_enc[64] = {0};
  size_t ath_len = 32, ath_enc_len = 64;
  gnutls_datum_t hash_data;
  
  if (r_jwt_init(&dpop_jwt) == RHN_OK) {
    if (r_jwt_advanced_parse(dpop_jwt, dpop_header, R_PARSE_HEADER_JWK, R_FLAG_IGNORE_REMOTE) == RHN_OK) {
      if (r_jwt_verify_signature(dpop_jwt, NULL, R_FLAG_IGNORE_REMOTE) == RHN_OK) {
        ret = I_OK;
        do {
          if (0 != o_strcmp("dpop+jwt", r_jwt_get_header_str_value(dpop_jwt, "typ"))) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_dpop_proof - Invalid typ");
            ret = I_ERROR_UNAUTHORIZED;
            break;
          }
          if ((alg = r_jwt_get_sign_alg(dpop_jwt)) != R_JWA_ALG_RS256 && alg != R_JWA_ALG_RS384 && alg != R_JWA_ALG_RS512 &&
              alg != R_JWA_ALG_ES256 && alg != R_JWA_ALG_ES384 && alg != R_JWA_ALG_ES512 && 
              alg != R_JWA_ALG_PS256 && alg != R_JWA_ALG_PS384 && alg != R_JWA_ALG_PS512 &&
              alg != R_JWA_ALG_EDDSA && alg != R_JWA_ALG_ES256K) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_dpop_proof - Invalid sign_alg");
            ret = I_ERROR_UNAUTHORIZED;
            break;
          }
          if ((j_header = r_jwt_get_full_header_json_t(dpop_jwt)) == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_dpop_proof - Error r_jwt_get_full_header_json_t");
            ret = I_ERROR;
            break;
          }
          if (json_object_get(j_header, "x5c") != NULL || json_object_get(j_header, "x5u") != NULL) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_dpop_proof - Invalid header, x5c or x5u present");
            ret = I_ERROR_UNAUTHORIZED;
            break;
          }
          if (r_jwk_init(&jwk_header) != RHN_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_dpop_proof - Error r_jwk_init");
            ret = I_ERROR;
            break;
          }
          if (r_jwk_import_from_json_t(jwk_header, json_object_get(j_header, "jwk")) != RHN_OK) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_dpop_proof - Invalid jwk property in header");
            ret = I_ERROR_UNAUTHORIZED;
            break;
          }
          if (!o_strlen(r_jwt_get_claim_str_value(dpop_jwt, "jti"))) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_dpop_proof - Invalid jti");
            ret = I_ERROR_UNAUTHORIZED;
            break;
          }
          if (0 != o_strcmp(htm, r_jwt_get_claim_str_value(dpop_jwt, "htm"))) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_dpop_proof - Invalid htm");
            ret = I_ERROR_UNAUTHORIZED;
            break;
          }
          if (0 != o_strcmp(htu, r_jwt_get_claim_str_value(dpop_jwt, "htu"))) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_dpop_proof - Invalid htu");
            ret = I_ERROR_UNAUTHORIZED;
            break;
          }
          time(&now);
          if (max_iat) {
            if (((time_t)r_jwt_get_claim_int_value(dpop_jwt, "iat"))+max_iat < now) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_dpop_proof - Expired iat");
              ret = I_ERROR_UNAUTHORIZED;
              break;
            }
          }
          if ((time_t)r_jwt_get_claim_int_value(dpop_jwt, "iat") > now) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_dpop_proof - Invalid iat");
            ret = I_ERROR_UNAUTHORIZED;
            break;
          }
          if (!o_strlen(access_token)) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_dpop_proof - Invalid access_token");
            ret = I_ERROR_PARAM;
            break;
          }
          hash_data.data = (unsigned char*)access_token;
          hash_data.size = o_strlen(access_token);
          if (gnutls_fingerprint(GNUTLS_DIG_SHA256, &hash_data, ath, &ath_len) != GNUTLS_E_SUCCESS) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_dpop_proof - Error gnutls_fingerprint");
            ret = I_ERROR;
            break;
          }
          if (!o_base64url_encode(ath, ath_len, ath_enc, &ath_enc_len)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_dpop_proof - Error o_base64url_encode ath");
            ret = I_ERROR;
            break;
          }
          if (0 != o_strcmp((const char *)ath_enc, r_jwt_get_claim_str_value(dpop_jwt, "ath"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_dpop_proof - Error ath invalid");
            ret = I_ERROR_UNAUTHORIZED;
            break;
          }
          if ((jkt_from_token = r_jwk_thumbprint(jwk_header, R_JWK_THUMB_SHA256, R_FLAG_IGNORE_REMOTE)) == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_dpop_proof - Error r_jwk_thumbprint");
            ret = I_ERROR;
            break;
          }
          if (0 != o_strcmp(jkt, jkt_from_token)) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_dpop_proof - jkt value doesn't match");
            ret = I_ERROR_UNAUTHORIZED;
            break;
          }
        } while (0);
        json_decref(j_header);
        r_jwk_free(jwk_header);
        o_free(jkt_from_token);
      } else {
        y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_dpop_proof - Invalid signature");
        ret = I_ERROR_UNAUTHORIZED;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_dpop_proof - Invalid DPoP token");
      ret = I_ERROR_UNAUTHORIZED;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_dpop_proof - Error r_jwt_init");
    ret = I_ERROR;
  }
  r_jwt_free(dpop_jwt);
  return ret;
}

int i_set_rich_authorization_request_str(struct _i_session * i_session, const char * type, const char * value) {
  int ret;
  json_t * j_value = NULL;

  if (i_session != NULL && o_strlen(type) && o_strlen(value)) {
    if ((j_value = json_loads(value, JSON_DECODE_ANY, NULL)) != NULL) {
      ret = i_set_rich_authorization_request_json_t(i_session, type, j_value);
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "i_set_rich_authorization_request_str - Error loading value, not in JSON format");
      ret = I_ERROR_PARAM;
    }
    json_decref(j_value);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "i_set_rich_authorization_request_str - Error input parameters");
    ret = I_ERROR_PARAM;
  }

  return ret;
}

int i_set_rich_authorization_request_json_t(struct _i_session * i_session, const char * type, json_t * j_value) {
  int ret;
  json_t * j_element = NULL;
  size_t index = 0;

  if (i_session != NULL && o_strlen(type) && json_is_object(j_value)) {
    json_array_foreach(i_session->j_authorization_details, index, j_element) {
      if (0 == o_strcmp(type, json_string_value(json_object_get(j_element, "type")))) {
        json_array_remove(i_session->j_authorization_details, index);
        break;
      }
    }
    json_object_set_new(j_value, "type", json_string(type));
    json_array_append(i_session->j_authorization_details, j_value);
    ret = I_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "i_set_rich_authorization_request_json_t - Error input parameters");
    ret = I_ERROR_PARAM;
  }

  return ret;
}

int i_remove_rich_authorization_request(struct _i_session * i_session, const char * type) {
  int ret = I_ERROR_PARAM;
  json_t * j_element = NULL;
  size_t index = 0;

  if (i_session != NULL && o_strlen(type)) {
    json_array_foreach(i_session->j_authorization_details, index, j_element) {
      if (0 == o_strcmp(type, json_string_value(json_object_get(j_element, "type")))) {
        json_array_remove(i_session->j_authorization_details, index);
        ret = I_OK;
        break;
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "i_remove_rich_authorization_request - Error input parameters");
  }

  return ret;
}

json_t * i_get_rich_authorization_request_json_t(struct _i_session * i_session, const char * type) {
  json_t * j_element = NULL;
  size_t index = 0;

  if (i_session != NULL && o_strlen(type)) {
    json_array_foreach(i_session->j_authorization_details, index, j_element) {
      if (0 == o_strcmp(type, json_string_value(json_object_get(j_element, "type")))) {
        return json_deep_copy(j_element);
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "i_remove_rich_authorization_request - Error input parameters");
  }

  return NULL;
}

char * i_get_rich_authorization_request_str(struct _i_session * i_session, const char * type) {
  json_t * j_element = i_get_rich_authorization_request_json_t(i_session, type);
  char * to_return = NULL;

  if (j_element != NULL) {
    to_return = json_dumps(j_element, JSON_COMPACT);
  }
  json_decref(j_element);

  return to_return;
}

int i_run_device_auth_request(struct _i_session * i_session) {
  int ret = I_OK, res;
  struct _u_request request;
  struct _u_response response;
  json_t * j_response;
  char * claims;
  jwa_alg sign_alg = R_JWA_ALG_UNKNOWN, enc_alg = R_JWA_ALG_UNKNOWN;
  jwa_enc enc = R_JWA_ENC_UNKNOWN;

  if (i_session != NULL &&
      i_session->device_authorization_endpoint != NULL &&
      i_session->client_id != NULL &&
      i_session->response_type == I_RESPONSE_TYPE_DEVICE_CODE) {
    _i_init_request(i_session, &request);
    ulfius_init_response(&response);
    ulfius_set_request_properties(&request,
                                  U_OPT_HTTP_VERB, "POST",
                                  U_OPT_HTTP_URL, _i_get_endpoint(i_session, "device"),
                                  U_OPT_HEADER_PARAMETER, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR,
                                  U_OPT_HEADER_PARAMETER, "Accept", "application/json",
                                  U_OPT_POST_BODY_PARAMETER, "grant_type", "device_authorization",
                                  U_OPT_NONE);
    if (i_session->scope != NULL) {
      ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "scope", i_session->scope, U_OPT_NONE);
    }

    if (_i_has_claims(i_session)) {
      claims = json_dumps(i_session->j_claims, JSON_COMPACT);
      ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "claims", claims, U_OPT_NONE);
      o_free(claims);
    }

    if (i_session->resource_indicator != NULL) {
      ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "resource", i_session->resource_indicator, U_OPT_NONE);
    }

    if (i_session->client_sign_alg != R_JWA_ALG_UNKNOWN) {
      sign_alg = i_session->client_sign_alg;
    } else if (i_session->token_endpoint_signing_alg != R_JWA_ALG_UNKNOWN) {
      sign_alg = i_session->token_endpoint_signing_alg;
    }
    if (i_session->client_enc_alg != R_JWA_ALG_UNKNOWN) {
      enc_alg = i_session->client_enc_alg;
    } else if (i_session->token_endpoint_encryption_alg != R_JWA_ALG_UNKNOWN) {
      enc_alg = i_session->token_endpoint_encryption_alg;
    }
    if (i_session->client_enc != R_JWA_ENC_UNKNOWN) {
      enc = i_session->client_enc;
    } else if (i_session->token_endpoint_encryption_enc != R_JWA_ENC_UNKNOWN) {
      enc = i_session->token_endpoint_encryption_enc;
    }
    if ((res = _i_add_token_authentication(i_session, i_session->device_authorization_endpoint, &request, sign_alg, enc_alg, enc)) == I_OK) {
      if (ulfius_send_http_request(&request, &response) == U_OK) {
        if (response.status == 200 || response.status == 400) {
          j_response = ulfius_get_json_body_response(&response, NULL);
          if (j_response != NULL) {
            if (response.status == 200) {
              i_set_parameter_list(i_session,
                                   I_OPT_DEVICE_AUTH_CODE, json_string_value(json_object_get(j_response, "device_code")),
                                   I_OPT_DEVICE_AUTH_USER_CODE, json_string_value(json_object_get(j_response, "user_code")),
                                   I_OPT_DEVICE_AUTH_VERIFICATION_URI, json_string_value(json_object_get(j_response, "verification_uri")),
                                   I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE, json_string_value(json_object_get(j_response, "verification_uri_complete")),
                                   I_OPT_DEVICE_AUTH_EXPIRES_IN, (unsigned int)json_integer_value(json_object_get(j_response, "expires_in")),
                                   I_OPT_DEVICE_AUTH_INTERVAL, (unsigned int)json_integer_value(json_object_get(j_response, "interval")),
                                   I_OPT_NONE);
              ret = I_OK;
            } else {
              i_set_parameter_list(i_session,
                                   I_OPT_ERROR, json_string_value(json_object_get(j_response, "error")),
                                   I_OPT_ERROR_DESCRIPTION, json_string_value(json_object_get(j_response, "error_description")),
                                   I_OPT_ERROR_URI, json_string_value(json_object_get(j_response, "error_uri")),
                                   I_OPT_NONE);
              ret = I_ERROR_PARAM;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_run_device_auth_request - Error parsing JSON response");
            ret = I_ERROR;
          }
          json_decref(j_response);
        } else if (response.status == 403) {
          ret = I_ERROR_UNAUTHORIZED;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_run_device_auth_request - Invalid response status");
          ret = I_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_run_device_auth_request - Error sending token request");
        ret = I_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_run_device_auth_request - Error _i_add_token_authentication");
      ret = res;
    }
    ulfius_clean_request(&request);
    ulfius_clean_response(&response);
  } else {
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_run_par_request(struct _i_session * i_session) {
  int ret = I_OK, res;
  struct _u_request request;
  struct _u_response response;
  json_t * j_response;
  char * tmp;
  const char ** key = NULL;
  int i;
  jwa_alg sign_alg = R_JWA_ALG_UNKNOWN, enc_alg = R_JWA_ALG_UNKNOWN;
  jwa_enc enc = R_JWA_ENC_UNKNOWN;

  if (i_session != NULL &&
      i_session->pushed_authorization_request_endpoint != NULL &&
      _i_check_strict_parameters(i_session) &&
      i_session->redirect_uri != NULL &&
      i_session->client_id != NULL) {
    _i_init_request(i_session, &request);
    ulfius_init_response(&response);

    if (u_map_count(&i_session->additional_parameters)) {
      key = u_map_enum_keys(&i_session->additional_parameters);
      for (i=0; key[i]!=NULL; i++) {
        ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, key[i], u_map_get(&i_session->additional_parameters, key[i]), U_OPT_NONE);
      }
    }

    ulfius_set_request_properties(&request,
                                  U_OPT_HTTP_VERB, "POST",
                                  U_OPT_HTTP_URL, _i_get_endpoint(i_session, "par"),
                                  U_OPT_HEADER_PARAMETER, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR,
                                  U_OPT_HEADER_PARAMETER, "Accept", "application/json",
                                  U_OPT_POST_BODY_PARAMETER, "client_id", i_session->client_id,
                                  U_OPT_POST_BODY_PARAMETER, "redirect_uri", i_session->redirect_uri,
                                  U_OPT_POST_BODY_PARAMETER, "response_type", _i_get_response_type(i_session->response_type),
                                  U_OPT_NONE);

    if (i_session->state != NULL) {
      ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "state", i_session->state, U_OPT_NONE);
    }

    if (i_session->scope != NULL) {
      ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "scope", i_session->scope, U_OPT_NONE);
    }

    if (i_session->nonce != NULL) {
      ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "nonce", i_session->nonce, U_OPT_NONE);
    }

    if (i_session->resource_indicator != NULL) {
      ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "resource", i_session->resource_indicator, U_OPT_NONE);
    }

    if (_i_has_claims(i_session)) {
      tmp = json_dumps(i_session->j_claims, JSON_COMPACT);
      ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "claims", tmp, U_OPT_NONE);
      o_free(tmp);
    }

    if (json_array_size(i_session->j_authorization_details)) {
      tmp = json_dumps(i_session->j_authorization_details, JSON_COMPACT);
      ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "authorization_details", tmp, U_OPT_NONE);
      o_free(tmp);
    }

    if (i_session->client_sign_alg != R_JWA_ALG_UNKNOWN) {
      sign_alg = i_session->client_sign_alg;
    } else if (i_session->token_endpoint_signing_alg != R_JWA_ALG_UNKNOWN) {
      sign_alg = i_session->token_endpoint_signing_alg;
    }
    if (i_session->client_enc_alg != R_JWA_ALG_UNKNOWN) {
      enc_alg = i_session->client_enc_alg;
    } else if (i_session->token_endpoint_encryption_alg != R_JWA_ALG_UNKNOWN) {
      enc_alg = i_session->token_endpoint_encryption_alg;
    }
    if (i_session->client_enc != R_JWA_ENC_UNKNOWN) {
      enc = i_session->client_enc;
    } else if (i_session->token_endpoint_encryption_enc != R_JWA_ENC_UNKNOWN) {
      enc = i_session->token_endpoint_encryption_enc;
    }
    if ((res = _i_add_token_authentication(i_session, i_session->pushed_authorization_request_endpoint, &request, sign_alg, enc_alg, enc)) == I_OK) {
      if (ulfius_send_http_request(&request, &response) == U_OK) {
        if (response.status == 201 || response.status == 400) {
          j_response = ulfius_get_json_body_response(&response, NULL);
          if (j_response != NULL) {
            if (response.status == 201) {
              i_set_parameter_list(i_session,
                                   I_OPT_PUSHED_AUTH_REQ_URI, json_string_value(json_object_get(j_response, "request_uri")),
                                   I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN, (unsigned int)json_integer_value(json_object_get(j_response, "expires_in")),
                                   I_OPT_NONE);
              ret = I_OK;
            } else {
              i_set_parameter_list(i_session,
                                   I_OPT_ERROR, json_string_value(json_object_get(j_response, "error")),
                                   I_OPT_ERROR_DESCRIPTION, json_string_value(json_object_get(j_response, "error_description")),
                                   I_OPT_ERROR_URI, json_string_value(json_object_get(j_response, "error_uri")),
                                   I_OPT_NONE);
              ret = I_ERROR_PARAM;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_run_par_request - Error parsing JSON response");
            ret = I_ERROR;
          }
          json_decref(j_response);
        } else if (response.status == 403) {
          ret = I_ERROR_UNAUTHORIZED;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_run_par_request - Invalid response status");
          ret = I_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_run_par_request - Error sending token request");
        ret = I_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_run_par_request - Error _i_add_token_authentication");
      ret = res;
    }
    ulfius_clean_request(&request);
    ulfius_clean_response(&response);
  } else {
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_run_ciba_request(struct _i_session * i_session) {
  int ret = I_OK, res;
  struct _u_request request;
  struct _u_response response;
  json_t * j_response, * j_login_hint = NULL;
  char * tmp = NULL;
  const char ** key = NULL;
  int i;
  jwt_t * jwt = NULL;
  jwk_t * jwk_sign = NULL;
  jwa_alg sign_alg = R_JWA_ALG_UNKNOWN, enc_alg = R_JWA_ALG_UNKNOWN;
  jwa_enc enc = R_JWA_ENC_UNKNOWN;

  if (i_session != NULL &&
      i_session->ciba_endpoint != NULL &&
      (((i_session->ciba_mode == I_CIBA_MODE_PING || i_session->ciba_mode == I_CIBA_MODE_PUSH) && i_session->ciba_client_notification_token != NULL) || i_session->ciba_mode == I_CIBA_MODE_POLL) &&
      _i_check_strict_parameters(i_session) &&
      i_session->ciba_login_hint != NULL &&
      i_session->scope != NULL &&
      i_session->client_id != NULL) {
    _i_init_request(i_session, &request);
    ulfius_init_response(&response);

    if (u_map_count(&i_session->additional_parameters)) {
      key = u_map_enum_keys(&i_session->additional_parameters);
      for (i=0; key[i]!=NULL; i++) {
        ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, key[i], u_map_get(&i_session->additional_parameters, key[i]), U_OPT_NONE);
      }
    }

    ulfius_set_request_properties(&request,
                                  U_OPT_HTTP_VERB, "POST",
                                  U_OPT_HTTP_URL, _i_get_endpoint(i_session, "ciba"),
                                  U_OPT_HEADER_PARAMETER, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR,
                                  U_OPT_HEADER_PARAMETER, "Accept", "application/json",
                                  U_OPT_POST_BODY_PARAMETER, "client_id", i_session->client_id,
                                  U_OPT_POST_BODY_PARAMETER, "scope", i_session->scope,
                                  U_OPT_NONE);

    if (i_session->ciba_mode != I_CIBA_MODE_POLL) {
      ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "client_notification_token", i_session->ciba_client_notification_token, U_OPT_NONE);
    }
    
    do {
      if (i_session->ciba_login_hint_format == I_CIBA_LOGIN_HINT_FORMAT_JSON) {
        if ((j_login_hint = json_loads(i_session->ciba_login_hint, JSON_DECODE_ANY, NULL)) != NULL) {
          tmp = json_dumps(j_login_hint, JSON_COMPACT);
          ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "login_hint", tmp, U_OPT_NONE);
          o_free(tmp);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_run_ciba_auth_request - Error parsing login_hint");
          ret = I_ERROR_PARAM;
          break;
        }
      }
      
      if (i_session->ciba_login_hint_format == I_CIBA_LOGIN_HINT_FORMAT_JWT) {
        r_jwt_init(&jwt);
        if (i_session->client_sign_alg != R_JWA_ALG_UNKNOWN) {
          sign_alg = i_session->client_sign_alg;
        } else if (i_session->ciba_request_signing_alg != R_JWA_ALG_UNKNOWN) {
          sign_alg = i_session->ciba_request_signing_alg;
        }
        if (r_jwt_set_full_claims_json_str(jwt, i_session->ciba_login_hint) == RHN_OK) {
          if (i_session->token_method == I_TOKEN_AUTH_METHOD_JWT_SIGN_SECRET) {
            if (i_session->client_secret != NULL) {
              if ((sign_alg == R_JWA_ALG_HS256 || sign_alg == R_JWA_ALG_HS384 || sign_alg == R_JWA_ALG_HS512) && !_i_has_openid_config_parameter_value(i_session, "backchannel_authentication_request_signing_alg_values_supported", r_jwa_alg_to_str(sign_alg))) {
                y_log_message(Y_LOG_LEVEL_ERROR, "signature alg is not specified or supported by the server");
                ret = I_ERROR_PARAM;
              } else if (sign_alg == R_JWA_ALG_UNKNOWN && json_array_size(json_object_get(i_session->openid_config, "backchannel_authentication_request_signing_alg_values_supported"))) {
                // no signtature alg specified, use one supported by the server
                if (_i_has_openid_config_parameter_value(i_session, "backchannel_authentication_request_signing_alg_values_supported", "HS256")) {
                  sign_alg = R_JWA_ALG_HS256;
                } else if (_i_has_openid_config_parameter_value(i_session, "backchannel_authentication_request_signing_alg_values_supported", "HS384")) {
                  sign_alg = R_JWA_ALG_HS384;
                } else if (_i_has_openid_config_parameter_value(i_session, "backchannel_authentication_request_signing_alg_values_supported", "HS512")) {
                  sign_alg = R_JWA_ALG_HS512;
                }
              }
              if (sign_alg != R_JWA_ALG_UNKNOWN) {
                r_jwt_set_sign_alg(jwt, sign_alg);
                r_jwk_init(&jwk_sign);
                r_jwk_import_from_symmetric_key(jwk_sign, (const unsigned char *)i_session->client_secret, o_strlen(i_session->client_secret));
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "Invalid signing key parameters");
                ret = I_ERROR_PARAM;
                break;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "Client has no secret");
              ret = I_ERROR_PARAM;
              break;
            }
          } else {
            if ((i_session->ciba_login_hint_kid != NULL && (jwk_sign = r_jwks_get_by_kid(i_session->client_jwks, i_session->ciba_login_hint_kid)) != NULL) || (r_jwks_size(i_session->client_jwks) == 1 && (jwk_sign = r_jwks_get_at(i_session->client_jwks, 0)) != NULL)) {
              if ((sign_alg == R_JWA_ALG_RS256 || sign_alg == R_JWA_ALG_RS384 || sign_alg == R_JWA_ALG_RS512 ||
                   sign_alg == R_JWA_ALG_PS256 || sign_alg == R_JWA_ALG_PS384 || sign_alg == R_JWA_ALG_PS512) &&
                   _i_has_openid_config_parameter_value(i_session, "backchannel_authentication_request_signing_alg_values_supported", i_get_str_parameter(i_session, I_OPT_CLIENT_SIGN_ALG))) {
                if (!(r_jwk_key_type(jwk_sign, NULL, i_session->x5u_flags) & (R_KEY_TYPE_RSA|R_KEY_TYPE_PRIVATE))) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "Invalid signing key type");
                  ret = I_ERROR_PARAM;
                  break;
                }
              } else if ((sign_alg == R_JWA_ALG_ES256 || sign_alg == R_JWA_ALG_ES384 || sign_alg == R_JWA_ALG_ES512) && _i_has_openid_config_parameter_value(i_session, "backchannel_authentication_request_signing_alg_values_supported", i_get_str_parameter(i_session, I_OPT_CLIENT_SIGN_ALG))) {
                if (!(r_jwk_key_type(jwk_sign, NULL, i_session->x5u_flags) & (R_KEY_TYPE_EC|R_KEY_TYPE_PRIVATE))) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "Invalid signing key type");
                  ret = I_ERROR_PARAM;
                  break;
                }
              } else if (sign_alg == R_JWA_ALG_EDDSA && _i_has_openid_config_parameter_value(i_session, "backchannel_authentication_request_signing_alg_values_supported", i_get_str_parameter(i_session, I_OPT_CLIENT_SIGN_ALG))) {
                if (!(r_jwk_key_type(jwk_sign, NULL, i_session->x5u_flags) & (R_KEY_TYPE_EDDSA|R_KEY_TYPE_PRIVATE))) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "Invalid signing key type");
                  ret = I_ERROR_PARAM;
                  break;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "Invalid signing key parameters");
                ret = I_ERROR_PARAM;
                break;
              }
              r_jwt_set_sign_alg(jwt, sign_alg);
            } else if (!r_jwks_size(i_session->client_jwks)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "Client has no private key ");
              ret = I_ERROR_PARAM;
              break;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "Client has more than one private key, please specify one with the parameter I_OPT_CLIENT_KID");
              ret = I_ERROR_PARAM;
              break;
            }
          }
          if (ret == I_OK) {
            tmp = r_jwt_serialize_signed(jwt, jwk_sign, i_session->x5u_flags);
            ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "login_hint_token", tmp, U_OPT_NONE);
            o_free(tmp);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_run_ciba_auth_request - Error parsing login_hint");
          ret = I_ERROR_PARAM;
          break;
        }
      }

      if (i_session->ciba_login_hint_format == I_CIBA_LOGIN_HINT_FORMAT_ID_TOKEN) {
        ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "id_token_hint", i_session->ciba_login_hint, U_OPT_NONE);
      }
      
      if (i_session->ciba_binding_message != NULL) {
        ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "binding_message", i_session->ciba_binding_message, U_OPT_NONE);
      }
      
      if (i_session->ciba_user_code != NULL) {
        ulfius_set_request_properties(&request, U_OPT_POST_BODY_PARAMETER, "user_code", i_session->ciba_user_code, U_OPT_NONE);
      }
    } while (0);
    r_jwt_free(jwt);
    r_jwk_free(jwk_sign);
    json_decref(j_login_hint);

  
    if (ret == I_OK) {
      if (i_session->client_sign_alg != R_JWA_ALG_UNKNOWN) {
        sign_alg = i_session->client_sign_alg;
      } else if (i_session->token_endpoint_signing_alg != R_JWA_ALG_UNKNOWN) {
        sign_alg = i_session->token_endpoint_signing_alg;
      }
      if (i_session->client_enc_alg != R_JWA_ALG_UNKNOWN) {
        enc_alg = i_session->client_enc_alg;
      } else if (i_session->token_endpoint_encryption_alg != R_JWA_ALG_UNKNOWN) {
        enc_alg = i_session->token_endpoint_encryption_alg;
      }
      if (i_session->client_enc != R_JWA_ENC_UNKNOWN) {
        enc = i_session->client_enc;
      } else if (i_session->token_endpoint_encryption_enc != R_JWA_ENC_UNKNOWN) {
        enc = i_session->token_endpoint_encryption_enc;
      }
      if ((res = _i_add_token_authentication(i_session, i_session->pushed_authorization_request_endpoint, &request, sign_alg, enc_alg, enc)) == I_OK) {
        if (ulfius_send_http_request(&request, &response) == U_OK) {
          if (response.status == 200 || response.status == 400) {
            j_response = ulfius_get_json_body_response(&response, NULL);
            if (j_response != NULL) {
              if (response.status == 200) {
                i_set_parameter_list(i_session,
                                     I_OPT_CIBA_AUTH_REQ_ID, json_string_value(json_object_get(j_response, "auth_req_id")),
                                     I_OPT_CIBA_AUTH_REQ_EXPIRES_IN, (unsigned int)json_integer_value(json_object_get(j_response, "expires_in")),
                                     I_OPT_CIBA_AUTH_REQ_INTERVAL, (unsigned int)json_integer_value(json_object_get(j_response, "expires_in")),
                                     I_OPT_NONE);
                ret = I_OK;
              } else {
                i_set_parameter_list(i_session,
                                     I_OPT_ERROR, json_string_value(json_object_get(j_response, "error")),
                                     I_OPT_ERROR_DESCRIPTION, json_string_value(json_object_get(j_response, "error_description")),
                                     I_OPT_ERROR_URI, json_string_value(json_object_get(j_response, "error_uri")),
                                     I_OPT_NONE);
                ret = I_ERROR_PARAM;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_run_ciba_auth_request - Error parsing JSON response");
              ret = I_ERROR;
            }
            json_decref(j_response);
          } else if (response.status == 403 || response.status == 401) {
            ret = I_ERROR_UNAUTHORIZED;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_run_ciba_auth_request - Invalid response status");
            ret = I_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_run_ciba_auth_request - Error sending token request");
          ret = I_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_run_ciba_auth_request - Error _i_add_token_authentication");
        ret = res;
      }
    }
    ulfius_clean_request(&request);
    ulfius_clean_response(&response);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "i_run_ciba_auth_request - Error input parameters");
    ret = I_ERROR_PARAM;
  }
  return ret;
}

char * i_build_end_session_url(struct _i_session * i_session) {
  char * url = NULL, * post_logout_enc = NULL;
  if (i_get_str_parameter(i_session, I_OPT_END_SESSION_ENDPOINT) != NULL && i_get_str_parameter(i_session, I_OPT_ID_TOKEN) != NULL) {
    url = msprintf("%s?id_token_hint=%s", i_get_str_parameter(i_session, I_OPT_END_SESSION_ENDPOINT), i_get_str_parameter(i_session, I_OPT_ID_TOKEN));
    if (i_get_str_parameter(i_session, I_OPT_POST_LOGOUT_REDIRECT_URI) != NULL) {
      post_logout_enc = ulfius_url_encode(i_get_str_parameter(i_session, I_OPT_POST_LOGOUT_REDIRECT_URI));
      url = mstrcatf(url, "&post_logout_redirect_uri=%s", post_logout_enc);
      o_free(post_logout_enc);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "i_build_end_session_url - session has no end_session_endpoint or id_token");
  }
  return url;
}

int i_verify_end_session_backchannel_token(struct _i_session * i_session, const char * token) {
  int ret, res;
  jwt_t * jwt = NULL;
  json_t * j_events;

  if (r_jwt_init(&jwt) == RHN_OK) {
    if ((res = _i_verify_jwt_sig_enc(i_session, token, I_TOKEN_TYPE_ID_TOKEN, jwt)) == I_OK) {
      if (r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, i_get_str_parameter(i_session, I_OPT_ISSUER),
                                     R_JWT_CLAIM_AUD, i_get_str_parameter(i_session, I_OPT_CLIENT_ID),
                                     R_JWT_CLAIM_IAT, R_JWT_CLAIM_NOW,
                                     R_JWT_CLAIM_JTI, NULL,
                                     R_JWT_CLAIM_NOP) == RHN_OK) {
        j_events = r_jwt_get_claim_json_t_value(jwt, "events");
        if (json_is_object(j_events) && json_is_object(json_object_get(j_events, "http://schemas.openid.net/event/backchannel-logout"))) {
          if (i_get_int_parameter(i_session, I_OPT_BACKCHANNEL_LOGOUT_SESSION_REQUIRED) && r_jwt_get_claim_str_value(jwt, "sid") == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_end_session_backchannel_token - invalid claims, claim sid required");
            ret = I_ERROR_PARAM;
          } else if (r_jwt_get_claim_str_value(jwt, "sid") == NULL && r_jwt_get_claim_str_value(jwt, "sub") == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_end_session_backchannel_token - invalid claims, missing sub or sid claim");
            ret = I_ERROR_PARAM;
          } else if (r_jwt_get_claim_str_value(jwt, "sid") != NULL && 0 != o_strcmp(r_jwt_get_claim_str_value(jwt, "sid"), i_get_str_parameter(i_session, I_OPT_ID_TOKEN_SID))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_end_session_backchannel_token - invalid claims, invalid claim sid");
            ret = I_ERROR_PARAM;
          } else {
            json_decref(i_session->access_token_payload);
            i_session->access_token_payload = r_jwt_get_full_claims_json_t(jwt);
            ret = I_OK;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_end_session_backchannel_token - invalid claims, missing or invalid events claim");
          ret = I_ERROR_PARAM;
        }
        json_decref(j_events);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_end_session_backchannel_token - invalid claims");
        ret = I_ERROR_PARAM;
      }
    } else if (res == I_ERROR) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_end_session_backchannel_token - Error _i_verify_jwt_sig_enc");
      ret = I_ERROR_PARAM;
    } else {
      ret = res;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_end_session_backchannel_token - Error r_jwt_init");
    ret = I_ERROR;
  }
  r_jwt_free(jwt);
  return ret;
}

int i_close_session(struct _i_session * i_session, const char * sid) {
  int ret = I_OK;
  if (sid != NULL && 0 != o_strcmp(sid, i_get_str_parameter(i_session, I_OPT_ID_TOKEN_SID))) {
    ret = I_ERROR_PARAM;
  } else {
    if ((ret = i_set_str_parameter(i_session, I_OPT_CODE, NULL)) != I_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_close_session - Error cleaning code");
      return ret;
    }
    if ((ret = i_set_str_parameter(i_session, I_OPT_REFRESH_TOKEN, NULL)) != I_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_close_session - Error cleaning refresh token");
      return ret;
    }
    if ((ret = i_set_str_parameter(i_session, I_OPT_ACCESS_TOKEN, NULL)) != I_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_close_session - Error cleaning access token");
      return ret;
    }
    if ((ret = i_set_str_parameter(i_session, I_OPT_ID_TOKEN, NULL)) != I_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_close_session - Error cleaning id_token");
      return ret;
    }
    if ((ret = i_set_str_parameter(i_session, I_OPT_NONCE, NULL)) != I_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_close_session - Error cleaning nonce");
      return ret;
    }
    if ((ret = i_set_str_parameter(i_session, I_OPT_USERINFO, NULL)) != I_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_close_session - Error cleaning userinfo");
      return ret;
    }
    if ((ret = i_set_str_parameter(i_session, I_OPT_TOKEN_JTI, NULL)) != I_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_close_session - Error cleaning token jti");
      return ret;
    }
    if ((ret = i_set_str_parameter(i_session, I_OPT_DEVICE_AUTH_CODE, NULL)) != I_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_close_session - Error cleaning device auth code");
      return ret;
    }
    if ((ret = i_set_str_parameter(i_session, I_OPT_DEVICE_AUTH_USER_CODE, NULL)) != I_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_close_session - Error cleaning device auth user code");
      return ret;
    }
    if ((ret = i_set_str_parameter(i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI, NULL)) != I_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_close_session - Error cleaning device auth verification uri");
      return ret;
    }
    if ((ret = i_set_str_parameter(i_session, I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE, NULL)) != I_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_close_session - Error cleaning device auth verification uri complete");
      return ret;
    }
    if ((ret = i_set_str_parameter(i_session, I_OPT_PKCE_CODE_VERIFIER, NULL)) != I_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_close_session - Error cleaning PKCE code verifier");
      return ret;
    }
    if ((ret = i_set_str_parameter(i_session, I_OPT_CIBA_USER_CODE, NULL)) != I_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_close_session - Error cleaning CIBA user code");
      return ret;
    }
    if ((ret = i_set_str_parameter(i_session, I_OPT_CIBA_AUTH_REQ_ID, NULL)) != I_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_close_session - Error cleaning CIBA auth req id");
      return ret;
    }
    if ((ret = i_set_str_parameter(i_session, I_OPT_ID_TOKEN_SID, NULL)) != I_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_close_session - Error cleaning id_token sid");
      return ret;
    }
  }
  return ret;
}
