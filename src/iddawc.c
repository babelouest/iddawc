/**
 * 
 * Iddawc OAuth2 client library
 * 
 * iddawc.h: structures and functions declarations
 * 
 * Copyright 2019-2020 Nicolas Mora <mail@babelouest.org>
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
#include <rhonabwy.h>

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

/**
 * Generates a random string used as nonce and store it in str
 */
char * rand_string_nonce(char * str, size_t str_size) {
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

static const char * get_response_type(uint response_type) {
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
    default:
      o_strcpy(result, "");
      break;
  }
  return result;
}

static int extract_parameters(const char * url_params, struct _u_map * map) {
  char ** unescaped_parameters = NULL, * key, * value;
  size_t offset = 0;
  int ret = I_OK;
  
  if (split_string(url_params, "&", &unescaped_parameters)) {
    for (offset = 0; unescaped_parameters[offset] != NULL; offset++) {
      if (o_strchr(unescaped_parameters[offset], '=') != NULL) {
        key = o_strndup(unescaped_parameters[offset], o_strchr(unescaped_parameters[offset], '=') - unescaped_parameters[offset]);
        value = ulfius_url_decode(o_strchr(unescaped_parameters[offset], '=')+1);
        u_map_put(map, key, value);
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
  char * endptr = NULL;
  long expires_in = 0;
  
  for (i=0; keys[i] != NULL; i++) {
    key = keys[i];
    if (0 == o_strcasecmp(key, "code") && (i_get_response_type(i_session) & I_RESPONSE_TYPE_CODE) && o_strlen(u_map_get(map, key))) {
      c_ret = i_set_str_parameter(i_session, I_OPT_CODE, u_map_get(map, key));
      ret = ret!=I_OK?ret:c_ret;
    } else if (0 == o_strcasecmp(key, "id_token") && i_get_response_type(i_session) & I_RESPONSE_TYPE_ID_TOKEN && o_strlen(u_map_get(map, key))) {
      c_ret = i_set_str_parameter(i_session, I_OPT_ID_TOKEN, u_map_get(map, key));
      ret = ret!=I_OK?ret:c_ret;
    } else if (0 == o_strcasecmp(key, "access_token") && (i_get_response_type(i_session) & I_RESPONSE_TYPE_TOKEN) && o_strlen(u_map_get(map, key))) {
      c_ret = i_set_str_parameter(i_session, I_OPT_ACCESS_TOKEN, u_map_get(map, key));
      ret = ret!=I_OK?ret:c_ret;
      if (!o_strlen(u_map_get_case(map, "token_type"))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_redirect_to_parameters - Got parameter token but token_type is missing");
        ret = ret!=I_OK?ret:I_ERROR_SERVER;
      }
    } else if (0 == o_strcasecmp(key, "token_type")) {
      c_ret = i_set_str_parameter(i_session, I_OPT_TOKEN_TYPE, u_map_get(map, key));
      ret = ret!=I_OK?ret:c_ret;
    } else if (0 == o_strcasecmp(key, "expires_in")) {
      expires_in = strtol(u_map_get(map, key), &endptr, 10);
      if (endptr != (char *)u_map_get(map, key)) {
        if (i_set_int_parameter(i_session, I_OPT_EXPIRES_IN, (uint)expires_in) != I_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_redirect_to_parameters - expires_in invalid");
          ret = ret!=I_OK?ret:I_ERROR_SERVER;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_redirect_to_parameters - expires_in not numeric");
        ret = I_ERROR_SERVER;
      }
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

static int _i_parse_token_response(struct _i_session * i_session, int http_status, json_t * j_response) {
  int ret = I_OK;
  const char * key = NULL;
  json_t * j_element = NULL;
  char * value;
  
  if (i_session != NULL && json_is_object(j_response)) {
    if (http_status == 200) {
      if (json_string_length(json_object_get(j_response, "access_token")) &&
          json_string_length(json_object_get(j_response, "token_type"))) {
        if (i_set_str_parameter(i_session, I_OPT_ACCESS_TOKEN, json_string_value(json_object_get(j_response, "access_token"))) == I_OK &&
            i_set_str_parameter(i_session, I_OPT_TOKEN_TYPE, json_string_value(json_object_get(j_response, "token_type"))) == I_OK) {
          if (json_integer_value(json_object_get(j_response, "expires_in")) && i_set_int_parameter(i_session, I_OPT_EXPIRES_IN, json_integer_value(json_object_get(j_response, "expires_in"))) != I_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_token_response - Error setting expires_in");
            ret = I_ERROR;
          }
          if (json_string_length(json_object_get(j_response, "refresh_token")) && i_set_str_parameter(i_session, I_OPT_REFRESH_TOKEN, json_string_value(json_object_get(j_response, "refresh_token"))) != I_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_token_response - Error setting refresh_token");
            ret = I_ERROR;
          }
          if (json_string_length(json_object_get(j_response, "id_token"))) {
            if (i_set_str_parameter(i_session, I_OPT_ID_TOKEN, json_string_value(json_object_get(j_response, "id_token"))) != I_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_token_response - Error setting id_token");
              ret = I_ERROR;
            } else if (i_verify_id_token(i_session) != I_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_token_response - Error i_verify_id_token");
              ret = I_ERROR;
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
                  y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_token_response - Error i_set_additional_response %s - %s", key, json_string_value(j_element));
                  ret = I_ERROR;
                }
              } else {
                value = json_dumps(j_element, JSON_ENCODE_ANY);
                if (i_set_additional_response(i_session, key, value) != I_OK) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_token_response - Error i_set_additional_response %s - %s", key, json_string_value(j_element));
                  ret = I_ERROR;
                }
                o_free(value);
              }
            }
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_token_response - Error setting response parameters (1)");
          ret = I_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_token_response - required response parameters missing (1)");
        ret = I_ERROR_PARAM;
      }
    } else if (http_status == 400) {
      if (json_string_length(json_object_get(j_response, "error"))) {
        if (i_set_str_parameter(i_session, I_OPT_ERROR, json_string_value(json_object_get(j_response, "error"))) == I_OK) {
          if (json_string_length(json_object_get(j_response, "error_description")) && i_set_str_parameter(i_session, I_OPT_ERROR_DESCRIPTION, json_string_value(json_object_get(j_response, "error_description"))) != I_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_token_response - Error setting error_description");
            ret = I_ERROR;
          }
          if (json_string_length(json_object_get(j_response, "error_uri")) && i_set_str_parameter(i_session, I_OPT_ERROR_URI, json_string_value(json_object_get(j_response, "error_uri"))) != I_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_token_response - Error setting error_uri");
            ret = I_ERROR;
          }
          json_object_foreach(j_response, key, j_element) {
            if (0 != o_strcmp("error", key) &&
                0 != o_strcmp("error_description", key) &&
                0 != o_strcmp("error_uri", key)) {
              if (json_is_string(j_element)) {
                if (i_set_additional_response(i_session, key, json_string_value(j_element)) != I_OK) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_token_response - Error i_set_additional_response %s - %s", key, json_string_value(j_element));
                  ret = I_ERROR;
                }
              } else {
                value = json_dumps(j_element, JSON_ENCODE_ANY);
                if (i_set_additional_response(i_session, key, value) != I_OK) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_token_response - Error i_set_additional_response %s - %s", key, json_string_value(j_element));
                  ret = I_ERROR;
                }
                o_free(value);
              }
            }
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_token_response - Error setting response parameters (2)");
          ret = I_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "_i_parse_token_response - required response parameters missing (2)");
        ret = I_ERROR_PARAM;
      }
    }
  } else {
    ret = I_ERROR_PARAM;
  }
  return ret;
}

static int _i_load_jwks_endpoint(struct _i_session * i_session) {
  int ret;
  struct _u_request request;
  struct _u_response response;
  json_t * j_jwks;
  
  if (i_session != NULL && json_string_length(json_object_get(i_session->openid_config, "jwks_uri"))) {
    ulfius_init_request(&request);
    ulfius_init_response(&response);
    
    u_map_put(request.map_header, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR);
    u_map_put(request.map_header, "Accept", "application/json");
    request.http_url = o_strdup(json_string_value(json_object_get(i_session->openid_config, "jwks_uri")));
    if (ulfius_send_http_request(&request, &response) == U_OK) {
      if (response.status == 200) {
        j_jwks = ulfius_get_json_body_response(&response, NULL);
        r_jwks_free(i_session->server_jwks);
        r_jwks_init(&i_session->server_jwks);
        if (r_jwks_import_from_json_t(i_session->server_jwks, j_jwks) == RHN_OK) {
          ret = I_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "_i_load_jwks_endpoint - Error r_jwks_import_from_str");
          ret = I_ERROR;
        }
        json_decref(j_jwks);
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
  int ret;
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
        if (get_jwks && _i_load_jwks_endpoint(i_session) != I_OK) {
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

static int has_openid_config_parameter_value(struct _i_session * i_session, const char * parameter, const char * value) {
  int ret;
  size_t index = 0;
  json_t * j_element = NULL;
  
  if (i_session != NULL) {
    if (i_session->openid_config != NULL && i_session->openid_config_strict && json_object_get(i_session->openid_config, parameter) != NULL) {
      if (json_is_string(json_object_get(i_session->openid_config, parameter))) {
        if (0 == o_strcmp(value, json_string_value(json_object_get(i_session->openid_config, parameter)))) {
          ret = 1;
        } else {
          ret = 0;
        }
      } else if (json_is_array(json_object_get(i_session->openid_config, parameter))) {
        ret = 0;
        json_array_foreach(json_object_get(i_session->openid_config, parameter), index, j_element) {
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
    ret = 0;
  }
  return ret;
}

static int check_strict_parameters(struct _i_session * i_session) {
  char ** str_array = NULL;
  int ret;
  size_t i;
  
  if (i_session != NULL) {
    ret = 1;
    if (i_session->scope != NULL) {
      if (split_string(i_session->scope, " ", &str_array)) {
        for (i=0; str_array[i]!=NULL; i++) {
          if (!has_openid_config_parameter_value(i_session, "scopes_supported", str_array[i])) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "scope %s not supported", str_array[i]);
            ret = 0;
          }
        }
      }
      free_string_array(str_array);
    }
    if (!has_openid_config_parameter_value(i_session, "response_types_supported", get_response_type(i_session->response_type))) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "response_type %s not supported", get_response_type(i_session->response_type));
      ret = 0;
    }
  } else {
    ret = 0;
  }
  return ret;
}

static json_t * export_u_map(struct _u_map * map) {
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
      y_log_message(Y_LOG_LEVEL_ERROR, "export_u_map - Error allocating resources for j_return");
    }
  }
  return j_return;
}

static char * generate_auth_jwt(struct _i_session * i_session) {
  jwt_t * jwt = NULL;
  jwk_t * jwk_sign = NULL, * jwk_enc = NULL;
  char * jwt_str = NULL;
  const char ** keys = NULL;
  uint i;
  jwa_alg sign_alg = R_JWA_ALG_UNKNOWN, enc_alg = R_JWA_ALG_UNKNOWN;
  jwa_enc enc = R_JWA_ENC_UNKNOWN;
  int has_error = 0;
  
  if (i_session != NULL) {
    r_jwt_init(&jwt);
    r_jwt_set_claim_str_value(jwt, "redirect_uri", i_session->redirect_uri);
    r_jwt_set_claim_str_value(jwt, "response_type", get_response_type(i_session->response_type));
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
    
    keys = u_map_enum_keys(&i_session->additional_parameters);
    
    for (i=0; keys[i] != NULL; i++) {
      r_jwt_set_claim_str_value(jwt, keys[i], u_map_get(&i_session->additional_parameters, keys[i]));
    }
    
    if (i_session->auth_method & I_AUTH_METHOD_JWT_SIGN_SECRET) {
      if (o_strlen(i_session->client_secret)) {
        if ((i_session->client_sign_alg == R_JWA_ALG_HS256 || i_session->client_sign_alg == R_JWA_ALG_HS384 || i_session->client_sign_alg == R_JWA_ALG_HS512) && has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", i_get_str_parameter(i_session, I_OPT_CLIENT_SIGN_ALG))) {
          // signature alg is specified and supported by the server
          sign_alg = i_session->client_sign_alg;
        } else if (i_session->client_sign_alg == R_JWA_ALG_UNKNOWN && json_array_size(json_object_get(i_session->openid_config, "request_object_signing_alg_values_supported"))) {
          // no signtature alg specified, use one supported by the server
          if (has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "HS256")) {
            sign_alg = R_JWA_ALG_HS256;
          } else if (has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "HS384")) {
            sign_alg = R_JWA_ALG_HS384;
          } else if (has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "HS512")) {
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
        if ((i_session->client_sign_alg == R_JWA_ALG_RS256 || i_session->client_sign_alg == R_JWA_ALG_RS384 || i_session->client_sign_alg == R_JWA_ALG_RS512 ||
             i_session->client_sign_alg == R_JWA_ALG_PS256 || i_session->client_sign_alg == R_JWA_ALG_PS384 || i_session->client_sign_alg == R_JWA_ALG_PS512) && 
             has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", i_get_str_parameter(i_session, I_OPT_CLIENT_SIGN_ALG))) {
          if (!(r_jwk_key_type(jwk_sign, NULL, i_session->x5u_flags) & (R_KEY_TYPE_RSA|R_KEY_TYPE_PRIVATE))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "Invalid signing key type");
            has_error = 1;
          }
        } else if ((i_session->client_sign_alg == R_JWA_ALG_ES256 || i_session->client_sign_alg == R_JWA_ALG_ES384 || i_session->client_sign_alg == R_JWA_ALG_ES512) && has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", i_get_str_parameter(i_session, I_OPT_CLIENT_SIGN_ALG))) {
          if (!(r_jwk_key_type(jwk_sign, NULL, i_session->x5u_flags) & (R_KEY_TYPE_ECDSA|R_KEY_TYPE_PRIVATE))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "Invalid signing key type");
            has_error = 1;
          }
        } else if (i_session->client_sign_alg == R_JWA_ALG_EDDSA && has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", i_get_str_parameter(i_session, I_OPT_CLIENT_SIGN_ALG))) {
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
        if (i_session->client_enc != R_JWA_ENC_UNKNOWN && has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", i_get_str_parameter(i_session, I_OPT_CLIENT_ENC))) {
          enc = i_session->client_enc;
        } else if (i_session->client_enc == R_JWA_ENC_UNKNOWN && json_array_size(json_object_get(i_session->openid_config, "request_object_encryption_enc_values_supported"))) {
          if (has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A128CBC-HS256")) {
            enc = R_JWA_ENC_A128CBC;
          } else if (has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A192CBC-HS384")) {
            enc = R_JWA_ENC_A192CBC;
          } else if (has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A256CBC-HS512")) {
            enc = R_JWA_ENC_A256CBC;
          } else if (has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A128GCM")) {
            enc = R_JWA_ENC_A128GCM;
          } else if (has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A192GCM")) {
            enc = R_JWA_ENC_A192GCM;
          } else if (has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A256GCM")) {
            enc = R_JWA_ENC_A256GCM;
          }
        }
        if ((i_session->client_enc_alg == R_JWA_ALG_A128GCMKW || i_session->client_enc_alg == R_JWA_ALG_A192GCMKW || i_session->client_enc_alg == R_JWA_ALG_A256GCMKW ||
        i_session->client_enc_alg == R_JWA_ALG_A128KW || i_session->client_enc_alg == R_JWA_ALG_A192KW || i_session->client_enc_alg == R_JWA_ALG_A256KW || i_session->client_enc_alg == R_JWA_ALG_DIR || i_session->client_enc_alg == R_JWA_ALG_PBES2_H256 || i_session->client_enc_alg == R_JWA_ALG_PBES2_H384 || i_session->client_enc_alg == R_JWA_ALG_PBES2_H512) && has_openid_config_parameter_value(i_session, "request_object_encryption_alg_values_supported", i_get_str_parameter(i_session, I_OPT_CLIENT_ENC_ALG))) {
          // signature alg is specified and supported by the server
          enc_alg = i_session->client_enc_alg;
        } else if (i_session->client_enc_alg == R_JWA_ALG_UNKNOWN && json_array_size(json_object_get(i_session->openid_config, "request_object_encryption_alg_values_supported"))) {
          // no signtature alg specified, use one supported by the server
          if (has_openid_config_parameter_value(i_session, "request_object_encryption_alg_values_supported", "A128KW")) {
            enc_alg = R_JWA_ALG_A128KW;
          } else if (has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "A192KW")) {
            enc_alg = R_JWA_ALG_A192KW;
          } else if (has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "A256KW")) {
            enc_alg = R_JWA_ALG_A256KW;
          } else if (has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "A128GCMKW")) {
            enc_alg = R_JWA_ALG_A128GCMKW;
          } else if (has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "A192GCMKW")) {
            enc_alg = R_JWA_ALG_A192GCMKW;
          } else if (has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "A256GCMKW")) {
            enc_alg = R_JWA_ALG_A256GCMKW;
          } else if (has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "dir")) {
            enc_alg = R_JWA_ALG_DIR;
          } else if (has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "PBES2-HS256+A128KW")) {
            enc_alg = R_JWA_ALG_PBES2_H256;
          } else if (has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "PBES2-HS384+A192KW")) {
            enc_alg = R_JWA_ALG_PBES2_H384;
          } else if (has_openid_config_parameter_value(i_session, "request_object_signing_alg_values_supported", "PBES2-HS512+A256KW")) {
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
        if (i_session->client_enc != R_JWA_ENC_UNKNOWN && has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", i_get_str_parameter(i_session, I_OPT_CLIENT_ENC))) {
          enc = i_session->client_enc;
        } else if (i_session->client_enc == R_JWA_ENC_UNKNOWN && json_array_size(json_object_get(i_session->openid_config, "request_object_encryption_enc_values_supported"))) {
          if (has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A128CBC-HS256")) {
            enc = R_JWA_ENC_A128CBC;
          } else if (has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A192CBC-HS384")) {
            enc = R_JWA_ENC_A192CBC;
          } else if (has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A256CBC-HS512")) {
            enc = R_JWA_ENC_A256CBC;
          } else if (has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A128GCM")) {
            enc = R_JWA_ENC_A128GCM;
          } else if (has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A192GCM")) {
            enc = R_JWA_ENC_A192GCM;
          } else if (has_openid_config_parameter_value(i_session, "request_object_encryption_enc_values_supported", "A256GCM")) {
            enc = R_JWA_ENC_A256GCM;
          }
        }
        enc_alg = i_session->client_enc_alg;
        if ((i_session->client_enc_alg == R_JWA_ALG_RSA1_5 || i_session->client_enc_alg == R_JWA_ALG_RSA_OAEP || i_session->client_enc_alg == R_JWA_ALG_RSA_OAEP_256) && has_openid_config_parameter_value(i_session, "request_object_encryption_alg_values_supported", i_get_str_parameter(i_session, I_OPT_CLIENT_SIGN_ALG))) {
          if (!(r_jwk_key_type(jwk_enc, NULL, i_session->x5u_flags) & (R_KEY_TYPE_RSA|R_KEY_TYPE_PRIVATE))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "Invalid encrypt key type");
            has_error = 1;
          }
        } else if ((i_session->client_enc_alg == R_JWA_ALG_ECDH_ES || i_session->client_enc_alg == R_JWA_ALG_ECDH_ES_A128KW || i_session->client_enc_alg == R_JWA_ALG_ECDH_ES_A192KW || i_session->client_enc_alg == R_JWA_ALG_ECDH_ES_A256KW) && has_openid_config_parameter_value(i_session, "request_object_encryption_alg_values_supported", i_get_str_parameter(i_session, I_OPT_CLIENT_SIGN_ALG))) {
          if (!(r_jwk_key_type(jwk_enc, NULL, i_session->x5u_flags) & (R_KEY_TYPE_ECDSA|R_KEY_TYPE_PRIVATE))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "Invalid encrypt key type");
            has_error = 1;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "Invalid encrypt key parameters (pubkey)");
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

static int _i_add_token_authentication(struct _i_session * i_session, struct _u_request * request) {
  int ret = I_OK;
  jwt_t * jwt = NULL;
  jwk_t * jwk_sign = NULL;
  jwa_alg sign_alg = R_JWA_ALG_UNKNOWN;
  time_t now;
  char * jwt_str = NULL;
  
  if (i_session->token_method == I_TOKEN_AUTH_METHOD_SECRET_BASIC) {
    if (i_session->client_secret != NULL) {
      request->auth_basic_user = o_strdup(i_session->client_id);
      request->auth_basic_password = o_strdup(i_session->client_secret);
    }
  } else if (i_session->token_method == I_TOKEN_AUTH_METHOD_SECRET_POST) {
    if (i_session->client_secret != NULL) {
      u_map_put(request->map_post_body, "client_id", i_session->client_id);
      u_map_put(request->map_post_body, "client_secret", i_session->client_secret);
    }
  } else if (i_session->token_method == I_TOKEN_AUTH_METHOD_SECRET_JWT || i_session->token_method == I_TOKEN_AUTH_METHOD_PRIVATE_JWT) {
    if (i_session->token_jti != NULL) {
      time(&now);
      r_jwt_init(&jwt);
      r_jwt_set_claim_str_value(jwt, "iss", i_session->client_id);
      r_jwt_set_claim_str_value(jwt, "sub", i_session->client_id);
      r_jwt_set_claim_str_value(jwt, "aud", i_session->token_endpoint);
      r_jwt_set_claim_str_value(jwt, "jti", i_session->token_jti);
      r_jwt_set_claim_int_value(jwt, "exp", now+i_session->token_exp);
      r_jwt_set_claim_int_value(jwt, "iat", now);
      if (i_session->token_method == I_TOKEN_AUTH_METHOD_SECRET_JWT) {
        if (i_session->client_secret != NULL) {
          if ((i_session->client_sign_alg == R_JWA_ALG_HS256 || i_session->client_sign_alg == R_JWA_ALG_HS384 || i_session->client_sign_alg == R_JWA_ALG_HS512) && has_openid_config_parameter_value(i_session, "token_endpoint_auth_signing_alg_values_supported", i_get_str_parameter(i_session, I_OPT_CLIENT_SIGN_ALG))) {
            // signature alg is specified and supported by the server
            sign_alg = i_session->client_sign_alg;
          } else if (i_session->client_sign_alg == R_JWA_ALG_UNKNOWN && json_array_size(json_object_get(i_session->openid_config, "token_endpoint_auth_signing_alg_values_supported"))) {
            // no signtature alg specified, use one supported by the server
            if (has_openid_config_parameter_value(i_session, "token_endpoint_auth_signing_alg_values_supported", "HS256")) {
              sign_alg = R_JWA_ALG_HS256;
            } else if (has_openid_config_parameter_value(i_session, "token_endpoint_auth_signing_alg_values_supported", "HS384")) {
              sign_alg = R_JWA_ALG_HS384;
            } else if (has_openid_config_parameter_value(i_session, "token_endpoint_auth_signing_alg_values_supported", "HS512")) {
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
          if ((i_session->client_sign_alg == R_JWA_ALG_RS256 || i_session->client_sign_alg == R_JWA_ALG_RS384 || i_session->client_sign_alg == R_JWA_ALG_RS512 ||
               i_session->client_sign_alg == R_JWA_ALG_PS256 || i_session->client_sign_alg == R_JWA_ALG_PS384 || i_session->client_sign_alg == R_JWA_ALG_PS512) && 
               has_openid_config_parameter_value(i_session, "token_endpoint_auth_signing_alg_values_supported", i_get_str_parameter(i_session, I_OPT_CLIENT_SIGN_ALG))) {
            if (!(r_jwk_key_type(jwk_sign, NULL, i_session->x5u_flags) & (R_KEY_TYPE_RSA|R_KEY_TYPE_PRIVATE))) {
              y_log_message(Y_LOG_LEVEL_ERROR, "Invalid signing key type");
              ret = I_ERROR_PARAM;
            }
          } else if ((i_session->client_sign_alg == R_JWA_ALG_ES256 || i_session->client_sign_alg == R_JWA_ALG_ES384 || i_session->client_sign_alg == R_JWA_ALG_ES512) && has_openid_config_parameter_value(i_session, "token_endpoint_auth_signing_alg_values_supported", i_get_str_parameter(i_session, I_OPT_CLIENT_SIGN_ALG))) {
            if (!(r_jwk_key_type(jwk_sign, NULL, i_session->x5u_flags) & (R_KEY_TYPE_ECDSA|R_KEY_TYPE_PRIVATE))) {
              y_log_message(Y_LOG_LEVEL_ERROR, "Invalid signing key type");
              ret = I_ERROR_PARAM;
            }
          } else if (i_session->client_sign_alg == R_JWA_ALG_EDDSA && has_openid_config_parameter_value(i_session, "token_endpoint_auth_signing_alg_values_supported", i_get_str_parameter(i_session, I_OPT_CLIENT_SIGN_ALG))) {
            if (!(r_jwk_key_type(jwk_sign, NULL, i_session->x5u_flags) & (R_KEY_TYPE_EDDSA|R_KEY_TYPE_PRIVATE))) {
              y_log_message(Y_LOG_LEVEL_ERROR, "Invalid signing key type");
              ret = I_ERROR_PARAM;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "Invalid signing key parameters");
            ret = I_ERROR_PARAM;
          }
          r_jwt_set_sign_alg(jwt, i_session->client_sign_alg);
        } else if (!r_jwks_size(i_session->client_jwks)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "Client has no private key ");
          ret = I_ERROR_PARAM;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "Client has more than one private key, please specify one with the parameter I_OPT_CLIENT_KID");
          ret = I_ERROR_PARAM;
        }
      }
      if (ret == I_OK) {
        jwt_str = r_jwt_serialize_signed(jwt, jwk_sign, i_session->x5u_flags);
        u_map_put(request->map_post_body, "client_assertion", jwt_str);
        u_map_put(request->map_post_body, "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        o_free(jwt_str);
      }
      r_jwk_free(jwk_sign);
      r_jwt_free(jwt);
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "_i_add_token_authentication - jti required");
      ret = I_ERROR_PARAM;
    }
  }
  return ret;
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
    i_session->token_target = NULL;
    i_session->token_target_type_hint = NULL;
    i_session->token_type = NULL;
    i_session->expires_in = 0;
    i_session->id_token = NULL;
    i_session->id_token_payload = NULL;
    i_session->code = NULL;
    i_session->result = I_OK;
    i_session->error = NULL;
    i_session->error_description = NULL;
    i_session->error_uri = NULL;
    i_session->auth_method = I_AUTH_METHOD_GET;
    i_session->token_method = I_TOKEN_AUTH_METHOD_SECRET_BASIC;
    i_session->x5u_flags = 0;
    i_session->openid_config = NULL;
    i_session->openid_config_strict = I_STRICT_YES;
    i_session->issuer = NULL;
    i_session->userinfo = NULL;
    i_session->j_userinfo = NULL;
    i_session->server_kid = NULL;
    i_session->client_kid = NULL;
    i_session->client_sign_alg = R_JWA_ALG_UNKNOWN;
    i_session->client_enc_alg = R_JWA_ALG_UNKNOWN;
    i_session->client_enc = R_JWA_ENC_UNKNOWN;
    i_session->token_jti = NULL;
    i_session->token_exp = 600;
    i_session->revocation_endpoint = NULL;
    i_session->introspection_endpoint = NULL;
    i_session->registration_endpoint = NULL;
    if ((res = u_map_init(&i_session->additional_parameters)) == U_OK) {
      if ((res = u_map_init(&i_session->additional_response)) == U_OK) {
        if ((res = r_jwks_init(&i_session->server_jwks)) == RHN_OK) {
          if ((res = r_jwks_init(&i_session->client_jwks)) == RHN_OK) {
            return I_OK;
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
    u_map_clean(&i_session->additional_parameters);
    u_map_clean(&i_session->additional_response);
    r_jwks_free(i_session->server_jwks);
    r_jwks_free(i_session->client_jwks);
    json_decref(i_session->id_token_payload);
    json_decref(i_session->openid_config);
    json_decref(i_session->j_userinfo);
  }
}

int i_set_response_type(struct _i_session * i_session, uint i_value) {
  return i_set_int_parameter(i_session, I_OPT_RESPONSE_TYPE, i_value);
}

int i_set_result(struct _i_session * i_session, uint i_value) {
  return i_set_int_parameter(i_session, I_OPT_RESULT, i_value);
}

int i_set_int_parameter(struct _i_session * i_session, i_option option, uint i_value) {
  int ret = I_OK;
  if (i_session != NULL) {
    switch (option) {
      case I_OPT_RESPONSE_TYPE:
        switch (i_value) {
          case I_RESPONSE_TYPE_CODE:
          case I_RESPONSE_TYPE_TOKEN:
          case I_RESPONSE_TYPE_ID_TOKEN:
          case I_RESPONSE_TYPE_PASSWORD:
          case I_RESPONSE_TYPE_CLIENT_CREDENTIALS:
          case I_RESPONSE_TYPE_REFRESH_TOKEN:
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
      case I_OPT_OPENID_CONFIG_STRICT:
        i_session->openid_config_strict = i_value;
        break;
      case I_OPT_STATE_GENERATE:
        if (i_value) {
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
        if (i_value > 0) {
          i_session->token_exp = i_value;
        } else {
          ret = I_ERROR_PARAM;
        }
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
        if (o_strlen(s_value)) {
          i_session->userinfo = o_strdup(s_value);
          json_decref(i_session->j_userinfo);
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

int i_set_parameter_list(struct _i_session * i_session, ...) {
  uint option, i_value, ret = I_OK;
  const char * str_key, * str_value;
  va_list vl;
  
  if (i_session != NULL) {
    va_start(vl, i_session);
    for (option = va_arg(vl, uint); option != I_OPT_NONE && ret == I_OK; option = va_arg(vl, uint)) {
      switch (option) {
        case I_OPT_RESPONSE_TYPE:
        case I_OPT_RESULT:
        case I_OPT_AUTH_METHOD:
        case I_OPT_TOKEN_METHOD:
        case I_OPT_EXPIRES_IN:
        case I_OPT_STATE_GENERATE:
        case I_OPT_NONCE_GENERATE:
        case I_OPT_X5U_FLAGS:
        case I_OPT_OPENID_CONFIG_STRICT:
        case I_OPT_TOKEN_JTI_GENERATE:
        case I_OPT_TOKEN_EXP:
          i_value = va_arg(vl, uint);
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

int i_load_openid_config(struct _i_session * i_session) {
  int ret;
  struct _u_request request;
  struct _u_response response;
  
  if (i_session != NULL && i_session->openid_config_endpoint != NULL) {
    ulfius_init_request(&request);
    ulfius_init_response(&response);
     
    u_map_put(request.map_header, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR);
    u_map_put(request.map_header, "Accept", "application/json");
    request.http_url = o_strdup(i_session->openid_config_endpoint);
    if (ulfius_send_http_request(&request, &response) == U_OK) {
      if (response.status == 200) {
        if ((i_session->openid_config = ulfius_get_json_body_response(&response, NULL)) != NULL) {
          if (_i_parse_openid_config(i_session, 1) == I_OK) {
            ret = I_OK;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_load_openid_config - Error _i_parse_openid_config");
            ret = I_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_load_openid_config - Error response not in JSON format");
          ret = I_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_load_openid_config - Error invalid response status: %d", response.status);
        ret = I_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_load_openid_config - Error getting config_endpoint");
      ret = I_ERROR;
    }
    ulfius_clean_request(&request);
    ulfius_clean_response(&response);
  } else {
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_load_userinfo(struct _i_session * i_session) {
  struct _u_map header;
  int ret;
  
  u_map_init(&header);
  u_map_put(&header, "Accept", "application/json");
  ret = i_load_userinfo_custom(i_session, NULL, NULL, &header);
  u_map_clean(&header);
  
  return ret;
}

int i_load_userinfo_custom(struct _i_session * i_session, const char * http_method, struct _u_map * additional_query, struct _u_map * additional_headers) {
  int ret, res = RHN_ERROR;
  struct _u_request request;
  struct _u_response response;
  char * bearer = NULL, * url = NULL, * escaped = NULL, * token = NULL;
  const char ** keys;
  size_t i;
  int has_param;
  jwt_t * jwt;
  
  if (i_session != NULL && i_session->userinfo_endpoint != NULL && i_session->access_token != NULL) {
    ulfius_init_request(&request);
    ulfius_init_response(&response);
    
    if (o_strlen(http_method)) {
      request.http_verb = o_strdup(http_method);
    }
    if (additional_headers != NULL) {
      keys = u_map_enum_keys(additional_headers);
      for (i=0; keys[i]!=NULL; i++) {
        u_map_put(request.map_header, keys[i], u_map_get(additional_headers, keys[i]));
      }
    }
    u_map_put(request.map_header, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR);
    
    url = o_strdup(i_session->userinfo_endpoint);
    if (additional_query != NULL) {
      has_param = (o_strchr(url, '?')!=NULL);
      keys = u_map_enum_keys(additional_query);
      for (i=0; keys[i]!=NULL; i++) {
        escaped = ulfius_url_encode(u_map_get(additional_query, keys[i]));
        if (!has_param) {
          url = mstrcatf(url, "?%s=%s", keys[i], escaped);
        } else {
          url = mstrcatf(url, "&%s=%s", keys[i], escaped);
          has_param = 1;
        }
        o_free(escaped);
      }
    }
    request.http_url = url;
    
    bearer = msprintf("Bearer %s", i_session->access_token);
    if (u_map_put(request.map_header, "Authorization", bearer) == U_OK) {
      if (ulfius_send_http_request(&request, &response) == U_OK) {
        if (response.status == 200) {
          if (0 == o_strcmp("application/jwt", u_map_get_case(response.map_header, "Content-Type"))) {
            if (r_jwt_init(&jwt) == RHN_OK) {
              if (r_jwt_add_enc_jwks(jwt, i_session->client_jwks, NULL) == RHN_OK && r_jwt_add_sign_jwks(jwt, NULL, i_session->server_jwks) == RHN_OK) {
                token = o_strndup(response.binary_body, response.binary_body_length);
                if (r_jwt_parse(jwt, token, i_session->x5u_flags) == RHN_OK) {
                  if (jwt->type == R_JWT_TYPE_SIGN) {
                    res = r_jwt_verify_signature(jwt, NULL, i_session->x5u_flags);
                  } else if (jwt->type == R_JWT_TYPE_ENCRYPT) {
                    res = r_jwt_decrypt(jwt, NULL, i_session->x5u_flags);
                  } else if (jwt->type == R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT) {
                    res = r_jwt_decrypt_verify_signature_nested(jwt, NULL, i_session->x5u_flags, NULL, i_session->x5u_flags);
                  }
                  if (res == RHN_OK) {
                    json_decref(i_session->j_userinfo);
                    i_session->j_userinfo = r_jwt_get_full_claims_json_t(jwt);
                    o_free(i_session->userinfo);
                    i_session->userinfo = r_jwt_get_full_claims_str(jwt);
                    ret = I_OK;
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_load_userinfo - Error verifying jwt");
                    ret = I_ERROR;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "i_load_userinfo - Error r_jwt_parse");
                  ret = I_ERROR;
                }
                o_free(token);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "i_load_userinfo - Error adding jwks");
                ret = I_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_load_userinfo - Error r_jwt_init");
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
              y_log_message(Y_LOG_LEVEL_ERROR, "i_load_userinfo - Error getting response");
              ret = I_ERROR;
            }
          }
        } else if (response.status == 401 || response.status == 403) {
          ret = I_ERROR_UNAUTHORIZED;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_load_userinfo - Error invalid response status: %d", response.status);
          ret = I_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_load_userinfo - Error getting userinfo_endpoint");
        ret = I_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_load_userinfo - Error u_map_put");
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

uint i_get_response_type(struct _i_session * i_session) {
  return i_get_int_parameter(i_session, I_OPT_RESPONSE_TYPE);
}

uint i_get_result(struct _i_session * i_session) {
  return i_get_int_parameter(i_session, I_OPT_RESULT);
}

uint i_get_int_parameter(struct _i_session * i_session, i_option option) {
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
      case I_OPT_X5U_FLAGS:
        return i_session->x5u_flags;
        break;
      case I_OPT_OPENID_CONFIG_STRICT:
        return i_session->openid_config_strict;
        break;
      case I_OPT_TOKEN_EXP:
        return i_session->token_exp;
        break;
      default:
        return 0;
        break;
    }
  }
  return 0;
}

int i_parse_redirect_to(struct _i_session * i_session) {
  int ret = I_OK;
  struct _u_map map;
  const char * fragment = NULL, * query = NULL, * redirect_to = i_get_str_parameter(i_session, I_OPT_REDIRECT_TO);
  char * state = NULL, * query_dup = NULL;
  
  if (o_strncmp(redirect_to, i_session->redirect_uri, o_strlen(i_session->redirect_uri)) == 0) {
    // Extract fragment if response_type has id_token or token
    fragment = o_strnchr(redirect_to, o_strlen(redirect_to), '#');
    if ((i_session->response_type & I_RESPONSE_TYPE_TOKEN || i_session->response_type & I_RESPONSE_TYPE_ID_TOKEN) && fragment != NULL && has_openid_config_parameter_value(i_session, "response_modes_supported", "fragment")) {
      u_map_init(&map);
      if (extract_parameters(fragment+1, &map) == I_OK) {
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
    
    // Extract query without fragment if response_type is code only
    if (i_session->response_type & I_RESPONSE_TYPE_CODE && has_openid_config_parameter_value(i_session, "response_modes_supported", "query") && (query = o_strnchr(redirect_to, fragment!=NULL?(size_t)(fragment-redirect_to):o_strlen(redirect_to), '?')) != NULL) {
      if (fragment) {
        query_dup = o_strndup(query+1, o_strrchr(query, '#')-query-1);
      } else {
        query_dup = o_strdup(query+1);
      }
      u_map_init(&map);
      if (extract_parameters(query_dup, &map) == I_OK) {
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
      o_free(query_dup);
    }
    
    if (i_get_str_parameter(i_session, I_OPT_STATE) != NULL) {
      if (o_strcmp(i_get_str_parameter(i_session, I_OPT_STATE), state)) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "i_parse_redirect_to query - Error state invalid");
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

int i_build_auth_url_get(struct _i_session * i_session) {
  int ret;
  char * url = NULL, * escaped = NULL;
  const char ** keys = NULL;
  uint i;

  if (i_session != NULL && 
      i_session->response_type != I_RESPONSE_TYPE_NONE && 
      i_session->response_type != I_RESPONSE_TYPE_PASSWORD && 
      i_session->response_type != I_RESPONSE_TYPE_CLIENT_CREDENTIALS && 
      i_session->response_type != I_RESPONSE_TYPE_REFRESH_TOKEN && 
      i_session->redirect_uri != NULL && 
      i_session->client_id != NULL && 
      i_session->authorization_endpoint != NULL &&
      check_strict_parameters(i_session) &&
      (has_openid_config_parameter_value(i_session, "grant_types_supported", "implicit") || has_openid_config_parameter_value(i_session, "grant_types_supported", "authorization_code")) &&
      i_session->auth_method & I_AUTH_METHOD_GET) {
    escaped = ulfius_url_encode(i_session->redirect_uri);
    url = msprintf("%s?redirect_uri=%s", i_session->authorization_endpoint, escaped);
    o_free(escaped);

    escaped = ulfius_url_encode(get_response_type(i_session->response_type));
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
        
    keys = u_map_enum_keys(&i_session->additional_parameters);
        
    for (i=0; keys[i] != NULL; i++) {
      escaped = ulfius_url_encode(u_map_get(&i_session->additional_parameters, keys[i]));
      url = mstrcatf(url, "&%s=%s", keys[i], escaped);
      o_free(escaped);
    }
    ret = i_set_str_parameter(i_session, I_OPT_REDIRECT_TO, url);
    o_free(url);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "i_build_auth_url_get - Error input parameter");
    if (i_session == NULL) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "i_build_auth_url_get - i_session NULL");
    }
    if (i_session->response_type == I_RESPONSE_TYPE_NONE ||
        i_session->response_type == I_RESPONSE_TYPE_PASSWORD ||
        i_session->response_type == I_RESPONSE_TYPE_CLIENT_CREDENTIALS ||
        i_session->response_type == I_RESPONSE_TYPE_REFRESH_TOKEN) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "i_build_auth_url_get - response_type invalid");
    }
    if (i_session->authorization_endpoint == NULL) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "i_build_auth_url_get - authorization_endpoint invalid");
    }
    if (!check_strict_parameters(i_session)) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "i_build_auth_url_get - strict parameters invalid");
    }
    if (!has_openid_config_parameter_value(i_session, "grant_types_supported", "implicit") || !has_openid_config_parameter_value(i_session, "grant_types_supported", "authorization_code")) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "i_build_auth_url_get - grant_types not supported");
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
  uint i;
  char * jwt = NULL;
  
  if (i_session != NULL && 
      i_session->response_type != I_RESPONSE_TYPE_NONE && 
      i_session->response_type != I_RESPONSE_TYPE_PASSWORD && 
      i_session->response_type != I_RESPONSE_TYPE_CLIENT_CREDENTIALS && 
      i_session->response_type != I_RESPONSE_TYPE_REFRESH_TOKEN && 
      i_session->redirect_uri != NULL && 
      i_session->client_id != NULL && 
      i_session->authorization_endpoint != NULL &&
      check_strict_parameters(i_session) &&
      (has_openid_config_parameter_value(i_session, "grant_types_supported", "implicit") || has_openid_config_parameter_value(i_session, "grant_types_supported", "authorization_code"))) {
    if (ulfius_init_request(&request) != U_OK || ulfius_init_response(&response) != U_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_run_auth_request - Error initializing request or response");
      ret = I_ERROR;
    } else {
      u_map_put(request.map_header, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR);
      if (i_session->auth_method & I_AUTH_METHOD_GET) {
        if (i_session->auth_method & (I_AUTH_METHOD_JWT_SIGN_SECRET|I_AUTH_METHOD_JWT_SIGN_PRIVKEY|I_AUTH_METHOD_JWT_ENCRYPT_SECRET|I_AUTH_METHOD_JWT_ENCRYPT_PUBKEY)) {
          if ((jwt = generate_auth_jwt(i_session)) != NULL) {
            request.http_verb = o_strdup("GET");
            request.http_url = msprintf("%s?request=%s", i_session->authorization_endpoint, jwt);
            o_free(jwt);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_run_auth_request - Error generating jwt");
            ret = I_ERROR_PARAM;
          }
        } else if ((ret = i_build_auth_url_get(i_session)) == I_OK) {
          request.http_verb = o_strdup("GET");
          request.http_url = o_strdup(i_get_str_parameter(i_session, I_OPT_REDIRECT_TO));
        }
      } else if (i_session->auth_method & I_AUTH_METHOD_POST) {
        request.http_verb = o_strdup("POST");
        request.http_url = o_strdup(i_session->authorization_endpoint);
        if (i_session->auth_method & (I_AUTH_METHOD_JWT_SIGN_SECRET|I_AUTH_METHOD_JWT_SIGN_PRIVKEY|I_AUTH_METHOD_JWT_ENCRYPT_SECRET|I_AUTH_METHOD_JWT_ENCRYPT_PUBKEY)) {
          if ((jwt = generate_auth_jwt(i_session)) != NULL) {
            u_map_put(request.map_post_body, "request", jwt);
            o_free(jwt);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_run_auth_request - Error generating jwt");
            ret = I_ERROR_PARAM;
          }
        } else {
          u_map_put(request.map_post_body, "redirect_uri", i_session->redirect_uri);
          u_map_put(request.map_post_body, "response_type", get_response_type(i_session->response_type));
          u_map_put(request.map_post_body, "client_id", i_session->client_id);
          if (i_session->state != NULL) {
            u_map_put(request.map_post_body, "state", i_session->state);
          }
          if (i_session->scope != NULL) {
            u_map_put(request.map_post_body, "scope", i_session->scope);
          }
          if (i_session->nonce != NULL) {
            u_map_put(request.map_post_body, "nonce", i_session->nonce);
          }
          
          keys = u_map_enum_keys(&i_session->additional_parameters);
          
          for (i=0; keys[i] != NULL; i++) {
            u_map_put(request.map_post_body, keys[i], u_map_get(&i_session->additional_parameters, keys[i]));
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

int i_run_token_request(struct _i_session * i_session) {
  int ret = I_OK, res;
  struct _u_request request;
  struct _u_response response;
  json_t * j_response;
  
  if (i_session != NULL && i_session->token_endpoint != NULL) {
    if (i_session->response_type & I_RESPONSE_TYPE_CODE) {
      if (i_session->redirect_uri != NULL && 
          i_session->client_id != NULL && 
          i_session->code != NULL &&
          check_strict_parameters(i_session) &&
          has_openid_config_parameter_value(i_session, "grant_types_supported", "authorization_code")) {
        ulfius_init_request(&request);
        ulfius_init_response(&response);
        u_map_put(request.map_header, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR);
        u_map_put(request.map_header, "Accept", "application/json");
        request.http_verb = o_strdup("POST");
        request.http_url = o_strdup(i_session->token_endpoint);
        u_map_put(request.map_post_body, "grant_type", "authorization_code");
        u_map_put(request.map_post_body, "code", i_session->code);
        u_map_put(request.map_post_body, "redirect_uri", i_session->redirect_uri);
        u_map_put(request.map_post_body, "client_id", i_session->client_id);
        if ((res = _i_add_token_authentication(i_session, &request)) == I_OK) {
          if (ulfius_send_http_request(&request, &response) == U_OK) {
            if (response.status == 200 || response.status == 400) {
              j_response = ulfius_get_json_body_response(&response, NULL);
              if (j_response != NULL) {
                if (_i_parse_token_response(i_session, response.status, j_response) == I_OK) {
                  ret = response.status == 200?I_OK:I_ERROR_PARAM;
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request code - Error _i_parse_token_response");
                  ret = I_ERROR_PARAM;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request code - Error parsing JSON response %.*s", response.binary_body_length, response.binary_body);
                ret = I_ERROR;
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
        if (i_session->client_id == NULL) {
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
            ulfius_init_request(&request);
            ulfius_init_response(&response);
            u_map_put(request.map_header, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR);
            u_map_put(request.map_header, "Accept", "application/json");
            request.http_verb = o_strdup("POST");
            request.http_url = o_strdup(i_session->token_endpoint);
            u_map_put(request.map_post_body, "grant_type", "password");
            u_map_put(request.map_post_body, "username", i_session->username);
            u_map_put(request.map_post_body, "password", i_session->user_password);
            if (i_session->scope != NULL) {
              u_map_put(request.map_post_body, "scope", i_session->scope);
            }
            if ((res = _i_add_token_authentication(i_session, &request)) == I_OK) {
              if (ulfius_send_http_request(&request, &response) == U_OK) {
                if (response.status == 200 || response.status == 400) {
                  j_response = ulfius_get_json_body_response(&response, NULL);
                  if (j_response != NULL) {
                    if (_i_parse_token_response(i_session, response.status, j_response) == I_OK) {
                      ret = response.status == 200?I_OK:I_ERROR_PARAM;
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request password - Error _i_parse_token_response");
                      ret = I_ERROR_PARAM;
                    }
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request password - Error parsing JSON response");
                    ret = I_ERROR;
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
          if (i_session->client_id != NULL && i_session->client_secret != NULL) {
            ulfius_init_request(&request);
            ulfius_init_response(&response);
            u_map_put(request.map_header, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR);
            u_map_put(request.map_header, "Accept", "application/json");
            request.http_verb = o_strdup("POST");
            request.http_url = o_strdup(i_session->token_endpoint);
            u_map_put(request.map_post_body, "grant_type", "client_credentials");
            if (i_session->scope != NULL) {
              u_map_put(request.map_post_body, "scope", i_session->scope);
            }
            if ((res = _i_add_token_authentication(i_session, &request)) == I_OK) {
              if (ulfius_send_http_request(&request, &response) == U_OK) {
                if (response.status == 200 || response.status == 400) {
                  j_response = ulfius_get_json_body_response(&response, NULL);
                  if (j_response != NULL) {
                    if (_i_parse_token_response(i_session, response.status, j_response) == I_OK) {
                      ret = response.status == 200?I_OK:I_ERROR_PARAM;
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request client_credentials - Error _i_parse_token_response");
                      ret = I_ERROR_PARAM;
                    }
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request client_credentials - Error parsing JSON response");
                    ret = I_ERROR;
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
            ulfius_init_request(&request);
            ulfius_init_response(&response);
            u_map_put(request.map_header, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR);
            u_map_put(request.map_header, "Accept", "application/json");
            request.http_verb = o_strdup("POST");
            request.http_url = o_strdup(i_session->token_endpoint);
            u_map_put(request.map_post_body, "grant_type", "refresh_token");
            if (i_session->scope != NULL) {
              u_map_put(request.map_post_body, "scope", i_session->scope);
            }
            if ((res = _i_add_token_authentication(i_session, &request)) == I_OK) {
              if (ulfius_send_http_request(&request, &response) == U_OK) {
                if (response.status == 200 || response.status == 400) {
                  j_response = ulfius_get_json_body_response(&response, NULL);
                  if (j_response != NULL) {
                    if (_i_parse_token_response(i_session, response.status, j_response) == I_OK) {
                      ret = response.status == 200?I_OK:I_ERROR_PARAM;
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request refresh - Error _i_parse_token_response");
                      ret = I_ERROR_PARAM;
                    }
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "i_run_token_request refresh - Error parsing JSON response");
                    ret = I_ERROR;
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
  int ret = I_ERROR_PARAM, res = RHN_ERROR;
  jwt_t * jwt = NULL;
  size_t hash_len = 128, hash_encoded_len = 128;
  unsigned char hash[128], hash_encoded[128] = {0};
  int alg = GNUTLS_DIG_UNKNOWN;
  gnutls_datum_t hash_data;
  
  if (i_session != NULL && i_session->id_token != NULL) {
    if (r_jwt_init(&jwt) == RHN_OK) {
      if (r_jwt_parse(jwt, i_session->id_token, i_session->x5u_flags) == RHN_OK) {
        if (r_jwt_add_sign_jwks(jwt, NULL, i_session->server_jwks) == RHN_OK && r_jwt_add_enc_jwks(jwt, i_session->client_jwks, NULL) == RHN_OK) {
          if (jwt->type == R_JWT_TYPE_SIGN) {
            res = r_jwt_verify_signature(jwt, NULL, i_session->x5u_flags);
          } else if (jwt->type == R_JWT_TYPE_ENCRYPT) {
            res = r_jwt_decrypt(jwt, NULL, i_session->x5u_flags);
          } else if (jwt->type == R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT) {
            res = r_jwt_decrypt_verify_signature_nested(jwt, NULL, i_session->x5u_flags, NULL, i_session->x5u_flags);
          }
          if (res == RHN_OK) {
            json_decref(i_session->id_token_payload);
            if ((i_session->id_token_payload = r_jwt_get_full_claims_json_t(jwt)) != NULL) {
              if (r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, i_session->issuer,
                                             R_JWT_CLAIM_STR, "nonce", i_session->nonce,
                                             R_JWT_CLAIM_SUB, NULL,
                                             R_JWT_CLAIM_AUD, NULL,
                                             R_JWT_CLAIM_EXP, R_JWT_CLAIM_NOW,
                                             R_JWT_CLAIM_IAT, R_JWT_CLAIM_NOW,
                                             R_JWT_CLAIM_NOP) == RHN_OK) {
                ret = I_OK;
                if (json_object_get(i_session->id_token_payload, "at_hash") != NULL) {
                  if (i_session->access_token != NULL) {
                    alg = GNUTLS_DIG_UNKNOWN;
                    if ((r_jwt_get_sign_alg(jwt) == R_JWA_ALG_RS256 && has_openid_config_parameter_value(i_session, "id_token_signing_alg_values_supported", "HS256")) || 
                    (r_jwt_get_sign_alg(jwt) == R_JWA_ALG_RS256 && has_openid_config_parameter_value(i_session, "id_token_signing_alg_values_supported", "RS256")) || 
                    (r_jwt_get_sign_alg(jwt) == R_JWA_ALG_ES256 && has_openid_config_parameter_value(i_session, "id_token_signing_alg_values_supported", "ES256"))) {
                      alg = GNUTLS_DIG_SHA256;
                    } else if ((r_jwt_get_sign_alg(jwt) == R_JWA_ALG_HS384 && has_openid_config_parameter_value(i_session, "id_token_signing_alg_values_supported", "HS384")) || 
                    (r_jwt_get_sign_alg(jwt) == R_JWA_ALG_RS384 && has_openid_config_parameter_value(i_session, "id_token_signing_alg_values_supported", "RS384")) || 
                    (r_jwt_get_sign_alg(jwt) == R_JWA_ALG_ES384 && has_openid_config_parameter_value(i_session, "id_token_signing_alg_values_supported", "ES384"))) {
                      alg = GNUTLS_DIG_SHA384;
                    } else if ((r_jwt_get_sign_alg(jwt) == R_JWA_ALG_HS512 && has_openid_config_parameter_value(i_session, "id_token_signing_alg_values_supported", "HS512")) || 
                    (r_jwt_get_sign_alg(jwt) == R_JWA_ALG_RS512 && has_openid_config_parameter_value(i_session, "id_token_signing_alg_values_supported", "RS512")) || 
                    (r_jwt_get_sign_alg(jwt) == R_JWA_ALG_ES512 && has_openid_config_parameter_value(i_session, "id_token_signing_alg_values_supported", "ES512"))) {
                      alg = GNUTLS_DIG_SHA384;
                    }
                    if (alg != GNUTLS_DIG_UNKNOWN) {
                      hash_data.data = (unsigned char*)i_session->access_token;
                      hash_data.size = o_strlen(i_session->access_token);
                      if (gnutls_fingerprint(alg, &hash_data, hash, &hash_len) == GNUTLS_E_SUCCESS) {
                        if (o_base64url_encode(hash, hash_len/2, hash_encoded, &hash_encoded_len)) {
                          if (o_strcmp((const char *)hash_encoded, json_string_value(json_object_get(i_session->id_token_payload, "at_hash"))) != 0) {
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
                    alg = GNUTLS_DIG_UNKNOWN;
                    if (r_jwt_get_sign_alg(jwt) == R_JWA_ALG_HS256 || r_jwt_get_sign_alg(jwt) == R_JWA_ALG_RS256 || r_jwt_get_sign_alg(jwt) == R_JWA_ALG_ES256) {
                      alg = GNUTLS_DIG_SHA256;
                    } else if (r_jwt_get_sign_alg(jwt) == R_JWA_ALG_HS384 || r_jwt_get_sign_alg(jwt) == R_JWA_ALG_RS384 || r_jwt_get_sign_alg(jwt) == R_JWA_ALG_ES384) {
                      alg = GNUTLS_DIG_SHA384;
                    } else if (r_jwt_get_sign_alg(jwt) == R_JWA_ALG_HS512 || r_jwt_get_sign_alg(jwt) == R_JWA_ALG_RS512 || r_jwt_get_sign_alg(jwt) == R_JWA_ALG_ES512) {
                      alg = GNUTLS_DIG_SHA384;
                    }
                    if (alg != GNUTLS_DIG_UNKNOWN) {
                      hash_data.data = (unsigned char*)i_session->code;
                      hash_data.size = o_strlen(i_session->code);
                      if (gnutls_fingerprint(alg, &hash_data, hash, &hash_len) == GNUTLS_E_SUCCESS) {
                        if (o_base64url_encode(hash, hash_len/2, hash_encoded, &hash_encoded_len)) {
                          if (o_strcmp((const char *)hash_encoded, json_string_value(json_object_get(i_session->id_token_payload, "c_hash"))) != 0) {
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
              } else {
                y_log_message(Y_LOG_LEVEL_DEBUG, "i_verify_id_token - invalid JWT claims");
                ret = I_ERROR_PARAM;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_id_token - Error extracting claims from id_token");
              ret = I_ERROR;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_id_token - Error id_token validation");
            ret = I_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_id_token - Error Adding JWKS to jwt");
          ret = I_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_verify_id_token - Error parsing id_token");
        ret = I_ERROR;
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

int i_revoke_token(struct _i_session * i_session) {
  int ret;
  struct _u_request request;
  struct _u_response response;
  char * bearer = NULL;
  
  if (i_session != NULL && o_strlen(i_session->revocation_endpoint) && o_strlen(i_session->token_target)) {
    if (ulfius_init_request(&request) != U_OK || ulfius_init_response(&response) != U_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_revoke_token - Error initializing request or response");
      ret = I_ERROR;
    } else {
      ret = I_OK;
      request.http_verb = o_strdup("POST");
      request.http_url = o_strdup(i_session->revocation_endpoint);
      u_map_put(request.map_header, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR);
      if (o_strlen(i_session->access_token)) {
        bearer = msprintf("Bearer %s", i_session->access_token);
        if (u_map_put(request.map_header, "Authorization", bearer) != U_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_revoke_token - Error setting bearer token");
          ret = I_ERROR;
        }
        o_free(bearer);
      }
      if (u_map_put(request.map_post_body, "token", i_session->token_target) != U_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_revoke_token - Error setting target token");
        ret = I_ERROR;
      }
      if (o_strlen(i_session->token_target_type_hint)) {
        if (u_map_put(request.map_post_body, "token_type_hint", i_session->token_target_type_hint) != U_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_revoke_token - Error setting target token type hint");
          ret = I_ERROR;
        }
      }
      if (ret == I_OK) {
        if (ulfius_send_http_request(&request, &response) == U_OK) {
          if (response.status == 400 || response.status == 404 || response.status == 403) {
            ret = I_ERROR_PARAM;
          } else if (response.status != 200) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_revoke_token - Error revoking token");
            ret = I_ERROR;
          }
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

int i_introspect_token(struct _i_session * i_session, json_t ** j_result) {
  int ret;
  struct _u_request request;
  struct _u_response response;
  char * bearer = NULL;
  
  if (i_session != NULL && o_strlen(i_session->introspection_endpoint) && o_strlen(i_session->token_target)) {
    if (ulfius_init_request(&request) != U_OK || ulfius_init_response(&response) != U_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_introspect_token - Error initializing request or response");
      ret = I_ERROR;
    } else {
      ret = I_OK;
      request.http_verb = o_strdup("POST");
      request.http_url = o_strdup(i_session->introspection_endpoint);
      u_map_put(request.map_header, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR);
      if (o_strlen(i_session->access_token)) {
        bearer = msprintf("Bearer %s", i_session->access_token);
        if (u_map_put(request.map_header, "Authorization", bearer) != U_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_introspect_token - Error setting bearer token");
          ret = I_ERROR;
        }
        o_free(bearer);
      }
      if (u_map_put(request.map_post_body, "token", i_session->token_target) != U_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_introspect_token - Error setting target token");
        ret = I_ERROR;
      }
      if (o_strlen(i_session->token_target_type_hint)) {
        if (u_map_put(request.map_post_body, "token_type_hint", i_session->token_target_type_hint) != U_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_introspect_token - Error setting target token type hint");
          ret = I_ERROR;
        }
      }
      if (ret == I_OK) {
        if (ulfius_send_http_request(&request, &response) == U_OK) {
          if (response.status == 200 && j_result != NULL) {
            *j_result = ulfius_get_json_body_response(&response, NULL);
          } else if (response.status == 400 || response.status == 404 || response.status == 403) {
            ret = I_ERROR_PARAM;
          } else if (response.status != 200) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_introspect_token - Error introspecting token");
            ret = I_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_introspect_token - Error sending http request");
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

int i_register_client(struct _i_session * i_session, json_t * j_parameters, int update_session, json_t ** j_result) {
  int ret;
  struct _u_request request;
  struct _u_response response;
  char * bearer = NULL;
  json_t * j_response;
  
  if (i_session != NULL && o_strlen(i_session->registration_endpoint) && json_string_length(json_array_get(json_object_get(j_parameters, "redirect_uris"), 0))) {
    if (ulfius_init_request(&request) != U_OK || ulfius_init_response(&response) != U_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "i_register_client - Error initializing request or response");
      ret = I_ERROR;
    } else {
      ret = I_OK;
      request.http_verb = o_strdup("POST");
      request.http_url = o_strdup(i_session->registration_endpoint);
      u_map_put(request.map_header, "User-Agent", "Iddawc/" IDDAWC_VERSION_STR);
      if (o_strlen(i_session->access_token)) {
        bearer = msprintf("Bearer %s", i_session->access_token);
        if (u_map_put(request.map_header, "Authorization", bearer) != U_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_register_client - Error setting bearer token");
          ret = I_ERROR;
        }
        o_free(bearer);
      }
      if (ulfius_set_json_body_request(&request, j_parameters) != U_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "i_register_client - Error setting parameters");
        ret = I_ERROR;
      }
      if (ret == I_OK) {
        if (ulfius_send_http_request(&request, &response) == U_OK) {
          if (response.status == 200) {
            j_response = ulfius_get_json_body_response(&response, NULL);
            if (update_session) {
              i_set_str_parameter(i_session, I_OPT_CLIENT_ID, json_string_value(json_object_get(j_response, "client_id")));
              i_set_str_parameter(i_session, I_OPT_CLIENT_SECRET, json_string_value(json_object_get(j_response, "client_secret")));
              i_set_str_parameter(i_session, I_OPT_REDIRECT_URI, json_string_value(json_array_get(json_object_get(j_response, "redirect_uris"), 0)));
            }
            if (j_result != NULL) {
              *j_result = json_incref(j_response);
            }
            json_decref(j_response);
          } else if (response.status == 400 || response.status == 404 || response.status == 403) {
            ret = I_ERROR_PARAM;
          } else if (response.status != 200) {
            y_log_message(Y_LOG_LEVEL_ERROR, "i_register_client - Error registering client");
            ret = I_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "i_register_client - Error sending http request");
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

json_t * i_export_session_json_t(struct _i_session * i_session) {
  json_t * j_return = NULL;
  if (i_session != NULL) {
    j_return = json_pack("{ si ss* ss* ss* ss*  ss* ss* ss* ss* ss*  so so ss* ss* ss*  ss* si ss* ss* ss*  ss* ss* ss* ss* si  ss* sO*  si si so* si sO*  si ss* ss* ss* ss* ss* ss* ss* ss* si  ss* ss* ss* ss* ss* }",
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
                         
                         "additional_parameters", export_u_map(&i_session->additional_parameters),
                         "additional_response", export_u_map(&i_session->additional_response),
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
                         
                         "id_token", i_get_str_parameter(i_session, I_OPT_ID_TOKEN),
                         "id_token_payload", i_session->id_token_payload,
                         
                         "auth_method", i_get_int_parameter(i_session, I_OPT_AUTH_METHOD),
                         "token_method", i_get_int_parameter(i_session, I_OPT_TOKEN_METHOD),
                         "jwks", r_jwks_export_to_json_t(i_session->server_jwks),
                         "x5u_flags", i_get_int_parameter(i_session, I_OPT_X5U_FLAGS),
                         "openid_config", i_session->openid_config,
                         
                         "openid_config_strict", i_get_int_parameter(i_session, I_OPT_OPENID_CONFIG_STRICT),
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
                         "registration_endpoint", i_get_str_parameter(i_session, I_OPT_REGISTRATION_ENDPOINT));
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
                                     I_OPT_ID_TOKEN, json_string_value(json_object_get(j_import, "id_token")),
                                     I_OPT_USERNAME, json_string_value(json_object_get(j_import, "username")),
                                     I_OPT_AUTH_METHOD, (int)json_integer_value(json_object_get(j_import, "auth_method")),
                                     I_OPT_TOKEN_METHOD, (int)json_integer_value(json_object_get(j_import, "token_method")),
                                     I_OPT_USER_PASSWORD, json_string_value(json_object_get(j_import, "user_password")),
                                     I_OPT_X5U_FLAGS, (int)json_integer_value(json_object_get(j_import, "x5u_flags")),
                                     I_OPT_OPENID_CONFIG_STRICT, (int)json_integer_value(json_object_get(j_import, "openid_config_strict")),
                                     I_OPT_ISSUER, json_string_value(json_object_get(j_import, "issuer")),
                                     I_OPT_USERINFO, json_string_value(json_object_get(j_import, "userinfo")),
                                     I_OPT_SERVER_KID, json_string_value(json_object_get(j_import, "server-kid")),
                                     I_OPT_CLIENT_KID, json_string_value(json_object_get(j_import, "client-kid")),
                                     I_OPT_CLIENT_SIGN_ALG, json_string_value(json_object_get(j_import, "sig-alg")),
                                     I_OPT_CLIENT_ENC_ALG, json_string_value(json_object_get(j_import, "enc-alg")),
                                     I_OPT_CLIENT_ENC, json_string_value(json_object_get(j_import, "enc")),
                                     I_OPT_TOKEN_JTI, json_string_value(json_object_get(j_import, "token_jti")),
                                     I_OPT_TOKEN_EXP, json_integer_value(json_object_get(j_import, "token_exp")),
                                     I_OPT_TOKEN_TARGET, json_string_value(json_object_get(j_import, "token_target")),
                                     I_OPT_TOKEN_TARGET_TYPE_HINT, json_string_value(json_object_get(j_import, "token_target_type_hint")),
                                     I_OPT_REVOCATION_ENDPOINT, json_string_value(json_object_get(j_import, "revocation_endpoint")),
                                     I_OPT_INTROSPECTION_ENDPOINT, json_string_value(json_object_get(j_import, "introspection_endpoint")),
                                     I_OPT_REGISTRATION_ENDPOINT, json_string_value(json_object_get(j_import, "registration_endpoint")),
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
      i_session->id_token_payload = json_deep_copy(json_object_get(j_import, "id_token_payload"));
      i_session->openid_config = json_deep_copy(json_object_get(j_import, "openid_config"));
      if (json_object_get(j_import, "jwks") != NULL && r_jwks_import_from_json_t(i_session->server_jwks, json_object_get(j_import, "jwks")) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "i_import_session_json_t - Error r_jwks_import_from_json_t");
        ret = I_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "i_import_session_json_t - Error i_set_parameter_list");
    }
  } else {
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
