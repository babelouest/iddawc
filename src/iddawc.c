/**
 * 
 * Iddawc OAuth2 client library
 * 
 * iddawc.h: structures and functions declarations
 * 
 * Copyright 2019 Nicolas Mora <mail@babelouest.org>
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
#include <yder.h>

#include "iddawc.h"

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

static void parse_redirect_url_parameters(struct _i_session * i_session, struct _u_map * map) {
  const char ** keys = u_map_enum_keys(map);
  size_t i;
  
  for (i=0; keys[i] != NULL; i++) {
    if (0 == o_strcasecmp(keys[i], "code")) {
      i_set_parameter(i_session, I_OPT_CODE, u_map_get(map, keys[i]));
    } else if (0 == o_strcasecmp(keys[i], "id_token")) {
      i_set_parameter(i_session, I_OPT_ID_TOKEN, u_map_get(map, keys[i]));
    } else if (0 == o_strcasecmp(keys[i], "access_token")) {
      i_set_parameter(i_session, I_OPT_ACCESS_TOKEN, u_map_get(map, keys[i]));
    } else if (0 == o_strcasecmp(keys[i], "error")) {
      i_set_result(i_session, I_ERROR_UNAUTHORIZED);
      i_set_parameter(i_session, I_OPT_ERROR, u_map_get(map, keys[i]));
    } else if (0 == o_strcasecmp(keys[i], "error_description")) {
      i_set_result(i_session, I_ERROR_UNAUTHORIZED);
      i_set_parameter(i_session, I_OPT_ERROR_DESCRIPTION, u_map_get(map, keys[i]));
    } else if (0 == o_strcasecmp(keys[i], "error_uri")) {
      i_set_result(i_session, I_ERROR_UNAUTHORIZED);
      i_set_parameter(i_session, I_OPT_ERROR_URI, u_map_get(map, keys[i]));
    }
  }
}

int i_init_session(struct _i_session * i_session) {
  int res;
  
  if (i_session != NULL) {
    i_session->response_type = I_RESPONSE_TYPE_NONE;
    i_session->scope = NULL;
    i_session->nonce = NULL;
    i_session->redirect_url = NULL;
    i_session->redirect_to = NULL;
    i_session->state = NULL;
    i_session->client_id = NULL;
    i_session->client_secret = NULL;
    i_session->authorization_endpoint = NULL;
    i_session->token_endpoint = NULL;
    i_session->openid_config_endpoint = NULL;
    i_session->access_token_validation_endpoint = NULL;
    i_session->refresh_token = NULL;
    i_session->access_token = NULL;
    i_session->code = NULL;
    i_session->result = I_OK;
    i_session->error = NULL;
    i_session->error_description = NULL;
    i_session->error_uri = NULL;
    i_session->refresh_token = NULL;
    i_session->access_token = NULL;
    i_session->id_token = NULL;
    i_session->glewlwyd_api_url = NULL;
    i_session->glewlwyd_cookie_session = NULL;
    if ((res = u_map_init(&i_session->additional_parameters)) == U_OK) {
      return I_OK;
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
    o_free(i_session->redirect_url);
    o_free(i_session->redirect_to);
    o_free(i_session->state);
    o_free(i_session->client_id);
    o_free(i_session->client_secret);
    o_free(i_session->authorization_endpoint);
    o_free(i_session->token_endpoint);
    o_free(i_session->openid_config_endpoint);
    o_free(i_session->code);
    o_free(i_session->error);
    o_free(i_session->error_description);
    o_free(i_session->error_uri);
    o_free(i_session->refresh_token);
    o_free(i_session->access_token);
    o_free(i_session->id_token);
    o_free(i_session->glewlwyd_api_url);
    o_free(i_session->glewlwyd_cookie_session);
    u_map_clean(&i_session->additional_parameters);
  }
}

int i_set_response_type(struct _i_session * i_session, uint i_value) {
  return i_set_flag_parameter(i_session, I_OPT_RESPONSE_TYPE, i_value);
}

int i_set_result(struct _i_session * i_session, uint i_value) {
  return i_set_flag_parameter(i_session, I_OPT_RESULT, i_value);
}

int i_set_flag_parameter(struct _i_session * i_session, uint option, uint i_value) {
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
          case I_RESPONSE_TYPE_TOKEN|I_RESPONSE_TYPE_CODE|I_RESPONSE_TYPE_ID_TOKEN:
            i_session->response_type = i_value;
            break;
          default:
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
            ret = I_ERROR_PARAM;
            break;
        }
        break;
      default:
        ret = I_ERROR_PARAM;
        break;
    }
  } else {
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_set_parameter(struct _i_session * i_session, uint option, const char * s_value) {
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
        } else {
          o_free(i_session->scope);
          i_session->scope = NULL;
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
        o_free(i_session->redirect_url);
        if (o_strlen(s_value)) {
          i_session->redirect_url = o_strdup(s_value);
        } else {
          i_session->redirect_url = NULL;
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
      case I_OPT_ACCESS_TOKEN_VALIDATION_ENDPOINT:
        o_free(i_session->access_token_validation_endpoint);
        if (o_strlen(s_value)) {
          i_session->access_token_validation_endpoint = o_strdup(s_value);
        } else {
          i_session->access_token_validation_endpoint = NULL;
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
      case I_OPT_GLEWLWYD_API_URL:
        o_free(i_session->glewlwyd_api_url);
        if (o_strlen(s_value)) {
          i_session->glewlwyd_api_url = o_strdup(s_value);
        } else {
          i_session->glewlwyd_api_url = NULL;
        }
        break;
      case I_OPT_GLEWLWYD_COOKIE_SESSION:
        o_free(i_session->glewlwyd_cookie_session);
        if (o_strlen(s_value)) {
          i_session->glewlwyd_cookie_session = o_strdup(s_value);
        } else {
          i_session->glewlwyd_cookie_session = NULL;
        }
        break;
      default:
        ret = I_ERROR_PARAM;
        break;
    }
  } else {
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

int set_parameter_list(struct _i_session * i_session, ...) {
  uint option, i_value, ret = I_OK;
  const char * str_key, * str_value;
  va_list vl;
  
  va_start(vl, i_session);
  for (option = va_arg(vl, uint); option != I_OPT_NONE && ret == I_OK; option = va_arg(vl, uint)) {
    switch (option) {
      case I_OPT_RESPONSE_TYPE:
        i_value = va_arg(vl, uint);
      ret = i_set_response_type(i_session, i_value);
      break;
      case I_OPT_RESULT:
        i_value = va_arg(vl, uint);
      ret = i_set_result(i_session, i_value);
      break;
      case I_OPT_SCOPE:
      case I_OPT_STATE:
      case I_OPT_NONCE:
      case I_OPT_REDIRECT_URI:
      case I_OPT_REDIRECT_TO:
      case I_OPT_CLIENT_ID:
      case I_OPT_CLIENT_SECRET:
      case I_OPT_AUTH_ENDPOINT:
      case I_OPT_TOKEN_ENDPOINT:
      case I_OPT_OPENID_CONFIG_ENDPOINT:
      case I_OPT_ACCESS_TOKEN_VALIDATION_ENDPOINT:
      case I_OPT_ERROR:
      case I_OPT_ERROR_DESCRIPTION:
      case I_OPT_ERROR_URI:
      case I_OPT_CODE:
      case I_OPT_REFRESH_TOKEN:
      case I_OPT_ACCESS_TOKEN:
      case I_OPT_ID_TOKEN:
      case I_OPT_GLEWLWYD_API_URL:
      case I_OPT_GLEWLWYD_COOKIE_SESSION:
        str_value = va_arg(vl, const char *);
      ret = i_set_parameter(i_session, option, str_value);
      break;
      case I_OPT_ADDITIONAL_PARAMETER:
        str_key = va_arg(vl, const char *);
        str_value = va_arg(vl, const char *);
      ret = i_set_additional_parameter(i_session, str_key, str_value);
      break;
      default:
        ret = I_ERROR_PARAM;
      break;
    }
  }
  va_end(vl);
  return ret;
}

uint i_get_response_type(struct _i_session * i_session) {
  return i_get_flag_parameter(i_session, I_OPT_RESPONSE_TYPE);
}

uint i_get_result(struct _i_session * i_session) {
  return i_get_flag_parameter(i_session, I_OPT_RESULT);
}

uint i_get_flag_parameter(struct _i_session * i_session, uint option) {
  if (i_session != NULL) {
    switch (option) {
      case I_OPT_RESPONSE_TYPE:
        return i_session->response_type;
        break;
      case I_OPT_RESULT:
        return i_session->result;
        break;
      default:
        return 0;
        break;
    }
  }
  return 0;
}

const char * i_get_parameter(struct _i_session * i_session, uint option) {
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
        result = (const char *)i_session->redirect_url;
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
      case I_OPT_ACCESS_TOKEN_VALIDATION_ENDPOINT:
        result = (const char *)i_session->access_token_validation_endpoint;
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
      case I_OPT_GLEWLWYD_API_URL:
        result = (const char *)i_session->glewlwyd_api_url;
        break;
      case I_OPT_GLEWLWYD_COOKIE_SESSION:
        result = (const char *)i_session->glewlwyd_cookie_session;
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

int i_run_auth_request(struct _i_session * i_session) {
  int ret = I_OK;
  struct _u_request request;
  struct _u_response response;
  char * url = NULL, * escaped = NULL;
  const char ** keys = NULL, * fragment = NULL, * query = NULL;
  uint i;
  struct _u_map map;
  
  if (i_session != NULL && 
      i_session->response_type != I_RESPONSE_TYPE_NONE && 
      i_session->response_type != I_RESPONSE_TYPE_PASSWORD && 
      i_session->response_type != I_RESPONSE_TYPE_CLIENT_CREDENTIALS && 
      i_session->response_type != I_RESPONSE_TYPE_REFRESH_TOKEN && 
      i_session->redirect_url != NULL && 
      i_session->client_id != NULL && 
      i_session->authorization_endpoint != NULL) {
    if (ulfius_init_request(&request) != U_OK || ulfius_init_response(&response) != U_OK) {
      ret = I_ERROR;
    } else {
      escaped = ulfius_url_encode(i_session->redirect_url);
      url = msprintf("%s?redirect_url=%s&response_type=%s", i_session->authorization_endpoint, escaped, get_response_type(i_session->response_type));
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
      
      request.http_url = url;
      
      if (ulfius_send_http_request(&request, &response) == U_OK) {
        if (response.status == 302) {
          i_set_parameter(i_session, I_OPT_REDIRECT_TO, u_map_get_case(response.map_header, "Location"));
          if (o_strncmp(u_map_get_case(response.map_header, "Location"), i_session->redirect_url, o_strlen(i_session->redirect_url)) == 0) {
            // Parse redirect url to extract data
            
            // Extract fragment
            if ((fragment = o_strnchr(i_get_parameter(i_session, I_OPT_REDIRECT_TO), o_strlen(i_get_parameter(i_session, I_OPT_REDIRECT_TO)), '#')) != NULL) {
              u_map_init(&map);
              fragment++;
              if (extract_parameters(fragment, &map) == I_OK) {
                parse_redirect_url_parameters(i_session, &map);
                if ((i_get_parameter(i_session, I_OPT_STATE) != NULL || u_map_get(&map, "state") != NULL) && o_strcmp(i_get_parameter(i_session, I_OPT_STATE), u_map_get(&map, "state"))) {
                  ret = I_ERROR_SERVER;
                }
              }
              u_map_clean(&map);
            }
            
            // Extract query without fragment
            if ((query = o_strnchr(i_get_parameter(i_session, I_OPT_REDIRECT_TO), fragment!=NULL?(size_t)(i_get_parameter(i_session, I_OPT_REDIRECT_TO)-fragment):o_strlen(i_get_parameter(i_session, I_OPT_REDIRECT_TO)), '?')) != NULL) {
              u_map_init(&map);
              query++;
              if (extract_parameters(query, &map) == I_OK) {
                parse_redirect_url_parameters(i_session, &map);
                if ((i_get_parameter(i_session, I_OPT_STATE) != NULL || u_map_get(&map, "state") != NULL) && o_strcmp(i_get_parameter(i_session, I_OPT_STATE), u_map_get(&map, "state"))) {
                  ret = I_ERROR_SERVER;
                }
              }
              u_map_clean(&map);
            }
          }
        } else if (response.status == 400) {
          ret = I_ERROR_PARAM;
        } else {
          ret = I_ERROR;
        }
      } else {
        ret = I_ERROR;
      }
      ulfius_clean_request(&request);
      ulfius_clean_response(&response);
    }
  } else {
    ret = I_ERROR_PARAM;
  }
  return ret;
}
