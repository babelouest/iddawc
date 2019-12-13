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

#include "iddawc.h"

int i_init_session(struct _i_session * i_session) {
  int res;
  
  if (i_session != NULL) {
    i_session->response_type = I_RESPONSE_TYPE_NONE;
    i_session->scope = NULL;
    i_session->nonce = NULL;
    i_session->redirect_url = NULL;
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
    i_session->result_message = NULL;
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
    o_free(i_session->state);
    o_free(i_session->client_id);
    o_free(i_session->client_secret);
    o_free(i_session->authorization_endpoint);
    o_free(i_session->token_endpoint);
    o_free(i_session->openid_config_endpoint);
    o_free(i_session->refresh_token);
    o_free(i_session->access_token);
    o_free(i_session->code);
    o_free(i_session->result_message);
    o_free(i_session->refresh_token);
    o_free(i_session->access_token);
    o_free(i_session->id_token);
    o_free(i_session->glewlwyd_api_url);
    o_free(i_session->glewlwyd_cookie_session);
    u_map_clean(&i_session->additional_parameters);
  }
}

int i_set_response_type(struct _i_session * i_session, uint i_value) {
  int ret = I_OK;
  if (i_session != NULL) {
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
  } else {
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_set_oauth2_parameter(struct _i_session * i_session, uint option, const char * s_value) {
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
      case I_OPT_RESULT_MESSAGE:
        o_free(i_session->result_message);
        if (o_strlen(s_value)) {
          i_session->result_message = o_strdup(s_value);
        } else {
          i_session->result_message = NULL;
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

int i_set_oidc_additional_parameter(struct _i_session * i_session, const char * s_key, const char * s_value) {
  int ret = I_OK;
  if (i_session != NULL && s_key != NULL && s_value != NULL) {
    if (u_map_put(&i_session->additional_parameters, s_key, s_value) != U_OK) {
      ret = I_ERROR;
    }
  } else {
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_get_response_type(struct _i_session * i_session) {
  if (i_session != NULL) {
    return i_session->response_type;
  } else {
    return I_RESPONSE_TYPE_NONE;
  }
}

const char * i_get_oauth2_parameter(struct _i_session * i_session, uint option) {
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
      case I_OPT_RESULT_MESSAGE:
        result = (const char *)i_session->result_message;
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

const char * i_get_oidc_additional_parameter(struct _i_session * i_session, const char * s_key) {
  if (i_session != NULL) {
    return u_map_get(&i_session->additional_parameters, s_key);
  } else {
    return NULL;
  }
}
