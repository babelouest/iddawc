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
    i_session->refresh_token = NULL;
    i_session->access_token = NULL;
    i_session->code = NULL;
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
    o_free(i_session->refresh_token);
    o_free(i_session->access_token);
    o_free(i_session->code);
    u_map_clean(&i_session->additional_parameters);
  }
}

int i_set_int_option(struct _i_session * i_session, uint option, uint i_value) {
  (void)(i_session);
  (void)(option);
  (void)(i_value);
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
      default:
        ret = I_ERROR_PARAM;
        break;
    }
  } else {
    ret = I_ERROR_PARAM;
  }
  return ret;
}

int i_set_str_option(struct _i_session * i_session, uint option, const char * s_value) {
  (void)(i_session);
  (void)(option);
  (void)(s_value);
  return I_ERROR;
}
