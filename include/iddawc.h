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

#include <orcania.h>
#include <ulfius.h>

#define I_OK                 0
#define I_ERROR              1
#define I_ERROR_PARAM        2
#define I_ERROR_MEMORY       3
#define I_ERROR_UNAUTHORIZED 4
#define I_ERROR_SERVER       5

#define I_RESPONSE_TYPE_NONE               0x00000000
#define I_RESPONSE_TYPE_CODE               0x00000001
#define I_RESPONSE_TYPE_TOKEN              0x00000010
#define I_RESPONSE_TYPE_ID_TOKEN           0x00000100
#define I_RESPONSE_TYPE_PASSWORD           0x00001000
#define I_RESPONSE_TYPE_CLIENT_CREDENTIALS 0x00010000
#define I_RESPONSE_TYPE_REFRESH_TOKEN      0x00100000

enum _i_option {
  I_OPT_NONE                             = 0,
  I_OPT_RESPONSE_TYPE                    = 1,
  I_OPT_SCOPE                            = 2,
  I_OPT_SCOPE_APPEND                     = 3,
  I_OPT_STATE                            = 4,
  I_OPT_NONCE                            = 5,
  I_OPT_REDIRECT_URI                     = 6,
  I_OPT_REDIRECT_TO                      = 7,
  I_OPT_CLIENT_ID                        = 8,
  I_OPT_CLIENT_SECRET                    = 9,
  I_OPT_ADDITIONAL_PARAMETER             = 10,
  I_OPT_AUTH_ENDPOINT                    = 11,
  I_OPT_TOKEN_ENDPOINT                   = 12,
  I_OPT_OPENID_CONFIG_ENDPOINT           = 13,
  I_OPT_ACCESS_TOKEN_VALIDATION_ENDPOINT = 14,
  I_OPT_RESULT                           = 15,
  I_OPT_ERROR                            = 16,
  I_OPT_ERROR_DESCRIPTION                = 17,
  I_OPT_ERROR_URI                        = 18,
  I_OPT_CODE                             = 19,
  I_OPT_REFRESH_TOKEN                    = 20,
  I_OPT_ACCESS_TOKEN                     = 21,
  I_OPT_ID_TOKEN                         = 22,
  I_OPT_GLEWLWYD_API_URL                 = 23,
  I_OPT_GLEWLWYD_COOKIE_SESSION          = 24
};

struct _i_session {
  uint   response_type;
  char * scope;
  char * state;
  char * nonce;
  char * redirect_url;
  char * redirect_to;
  char * client_id;
  char * client_secret;
  struct _u_map additional_parameters;
  struct _pointer_list jwks_list;
  char * authorization_endpoint;
  char * token_endpoint;
  char * openid_config_endpoint;
  char * access_token_validation_endpoint;
  uint   result;
  char * error;
  char * error_description;
  char * error_uri;
  char * code;
  char * refresh_token;
  char * access_token;
  char * id_token;
  char * glewlwyd_api_url;
  char * glewlwyd_cookie_session;
};

int i_init_session(struct _i_session * i_session);

void i_clean_session(struct _i_session * i_session);

int i_set_response_type(struct _i_session * i_session, uint i_value);

int i_set_result(struct _i_session * i_session, uint i_value);

int i_set_flag_parameter(struct _i_session * i_session, uint option, uint i_value);

int i_set_parameter(struct _i_session * i_session, uint option, const char * s_value);

int i_set_additional_parameter(struct _i_session * i_session, const char * s_key, const char * s_value);

uint i_get_response_type(struct _i_session * i_session);

uint i_get_result(struct _i_session * i_session);

uint i_get_flag_parameter(struct _i_session * i_session, uint option);

const char * i_get_parameter(struct _i_session * i_session, uint option);

const char * i_get_additional_parameter(struct _i_session * i_session, const char * s_key);

int set_parameter_list(struct _i_session * i_session, ...);

int i_run_config_endpoint(struct _i_session * i_session);

int i_run_auth_request(struct _i_session * i_session);

int i_run_token_request(struct _i_session * i_session);

int i_run_access_token_validation_endpoint(struct _i_session * i_session);

int igc_auth_password(struct _i_session * i_session, const char * username, const char * password);

int igc_auth_scheme(struct _i_session * i_session, const char * scheme_mod, const char * scheme_name, const char * username, const char * json_value);

char * igc_get_scope_auth_status(struct _i_session * i_session, const char * username);
