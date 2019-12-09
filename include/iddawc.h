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
#include <yder.h>
#include <ulfius.h>

#define I_OK           0
#define I_ERROR        1
#define I_ERROR_PARAM  2
#define I_ERROR_MEMORY 3

#define I_RESPONSE_TYPE_NONE               0x00000000
#define I_RESPONSE_TYPE_CODE               0x00000001
#define I_RESPONSE_TYPE_TOKEN              0x00000010
#define I_RESPONSE_TYPE_ID_TOKEN           0x00000100
#define I_RESPONSE_TYPE_PASSWORD           0x00001000
#define I_RESPONSE_TYPE_CLIENT_CREDENTIALS 0x00010000
#define I_RESPONSE_TYPE_REFRESH_TOKEN      0x00100000

enum _i_option {
  I_OPT_NONE                 = 0,
  I_OPT_RESPONSE_TYPE        = 1,
  I_OPT_SCOPE_SET            = 2,
  I_OPT_SCOPE_APPEND         = 3,
  I_OPT_STATE                = 4,
  I_OPT_NONCE                = 5,
  I_OPT_ADDITIONAL_PARAMETER = 6,
  I_OPT_RESULT               = 7,
  I_OPT_CODE                 = 8,
  I_OPT_REFRESH_TOKEN        = 9,
  I_OPT_ACCESS_TOKEN         = 10,
  I_OPT_REDIRECT_URI         = 11
};

struct _i_session {
  // Input parameters
  int    response_type;
  char * scope;
  char * state;
  char * nonce;
  struct _u_map additional_parameters;
  
  // Output parameters
  int result;
  char * code;
  char * refresh_token;
  char * access_token;
  char * redirect_url;
};

int i_init_session(struct _i_session * i_session);

void i_clean_session(struct _i_session * i_session);

int i_set_int_option(struct _i_session * i_session, uint option, uint i_value);

int i_set_str_option(struct _i_session * i_session, uint option, const char * s_value);

int i_set_map_option(struct _i_session * i_session, uint option, const char * s_key, const char * s_value);
