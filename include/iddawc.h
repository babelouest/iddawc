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

#ifndef __IDDAWC_H
#define __IDDAWC_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <jansson.h>
#include <orcania.h>
#include <ulfius.h>
#include <rhonabwy.h>
#include "iddawc-cfg.h"

/**
 * @defgroup const Constants and properties
 * Constant values used as input or output
 * @{
 */

/**
 * Return values
 */
#define I_OK                 0
#define I_ERROR              1
#define I_ERROR_PARAM        2
#define I_ERROR_MEMORY       3
#define I_ERROR_UNAUTHORIZED 4
#define I_ERROR_SERVER       5

/**
 * Stackable response type values
 */
#define I_RESPONSE_TYPE_NONE               0x00000000
#define I_RESPONSE_TYPE_CODE               0x00000001
#define I_RESPONSE_TYPE_TOKEN              0x00000010
#define I_RESPONSE_TYPE_ID_TOKEN           0x00000100
#define I_RESPONSE_TYPE_PASSWORD           0x00001000
#define I_RESPONSE_TYPE_CLIENT_CREDENTIALS 0x00010000
#define I_RESPONSE_TYPE_REFRESH_TOKEN      0x00100000

/**
 * i_set_response_type i_values parameter values
 */
#define I_AUTH_METHOD_GET  0x00000000
#define I_AUTH_METHOD_POST 0x00000001
#define I_AUTH_METHOD_JWT  0x00000010

/**
 * I_OPT_OPENID_CONFIG_STRICT values available
 */
#define I_STRICT_NO  0
#define I_STRICT_YES 1

#define I_AUTH_SIGN_ALG_MAX_LENGTH 8

/**
 * I_OPT_AUTH_SIGN_ALG values available
 */
#define I_AUTH_SIGN_ALG_NONE  0
#define I_AUTH_SIGN_ALG_RS256 1
#define I_AUTH_SIGN_ALG_RS384 2
#define I_AUTH_SIGN_ALG_RS512 3

/**
 * Options available to set or get properties using
 * i_set_int_parameter, i_set_str_parameter,
 * i_get_int_parameter or i_get_str_parameter
 */
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
  I_OPT_ADDITIONAL_RESPONSE              = 11,
  I_OPT_AUTH_ENDPOINT                    = 12,
  I_OPT_TOKEN_ENDPOINT                   = 13,
  I_OPT_OPENID_CONFIG_ENDPOINT           = 14,
  I_OPT_OPENID_CONFIG                    = 15,
  I_OPT_OPENID_CONFIG_STRICT             = 16,
  I_OPT_USERINFO_ENDPOINT                = 17,
  I_OPT_RESULT                           = 18,
  I_OPT_ERROR                            = 19,
  I_OPT_ERROR_DESCRIPTION                = 20,
  I_OPT_ERROR_URI                        = 21,
  I_OPT_CODE                             = 22,
  I_OPT_REFRESH_TOKEN                    = 23,
  I_OPT_ACCESS_TOKEN                     = 24,
  I_OPT_ID_TOKEN                         = 25,
  I_OPT_GLEWLWYD_API_URL                 = 26,
  I_OPT_GLEWLWYD_COOKIE_SESSION          = 27,
  I_OPT_AUTH_METHOD                      = 28,
  I_OPT_AUTH_SIGN_ALG                    = 29,
  I_OPT_TOKEN_TYPE                       = 30,
  I_OPT_EXPIRES_IN                       = 31,
  I_OPT_USERNAME                         = 32,
  I_OPT_USER_PASSWORD                    = 33,
  I_OPT_ISSUER                           = 34,
  I_OPT_USERINFO                         = 35,
  I_OPT_NONCE_GENERATE                   = 36,
  I_OPT_STATE_GENERATE                   = 37,
  I_OPT_X5U_FLAGS                        = 38
};

/**
 * @}
 */

/**
 * @defgroup struct struct _i_session definition
 * Heart structure of the library
 * @{
 */

struct _i_session {
  uint          response_type;
  char        * scope;
  char        * state;
  char        * nonce;
  char        * redirect_uri;
  char        * redirect_to;
  char        * client_id;
  char        * client_secret;
  char        * username;
  char        * user_password;
  struct _u_map additional_parameters;
  struct _u_map additional_response;
  char        * authorization_endpoint;
  char        * token_endpoint;
  char        * openid_config_endpoint;
  char        * userinfo_endpoint;
  uint          result;
  char        * error;
  char        * error_description;
  char        * error_uri;
  char        * code;
  char        * refresh_token;
  char        * access_token;
  char        * token_type;
  uint          expires_in;
  char        * id_token;
  json_t *      id_token_payload;
  jwk_t  *      id_token_header;
  char        * glewlwyd_api_url;
  char        * glewlwyd_cookie_session;
  uint          auth_method;
  char          auth_sign_alg[I_AUTH_SIGN_ALG_MAX_LENGTH];
  jwks_t *      server_jwks;
  int           x5u_flags;
  json_t *      openid_config;
  int           openid_config_strict;
  char        * issuer;
  char        * userinfo;
  json_t *      j_userinfo;
};

/**
 * @}
 */

/**
 * @defgroup core Core functions
 * Core functions used to initialize or free struct _i_session
 * @{
 */

/**
 * Initialize a struct _i_session
 * @param i_session: a reference to a struct _i_session * to initialize
 * @return I_OK on success, an error value on error
 */
int i_init_session(struct _i_session * i_session);

/**
 * Cleanup a struct _i_session
 * @param i_session: a reference to a struct _i_session * to initialize
 */
void i_clean_session(struct _i_session * i_session);

/**
 * @}
 */

/**
 * @defgroup properties Get or set struct _i_session properties
 * Manipulates inner data of the session
 * @{
 */

/**
 * Sets response type of a session
 * @param i_session: a reference to a struct _i_session *
 * @param i_value: the response type
 * values available are I_RESPONSE_TYPE_NONE, I_RESPONSE_TYPE_CODE, I_RESPONSE_TYPE_TOKEN, 
 * I_RESPONSE_TYPE_ID_TOKEN, I_RESPONSE_TYPE_PASSWORD, I_RESPONSE_TYPE_CLIENT_CREDENTIALS
 * and I_RESPONSE_TYPE_REFRESH_TOKEN
 * Values I_RESPONSE_TYPE_CODE, I_RESPONSE_TYPE_TOKEN and I_RESPONSE_TYPE_ID_TOKEN can be 
 * stacked if using hybrid flow, example: 
 * I_RESPONSE_TYPE_CODE | I_RESPONSE_TYPE_TOKEN | I_RESPONSE_TYPE_ID_TOKEN
 * @return I_OK on success, an error value on error
 */
int i_set_response_type(struct _i_session * i_session, uint i_value);

/**
 * Sets the result of a request
 * @param i_session: a reference to a struct _i_session *
 * @param i_value: the result value
 * Values available are I_OK, I_ERROR, I_ERROR_PARAM, 
 * I_ERROR_MEMORY, I_ERROR_UNAUTHORIZED orI_ERROR_SERVER
 * @return I_OK on success, an error value on error
 */
int i_set_result(struct _i_session * i_session, uint i_value);

/**
 * Sets an unsigned integer property value
 * @param i_session: a reference to a struct _i_session *
 * @param option: the option to set
 * options availble are I_OPT_RESPONSE_TYPE, I_OPT_RESULT, I_OPT_AUTH_METHOD
 * I_OPT_AUTH_SIGN_ALG, I_OPT_EXPIRES_IN, I_OPT_OPENID_CONFIG_STRICT
 * @param i_value: The unsigned integer value to set
 * @return I_OK on success, an error value on error
 */
int i_set_int_parameter(struct _i_session * i_session, uint option, uint i_value);

/**
 * Sets a char * property value
 * @param i_session: a reference to a struct _i_session *
 * @param option: the option to set
 * options available are I_OPT_SCOPE, I_OPT_SCOPE_APPEND, I_OPT_STATE
 * I_OPT_NONCE, I_OPT_REDIRECT_URI, I_OPT_REDIRECT_TO, I_OPT_CLIENT_ID,
 * I_OPT_CLIENT_SECRET, I_OPT_AUTH_ENDPOINT, I_OPT_TOKEN_ENDPOINT,
 * I_OPT_OPENID_CONFIG_ENDPOINT, I_OPT_USERINFO_ENDPOINT, I_OPT_ERROR,
 * I_OPT_ERROR_DESCRIPTION, I_OPT_ERROR_URI, I_OPT_CODE, I_OPT_REFRESH_TOKEN,
 * I_OPT_ACCESS_TOKEN, I_OPT_ID_TOKEN, I_OPT_GLEWLWYD_API_URL,
 * I_OPT_GLEWLWYD_COOKIE_SESSION, I_OPT_TOKEN_TYPE, I_OPT_USERNAME,
 * I_OPT_USER_PASSWORD, I_OPT_OPENID_CONFIG, I_OPT_ISSUER
 * @param s_value: The char * value to set
 * @return I_OK on success, an error value on error
 */
int i_set_str_parameter(struct _i_session * i_session, uint option, const char * s_value);

/**
 * Sets an additional parameter for auth or token requests
 * @param i_session: a reference to a struct _i_session *
 * @param s_key: the key to set
 * @param s_value: the value to set
 * @return I_OK on success, an error value on error
 */
int i_set_additional_parameter(struct _i_session * i_session, const char * s_key, const char * s_value);

/**
 * Sets an additional response value
 * @param i_session: a reference to a struct _i_session *
 * @param s_key: the key to set
 * @param s_value: the value to set
 * @return I_OK on success, an error value on error
 */
int i_set_additional_response(struct _i_session * i_session, const char * s_key, const char * s_value);

/**
 * Returns the response type of the current session
 * @param i_session: a reference to a struct _i_session *
 * @return a value among the following:
 * I_RESPONSE_TYPE_NONE, I_RESPONSE_TYPE_CODE, I_RESPONSE_TYPE_TOKEN, 
 * I_RESPONSE_TYPE_ID_TOKEN, I_RESPONSE_TYPE_PASSWORD, I_RESPONSE_TYPE_CLIENT_CREDENTIALS
 * and I_RESPONSE_TYPE_REFRESH_TOKEN
 * Values I_RESPONSE_TYPE_CODE, I_RESPONSE_TYPE_TOKEN and I_RESPONSE_TYPE_ID_TOKEN can be 
 * stacked if using hybrid flow, example: 
 * I_RESPONSE_TYPE_CODE | I_RESPONSE_TYPE_TOKEN | I_RESPONSE_TYPE_ID_TOKEN
 */
uint i_get_response_type(struct _i_session * i_session);

/**
 * Returns the result of the last oauth2 request
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
uint i_get_result(struct _i_session * i_session);

/**
 * Returns the integer value of an option
 * @param i_session: a reference to a struct _i_session *
 * @param option: the option to get
 * options availble are I_OPT_RESPONSE_TYPE, I_OPT_RESULT, I_OPT_AUTH_METHOD
 * I_OPT_AUTH_SIGN_ALG, I_OPT_EXPIRES_IN, I_OPT_OPENID_CONFIG_STRICT
 * @return the option value
 */
uint i_get_int_parameter(struct _i_session * i_session, uint option);

/**
 * Returns the char * value of an option
 * @param i_session: a reference to a struct _i_session *
 * @param option: the option to get
 * options available are I_OPT_SCOPE, I_OPT_SCOPE_APPEND, I_OPT_STATE
 * I_OPT_NONCE, I_OPT_REDIRECT_URI, I_OPT_REDIRECT_TO, I_OPT_CLIENT_ID,
 * I_OPT_CLIENT_SECRET, I_OPT_AUTH_ENDPOINT, I_OPT_TOKEN_ENDPOINT,
 * I_OPT_OPENID_CONFIG_ENDPOINT, I_OPT_USERINFO_ENDPOINT, I_OPT_ERROR,
 * I_OPT_ERROR_DESCRIPTION, I_OPT_ERROR_URI, I_OPT_CODE, I_OPT_REFRESH_TOKEN,
 * I_OPT_ACCESS_TOKEN, I_OPT_ID_TOKEN, I_OPT_GLEWLWYD_API_URL,
 * I_OPT_GLEWLWYD_COOKIE_SESSION, I_OPT_TOKEN_TYPE, I_OPT_USERNAME,
 * I_OPT_USER_PASSWORD, I_OPT_OPENID_CONFIG, I_OPT_ISSUER
 * @return the char * value of the option, NULL if no value set
 */
const char * i_get_str_parameter(struct _i_session * i_session, uint option);

/**
 * Gets an additional parameter for auth or token requests
 * @param i_session: a reference to a struct _i_session *
 * @param s_key: the key to get
 * @return the value
 */
const char * i_get_additional_parameter(struct _i_session * i_session, const char * s_key);

/**
 * Gets an additional response from auth or token requests
 * @param i_session: a reference to a struct _i_session *
 * @param s_key: the key to get
 * @return the value
 */
const char * i_get_additional_response(struct _i_session * i_session, const char * s_key);

/**
 * Parses the redirect_uri given by the oauth2 server in the implicit flow
 * The redirect_uri may contain a code, a token, an id_token, or an error
 * Fills the session parameters with the values given in the redirect_uri
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_parse_redirect_to(struct _i_session * i_session);

/**
 * Sets a list of parameters to a session
 * @param i_session: a reference to a struct _i_session *
 * the list of parameters to set
 * Uses a variable-length parameter list
 * the syntax is the option followed by the value(s) required by the option
 * The list must be ended by a I_OPT_NONE
 * Example:
 * i_set_parameter_list(i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE, 
 * I_OPT_SCOPE, "scope1", I_OPT_STATE, "abcd", I_OPT_CLIENT_ID, "client1", 
 * I_OPT_AUTH_ENDPOINT, "https://auth2.tld/auth", I_OPT_NONE);
 * @return I_OK on success, an error value on error
 */
int i_set_parameter_list(struct _i_session * i_session, ...);

/**
 * Loads and parse the openid_config endpoint, and sets the parameter values accordingly
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_load_openid_config(struct _i_session * i_session);

/**
 * @}
 */

/**
 * @defgroup run Executes oauth2 or oidc requests
 * Run auth, token or userinfo requests
 * @{
 */

/**
 * Loads the userinfo endpoint using the access_token
 * sets the result to i_session->userinfo as char *
 * and i_session->j_userinfo as json_t * if the result is in JSON format
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_load_userinfo(struct _i_session * i_session);

/**
 * Builds the url to GET the auth endpoint
 * sets the result to parameter I_OPT_REDIRECT_TO
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_build_auth_url_get(struct _i_session * i_session);

/**
 * Executes an auth request using the implicit endpoint
 * and sets the result values in the session variables
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_run_auth_request(struct _i_session * i_session);

/**
 * Executes a token request using the implicit endpoint
 * and sets the result values in the session variables
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_run_token_request(struct _i_session * i_session);

/**
 * Validates the id_token signature and content if necessary
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_verify_id_token(struct _i_session * i_session);

/**
 * Exports a _i_session * into a json_t * object
 * @param i_session: a reference to a struct _i_session *
 * @return a json_t * object containing all data set in the session
 */
json_t * i_export_session_json_t(struct _i_session * i_session);

/**
 * Imports a _i_session * from a json_t * object
 * Imported data will overwrite existing data in i_session
 * @param i_session: a reference to a struct _i_session *
 * @param j_import: a json_t * object in i_export_session_json_t format
 * @return I_OK on success, an error value on error
 */
int i_import_session_json_t(struct _i_session * i_session, json_t * j_import);

/**
 * Exports a _i_session * into a json_t * object
 * @param i_session: a reference to a struct _i_session *
 * @return a char * containing a JSON stringified exported session
 */
char * i_export_session_str(struct _i_session * i_session);

/**
 * Imports a _i_session * from a json_t * object
 * Imported data will overwrite existing data in i_session
 * @param i_session: a reference to a struct _i_session *
 * @param str_import: a char * containing a JSON stringified session
 * @return I_OK on success, an error value on error
 */
int i_import_session_str(struct _i_session * i_session, const char * str_import);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif // __IDDAWC_H_
