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

#define I_OK                 0 ///< Success
#define I_ERROR              1 ///< Error
#define I_ERROR_PARAM        2 ///< Error in parameters
#define I_ERROR_MEMORY       3 ///< Memory error
#define I_ERROR_UNAUTHORIZED 4 ///< Request unauthorized
#define I_ERROR_SERVER       5 ///< Server error

#define I_RESPONSE_TYPE_NONE               0x00000000 ///< No response type
#define I_RESPONSE_TYPE_CODE               0x00000001 ///< Response type code
#define I_RESPONSE_TYPE_TOKEN              0x00000010 ///< Response type token
#define I_RESPONSE_TYPE_ID_TOKEN           0x00000100 ///< Response type id_token
#define I_RESPONSE_TYPE_PASSWORD           0x00001000 ///< Response type password
#define I_RESPONSE_TYPE_CLIENT_CREDENTIALS 0x00010000 ///< Response type client_credentials
#define I_RESPONSE_TYPE_REFRESH_TOKEN      0x00100000 ///< Response type refresh_token

#define I_AUTH_METHOD_GET                 0x00000001 ///< access auth endpoint using GET method
#define I_AUTH_METHOD_POST                0x00000010 ///< access auth endpoint using POST method
#define I_AUTH_METHOD_JWT_SIGN_SECRET     0x00000100 ///< access auth endpoint using a JWT signed with the client secret
#define I_AUTH_METHOD_JWT_SIGN_PRIVKEY    0x00001000 ///< access auth endpoint using a JWT signed with the client private key
#define I_AUTH_METHOD_JWT_ENCRYPT_SECRET  0x00010000 ///< access auth endpoint using a JWT encrypted with the client secret
#define I_AUTH_METHOD_JWT_ENCRYPT_PUBKEY  0x00100000 ///< access auth endpoint using a JWT encrypted with the client private key

#define I_TOKEN_AUTH_METHOD_SECRET_BASIC 0 ///< access token endpoint using HTTP basic auth with client_id and client password
#define I_TOKEN_AUTH_METHOD_SECRET_POST  1 ///< access token endpoint using secret send in POST parameters
#define I_TOKEN_AUTH_METHOD_SECRET_JWT   2 ///< access token endpoint using a JWT signed with the client secret
#define I_TOKEN_AUTH_METHOD_PRIVATE_JWT  3 ///< access token endpoint using a JWT signed with the client private key
#define I_TOKEN_AUTH_METHOD_NONE         4 ///< access token endpoint using no authentication

#define I_STRICT_NO  0 ///< Do not stricly conform to openid config result
#define I_STRICT_YES 1 ///< Stricly conform to openid config result

#define I_AUTH_SIGN_ALG_MAX_LENGTH 8 ///< Max length of a sign algorithm name

/**
 * Options available to set or get properties using
 * i_set_int_parameter, i_set_str_parameter,
 * i_get_int_parameter or i_get_str_parameter
 */
typedef enum {
  I_OPT_NONE                             = 0,  ///< Empty option to complete a i_set_parameter_list
  I_OPT_RESPONSE_TYPE                    = 1,  ///< response_type, values available are I_RESPONSE_TYPE_CODE, I_RESPONSE_TYPE_TOKEN, I_RESPONSE_TYPE_ID_TOKEN, I_RESPONSE_TYPE_PASSWORD, I_RESPONSE_TYPE_CLIENT_CREDENTIALS and I_RESPONSE_TYPE_REFRESH_TOKEN
  I_OPT_SCOPE                            = 2,  ///< scope values, string, multiple scopes must be separated by a space character: "scope1 openid"
  I_OPT_SCOPE_APPEND                     = 3,  ///< append another scope value to the scope list, string
  I_OPT_STATE                            = 4,  ///< state value, string
  I_OPT_NONCE                            = 5,  ///< nonce value, string
  I_OPT_REDIRECT_URI                     = 6,  ///< redirect_uri, string
  I_OPT_REDIRECT_TO                      = 7,  ///< url where the oauth2 is redirected to after a /auth request
  I_OPT_CLIENT_ID                        = 8,  ///< client_id, string
  I_OPT_CLIENT_SECRET                    = 9,  ///< client secret, string
  I_OPT_ADDITIONAL_PARAMETER             = 10, ///< use this option to pass any additional parameter value in the /auth request
  I_OPT_ADDITIONAL_RESPONSE              = 11, ///< 
  I_OPT_AUTH_ENDPOINT                    = 12, ///< absolute url for the auth endpoint, string
  I_OPT_TOKEN_ENDPOINT                   = 13, ///< absolute url for the token endpoint, string
  I_OPT_OPENID_CONFIG_ENDPOINT           = 14, ///< absolute url for the .well-known/openid-configuration endpoint, string
  I_OPT_OPENID_CONFIG                    = 15, ///< result of the .well-known/openid-configuration
  I_OPT_OPENID_CONFIG_STRICT             = 16, ///< must the .well-known/openid-configuration parameters be strictly 
  I_OPT_USERINFO_ENDPOINT                = 17, ///< absolute url for the userinfo endpoint or equivalent, string
  I_OPT_RESULT                           = 18, ///< result of a request
  I_OPT_ERROR                            = 19, ///< error value of a failed request, string
  I_OPT_ERROR_DESCRIPTION                = 20, ///< error description of a failed request, string
  I_OPT_ERROR_URI                        = 21, ///< error uri of a failed request, string
  I_OPT_CODE                             = 22, ///< code given after a succesfull auth request using the response_type I_RESPONSE_TYPE_CODE
  I_OPT_REFRESH_TOKEN                    = 23, ///< refresh token given after a succesfull token request using the proper response_type
  I_OPT_ACCESS_TOKEN                     = 24, ///< access token given after a succesfull auth or token request using the proper response_type
  I_OPT_ID_TOKEN                         = 25, ///< id_token given after a succesfull auth or token request using the proper response_type
  I_OPT_AUTH_METHOD                      = 28, ///< Authentication method to use with the auth endpoint, values available are I_AUTH_METHOD_GET, I_AUTH_METHOD_POST, I_AUTH_METHOD_JWT_SIGN_SECRET, I_AUTH_METHOD_JWT_SIGN_PRIVKEY, I_AUTH_METHOD_JWT_ENCRYPT_SECRET or I_AUTH_METHOD_JWT_ENCRYPT_PUBKEY, values I_AUTH_METHOD_JWT_SIGN_SECRET, I_AUTH_METHOD_JWT_SIGN_PRIVKEY, I_AUTH_METHOD_JWT_ENCRYPT_SECRET or I_AUTH_METHOD_JWT_ENCRYPT_PUBKEY can be combined with I_AUTH_METHOD_GET or I_AUTH_METHOD_POST
  I_OPT_TOKEN_METHOD                     = 29, ///< Authentication method to use with the token endpoint, values available are I_TOKEN_AUTH_METHOD_SECRET_BASIC, I_TOKEN_AUTH_METHOD_SECRET_POST, I_TOKEN_AUTH_METHOD_SECRET_JWT, I_TOKEN_AUTH_METHOD_PRIVATE_JWT, I_TOKEN_AUTH_METHOD_NONE
  I_OPT_TOKEN_TYPE                       = 30, ///< token_type value after a succesfull auth or token request, string
  I_OPT_EXPIRES_IN                       = 31, ///< expires_in value after a succesfull auth or token request, integer
  I_OPT_USERNAME                         = 32, ///< username for password response_types, string
  I_OPT_USER_PASSWORD                    = 33, ///< password for password response_types, string
  I_OPT_ISSUER                           = 34, ///< issuer value, string
  I_OPT_USERINFO                         = 35, ///< userinfo result, string
  I_OPT_NONCE_GENERATE                   = 36, ///< generate a random nonce value
  I_OPT_STATE_GENERATE                   = 37, ///< generate a random state value
  I_OPT_X5U_FLAGS                        = 38, ///< x5u flage to apply when JWK used have a x5u property, values available are R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid, R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary, R_FLAG_IGNORE_REMOTE: do not download remote key
  I_OPT_SERVER_KID                       = 39, ///< key id to use if multiple jwk are available on the server, string
  I_OPT_CLIENT_KID                       = 40, ///< key id to use if multiple jwk are available on the client, string
  I_OPT_CLIENT_SIGN_ALG                  = 41, ///< signature algorithm to use when the client signs a request in a JWT, values available are 'none', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'EDDSA'
  I_OPT_CLIENT_ENC_ALG                   = 42, ///< key encryption algorithm to use when the client encrypts a request in a JWT, values available are 'RSA1_5', 'RSA_OAEP', 'RSA_OAEP_256', 'A128KW', 'A192KW', 'A256KW', 'DIR', 'ECDH_ES', 'ECDH_ES_A128KW', 'ECDH_ES_A192KW', 'ECDH_ES_A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'PBES2_H256', 'PBES2_H384 or 'PBES2_H512', warning: some algorithm may be unavailable depending on Rhonabwy version used
  I_OPT_CLIENT_ENC                       = 43, ///< data encryption algorithm to use when the client encrypts a request in a JWT, values available are 'A128CBC,' 'A192CBC,' 'A256CBC,' 'A128GCM,' 'A192GCM,' 'A256GCM,' warning: some algorithm may be unavailable depending on Rhonabwy version used
  I_OPT_TOKEN_JTI                        = 44, ///< jti value, string
  I_OPT_TOKEN_JTI_GENERATE               = 45, ///< generate a random jti value
  I_OPT_TOKEN_EXP                        = 46, ///< JWT token request expiration time in seconds
  I_OPT_TOKEN_TARGET                     = 47, ///< access_token which is the target of a revocation or an introspection, string
  I_OPT_TOKEN_TARGET_TYPE_HINT           = 48, ///< access_token which is the target of a revocation or an introspection, string
  I_OPT_REVOCATION_ENDPOINT              = 49, ///< absolute url for the revocation endpoint, string
  I_OPT_INTROSPECTION_ENDPOINT           = 50, ///< absolute url for the introspection endpoint, string
  I_OPT_REGISTRATION_ENDPOINT            = 51  ///< absolute url for the client registration endpoint, string
} i_option;

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
  char        * revocation_endpoint;
  char        * introspection_endpoint;
  char        * registration_endpoint;
  uint          result;
  char        * error;
  char        * error_description;
  char        * error_uri;
  char        * code;
  char        * refresh_token;
  char        * access_token;
  char        * token_target;
  char        * token_target_type_hint;
  char        * token_type;
  uint          expires_in;
  char        * id_token;
  json_t      * id_token_payload;
  uint          auth_method;
  uint          token_method;
  jwks_t      * server_jwks;
  char        * server_kid;
  jwks_t      * client_jwks;
  char        * client_kid;
  jwa_alg       client_sign_alg;
  jwa_alg       client_enc_alg;
  jwa_enc       client_enc;
  int           x5u_flags;
  json_t      * openid_config;
  int           openid_config_strict;
  char        * issuer;
  char        * userinfo;
  json_t      * j_userinfo;
  char        * token_jti;
  uint          token_exp;
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
 * Initialize iddawc global parameters
 * This function isn't thread-safe so it must be called once before any other call to iddawc functions
 * The function i_global_close must be called when iddawc library is no longer required
 * @return RHN_OK on success, an error value on error
 */
int i_global_init();

/**
 * Close iddawc global parameters
 */
void i_global_close();

/**
 * Free a heap allocated variable
 * previously returned by a iddawc function
 * @param data: the data to free
 */
void i_free(void * data);

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
 * I_OPT_EXPIRES_IN, I_OPT_OPENID_CONFIG_STRICT
 * @param i_value: The unsigned integer value to set
 * @return I_OK on success, an error value on error
 */
int i_set_int_parameter(struct _i_session * i_session, i_option option, uint i_value);

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
int i_set_str_parameter(struct _i_session * i_session, i_option option, const char * s_value);

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
 * I_OPT_EXPIRES_IN, I_OPT_OPENID_CONFIG_STRICT
 * @return the option value
 */
uint i_get_int_parameter(struct _i_session * i_session, i_option option);

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
const char * i_get_str_parameter(struct _i_session * i_session, i_option option);

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
 * @return a char * containing a JSON stringified exported session, must be i_free'd after use
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

/**
 * @defgroup run Run OAuth2 or OIDC requests
 * Run auth, token, userinfo, introspect, revoke or register requests
 * @{
 */

/**
 * Loads and parse the openid_config endpoint, and sets the parameter values accordingly
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_load_openid_config(struct _i_session * i_session);

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
 * Parses the redirect_uri given by the oauth2 server in the implicit flow
 * The redirect_uri may contain a code, a token, an id_token, or an error
 * Fills the session parameters with the values given in the redirect_uri
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_parse_redirect_to(struct _i_session * i_session);

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
 * Loads the userinfo endpoint using the access_token
 * if the result is a JWT, validate the signature 
 * and/or decrypt the token
 * sets the result to i_session->userinfo as char *
 * and i_session->j_userinfo as json_t * if the result is in JSON format
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_load_userinfo(struct _i_session * i_session);

/**
 * Loads the userinfo endpoint using the access_token
 * with custom parameters
 * if the result is a JWT, validate the signature 
 * and/or decrypt the token
 * sets the result to i_session->userinfo as char *
 * and i_session->j_userinfo as json_t * if the result is in JSON format
 * @param i_session: a reference to a struct _i_session *
 * @param http_method: http method to use, values available are 'GET' or 'POST'
 * @param additional_query: set of additional parameters to add to the url query
 * @param additional_headers: set of additional parameters to add to the request header
 * @return I_OK on success, an error value on error
 */
int i_load_userinfo_custom(struct _i_session * i_session, const char * http_method, struct _u_map * additional_query, struct _u_map * additional_headers);

/**
 * Loads the introspection endpoint for the access_token_target
 * Using the access_token for authentication
 * @param i_session: a reference to a struct _i_session *
 * @param j_result: if not NULL, set an allocated json_t * object with the endpoint result
 * @return I_OK on success and if the access_token_target is valid, 
 * I_ERROR_UNAUTHORIZED if the access_token_target is invalid, another error value on error
 */
int i_introspect_token(struct _i_session * i_session, json_t ** j_result);

/**
 * Loads the revocation endpoint for the access_token_target
 * Using the access_token for authentication
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_revoke_token(struct _i_session * i_session);

/**
 * Register a new client using the dynamic registration endpoint
 * Using the access_token for authentication
 * @param i_session: a reference to a struct _i_session *
 * @param j_parameters: a json_t * object containing the client metadata
 * The metadata content depends on the registration endpoint but at least
 * the parameter redirect_uris (array of string) is required to register a new client
 * @param update_session: if the registration is succesfull, update the session with the new client_id and client_secret
 * @param j_result: if not NULL, set an allocated json_t * object with the endpoint result
 * @return I_OK on success, an error value on error
 */
int i_register_client(struct _i_session * i_session, json_t * j_parameters, int update_session, json_t ** j_result);

/**
 * Generates a DPoP token based on the given parameters and the internal state of the struct _i_session
 * The jti must be previously generated vie I_OPT_TOKEN_JTI_GENERATE or I_OPT_TOKEN_JTI
 * @param i_session: a reference to a struct _i_session *
 * @param htm: The htm claim value, the HTTP method used to access the protected resource (GET, POST, PATCH, etc.)
 * @param htu: The htu claim value, the HTTP url used to access the protected resource (ex: https://resource.tld/object)
 * @param iat: the iat claim value, the epoch time value when the DPoP token must be set. If 0, the current time will be used
 * @return a char * containing the DPoP token signed, must be i_free'd after use
 */
char * i_generate_dpop_token(struct _i_session * i_session, const char * htm, const char * htu, time_t iat);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif // __IDDAWC_H_
