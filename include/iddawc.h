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
#define I_RESPONSE_TYPE_PASSWORD           0x00001000 ///< Grant type password
#define I_RESPONSE_TYPE_CLIENT_CREDENTIALS 0x00010000 ///< Grant type client_credentials
#define I_RESPONSE_TYPE_REFRESH_TOKEN      0x00100000 ///< Grant type refresh_token
#define I_RESPONSE_TYPE_DEVICE_CODE        0x01000000 ///< Grant type urn:ietf:params:oauth:grant-type:device_code

#define I_AUTH_METHOD_GET                 0x00000001 ///< auth endpoint using GET method
#define I_AUTH_METHOD_POST                0x00000010 ///< auth endpoint using POST method
#define I_AUTH_METHOD_JWT_SIGN_SECRET     0x00000100 ///< auth endpoint using a JWT signed with the client secret
#define I_AUTH_METHOD_JWT_SIGN_PRIVKEY    0x00001000 ///< auth endpoint using a JWT signed with the client private key
#define I_AUTH_METHOD_JWT_ENCRYPT_SECRET  0x00010000 ///< auth endpoint using a JWT encrypted with the client secret
#define I_AUTH_METHOD_JWT_ENCRYPT_PUBKEY  0x00100000 ///< auth endpoint using a JWT encrypted with the server public key

#define I_TOKEN_AUTH_METHOD_NONE            0x00000000 ///< token endpoint using no authentication
#define I_TOKEN_AUTH_METHOD_SECRET_BASIC    0x00000001 ///< token endpoint using HTTP basic auth with client_id and client password
#define I_TOKEN_AUTH_METHOD_SECRET_POST     0x00000010 ///< token endpoint using secret send in POST parameters
#define I_TOKEN_AUTH_METHOD_TLS_CERTIFICATE 0x00000100 ///< token endpoint using TLS Certificate authentication
#define I_TOKEN_AUTH_METHOD_JWT_SIGN_SECRET     0x00001000 ///< token endpoint using a JWT signed with the client secret
#define I_TOKEN_AUTH_METHOD_JWT_SIGN_PRIVKEY    0x00010000 ///< token endpoint using a JWT signed with the client private key
#define I_TOKEN_AUTH_METHOD_JWT_ENCRYPT_SECRET  0x00100000 ///< token endpoint using a JWT encrypted with the client secret
#define I_TOKEN_AUTH_METHOD_JWT_ENCRYPT_PUBKEY  0x01000000 ///< token endpoint using a JWT signed with the client private key and encrypted with the server public key or the client secret

#define I_STRICT_NO  0 ///< Do not stricly conform to openid config result
#define I_STRICT_YES 1 ///< Stricly conform to openid config result

#define I_AUTH_SIGN_ALG_MAX_LENGTH 8 ///< Max length of a sign algorithm name

#define I_BEARER_TYPE_HEADER 0 ///< Bearer type header, the token will be available in the header
#define I_BEARER_TYPE_BODY   1 ///< Bearer type body, the token will be available as a body url-encoded parameter
#define I_BEARER_TYPE_URL    2 ///< Bearer type url, the token will be available as a url query parameter

#define I_INTROSPECT_REVOKE_AUTH_NONE          0 ///< Introspection/Revocation - no authentication
#define I_INTROSPECT_REVOKE_AUTH_ACCESS_TOKEN  1 ///< Introspection/Revocation - authentication using access token
#define I_INTROSPECT_REVOKE_AUTH_CLIENT_TARGET 2 ///< Introspection/Revocation - authentication with client credentials

#define I_TOKEN_TYPE_ACCESS_TOKEN  0 ///<
#define I_TOKEN_TYPE_ID_TOKEN      1 ///<
#define I_TOKEN_TYPE_USERINFO      2 ///<
#define I_TOKEN_TYPE_INTROSPECTION 3 ///<

#define I_HEADER_PREFIX_BEARER "Bearer "
#define I_HEADER_AUTHORIZATION "Authorization"
#define I_BODY_URL_PARAMETER   "access_token"
#define I_HEADER_DPOP          "DPoP"

#define I_REMOTE_VERIFY_NONE           0x0000 ///< No TLS Verification
#define I_REMOTE_HOST_VERIFY_PEER      0x0001 ///< Verify TLS session with peers
#define I_REMOTE_HOST_VERIFY_HOSTNAME  0x0010 ///< Verify TLS session with hostname
#define I_REMOTE_PROXY_VERIFY_PEER     0x0100 ///< Verify TLS session with peers
#define I_REMOTE_PROXY_VERIFY_HOSTNAME 0x1000 ///< Verify TLS session with hostname

#define I_PKCE_NONE         0 ///< No PKCE
#define I_PKCE_METHOD_PLAIN 1 ///< PKCE using method plain
#define I_PKCE_METHOD_S256  2 ///< PKCE using method SHA256

#define I_CLAIM_TARGET_ALL      0 ///< Add claim to userinfo and id_token
#define I_CLAIM_TARGET_USERINFO 1 ///< Add claim to userinfo
#define I_CLAIM_TARGET_ID_TOKEN 2 ///< Add claim to id_token

#define I_CLAIM_ESSENTIAL_NULL   0 ///< Set claim value to null
#define I_CLAIM_ESSENTIAL_TRUE   1 ///< Set claim essential value to true
#define I_CLAIM_ESSENTIAL_FALSE  2 ///< Set claim essential value to false
#define I_CLAIM_ESSENTIAL_IGNORE 3 ///< 

/**
 * Options available to set or get properties using
 * i_set_int_parameter, i_set_str_parameter,
 * i_get_int_parameter, i_get_str_parameter or i_set_parameter_list
 */
typedef enum {
  I_OPT_NONE                                  = 0,  ///< Empty option to complete a i_set_parameter_list
  I_OPT_RESPONSE_TYPE                         = 1,  ///< response_type, values available are I_RESPONSE_TYPE_CODE, I_RESPONSE_TYPE_TOKEN, I_RESPONSE_TYPE_ID_TOKEN, I_RESPONSE_TYPE_PASSWORD, I_RESPONSE_TYPE_CLIENT_CREDENTIALS and I_RESPONSE_TYPE_REFRESH_TOKEN
  I_OPT_SCOPE                                 = 2,  ///< scope values, string, multiple scopes must be separated by a space character: "scope1 openid"
  I_OPT_SCOPE_APPEND                          = 3,  ///< append another scope value to the scope list, string
  I_OPT_STATE                                 = 4,  ///< state value, string
  I_OPT_NONCE                                 = 5,  ///< nonce value, string
  I_OPT_REDIRECT_URI                          = 6,  ///< redirect_uri, string
  I_OPT_REDIRECT_TO                           = 7,  ///< url where the oauth2 is redirected to after a /auth request
  I_OPT_CLIENT_ID                             = 8,  ///< client_id, string
  I_OPT_CLIENT_SECRET                         = 9,  ///< client secret, string
  I_OPT_ADDITIONAL_PARAMETER                  = 10, ///< use this option to pass any additional parameter value in the /auth request
  I_OPT_ADDITIONAL_RESPONSE                   = 11, ///<
  I_OPT_AUTH_ENDPOINT                         = 12, ///< absolute url for the auth endpoint, string
  I_OPT_TOKEN_ENDPOINT                        = 13, ///< absolute url for the token endpoint, string
  I_OPT_OPENID_CONFIG_ENDPOINT                = 14, ///< absolute url for the .well-known/openid-configuration endpoint, string
  I_OPT_OPENID_CONFIG                         = 15, ///< result of the .well-known/openid-configuration
  I_OPT_OPENID_CONFIG_STRICT                  = 16, ///< must the .well-known/openid-configuration parameters be strictly
  I_OPT_USERINFO_ENDPOINT                     = 17, ///< absolute url for the userinfo endpoint or equivalent, string
  I_OPT_RESULT                                = 18, ///< result of a request
  I_OPT_ERROR                                 = 19, ///< error value of a failed request, string
  I_OPT_ERROR_DESCRIPTION                     = 20, ///< error description of a failed request, string
  I_OPT_ERROR_URI                             = 21, ///< error uri of a failed request, string
  I_OPT_CODE                                  = 22, ///< code given after a succesfull auth request using the response_type I_RESPONSE_TYPE_CODE
  I_OPT_REFRESH_TOKEN                         = 23, ///< refresh token given after a succesfull token request using the proper response_type
  I_OPT_ACCESS_TOKEN                          = 24, ///< access token given after a succesfull auth or token request using the proper response_type
  I_OPT_ID_TOKEN                              = 25, ///< id_token given after a succesfull auth or token request using the proper response_type
  I_OPT_AUTH_METHOD                           = 28, ///< Authentication method to use with the auth endpoint, values available are I_AUTH_METHOD_GET, I_AUTH_METHOD_POST, I_AUTH_METHOD_JWT_SIGN_SECRET, I_AUTH_METHOD_JWT_SIGN_PRIVKEY, I_AUTH_METHOD_JWT_ENCRYPT_SECRET or I_AUTH_METHOD_JWT_ENCRYPT_PUBKEY, values I_AUTH_METHOD_JWT_SIGN_SECRET, I_AUTH_METHOD_JWT_SIGN_PRIVKEY, I_AUTH_METHOD_JWT_ENCRYPT_SECRET or I_AUTH_METHOD_JWT_ENCRYPT_PUBKEY can be combined with I_AUTH_METHOD_GET or I_AUTH_METHOD_POST
  I_OPT_TOKEN_METHOD                          = 29, ///< Authentication method to use with the token endpoint, values available are I_TOKEN_AUTH_METHOD_SECRET_BASIC, I_TOKEN_AUTH_METHOD_SECRET_POST, I_TOKEN_AUTH_METHOD_SECRET_JWT, I_TOKEN_AUTH_METHOD_PRIVATE_JWT, I_TOKEN_AUTH_METHOD_NONE
  I_OPT_TOKEN_TYPE                            = 30, ///< token_type value after a succesfull auth or token request, string
  I_OPT_EXPIRES_IN                            = 31, ///< expires_in value after a succesfull auth or token request, integer
  I_OPT_EXPIRES_AT                            = 32, ///< expires_at value after a succesfull auth or token request, time_t
  I_OPT_USERNAME                              = 33, ///< username for password response_types, string
  I_OPT_USER_PASSWORD                         = 34, ///< password for password response_types, string
  I_OPT_ISSUER                                = 35, ///< issuer value, string
  I_OPT_USERINFO                              = 36, ///< userinfo result, string
  I_OPT_NONCE_GENERATE                        = 37, ///< Generate a random nonce value
  I_OPT_STATE_GENERATE                        = 38, ///< Generate a random state value
  I_OPT_X5U_FLAGS                             = 39, ///< x5u flage to apply when JWK used have a x5u property, values available are R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid, R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary, R_FLAG_IGNORE_REMOTE: do not download remote key
  I_OPT_SERVER_KID                            = 40, ///< key id to use if multiple jwk are available on the server, string
  I_OPT_SERVER_ENC_ALG                        = 41, ///< key id to use if multiple jwk are available on the server, string
  I_OPT_SERVER_ENC                            = 42, ///< key id to use if multiple jwk are available on the server, string
  I_OPT_CLIENT_KID                            = 43, ///< key id to use if multiple jwk are available on the client, string
  I_OPT_CLIENT_SIGN_ALG                       = 44, ///< signature algorithm to use when the client signs a request in a JWT, values available are 'none', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'EDDSA'
  I_OPT_CLIENT_ENC_ALG                        = 45, ///< key encryption algorithm to use when the client encrypts a request in a JWT, values available are 'RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256', 'A128KW', 'A192KW', 'A256KW', 'DIR', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW or 'PBES2-HS512+A256KW', warning: some algorithm may be unavailable depending on Rhonabwy version used
  I_OPT_CLIENT_ENC                            = 46, ///< data encryption algorithm to use when the client encrypts a request in a JWT, values available are 'A128CBC-HS256,' 'A192CBC-HS384,' 'A256CBC-HS512,' 'A128GCM,' 'A192GCM,' 'A256GCM,' warning: some algorithm may be unavailable depending on Rhonabwy version used
  I_OPT_TOKEN_JTI                             = 47, ///< jti value, string
  I_OPT_TOKEN_JTI_GENERATE                    = 48, ///< Generate a random jti value
  I_OPT_TOKEN_EXP                             = 49, ///< JWT token request expiration time in seconds
  I_OPT_TOKEN_TARGET                          = 50, ///< access_token which is the target of a revocation or an introspection, string
  I_OPT_TOKEN_TARGET_TYPE_HINT                = 51, ///< access_token which is the target of a revocation or an introspection, string
  I_OPT_REVOCATION_ENDPOINT                   = 52, ///< absolute url for the revocation endpoint, string
  I_OPT_INTROSPECTION_ENDPOINT                = 53, ///< absolute url for the introspection endpoint, string
  I_OPT_REGISTRATION_ENDPOINT                 = 54, ///< absolute url for the client registration endpoint, string
  I_OPT_DEVICE_AUTHORIZATION_ENDPOINT         = 55, ///< absolute url for the pushed authorization endpoint, string
  I_OPT_DEVICE_AUTH_CODE                      = 56, ///< device authorization code sent by the AS
  I_OPT_DEVICE_AUTH_USER_CODE                 = 57, ///< device authorization user code sent by the AS
  I_OPT_DEVICE_AUTH_VERIFICATION_URI          = 58, ///< device authorization verification URI sent by the AS
  I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE = 59, ///< device authorization verification URI complete sent by the AS
  I_OPT_DEVICE_AUTH_EXPIRES_IN                = 60, ///< device authorization code expiration sent by the AS
  I_OPT_DEVICE_AUTH_INTERVAL                  = 61, ///< device authorization code verification interval sent by the AS
  I_OPT_END_SESSION_ENDPOINT                  = 62, ///< absolute url for the end session endpoint, string
  I_OPT_CHECK_SESSION_IRAME                   = 63, ///< absolute url for the check session iframe, string
  I_OPT_PUSHED_AUTH_REQ_ENDPOINT              = 64, ///< absolute url for the pushed authoization endpoint, string
  I_OPT_PUSHED_AUTH_REQ_REQUIRED              = 65, ///< are pushed authorization requests required, boolean
  I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN            = 66, ///< pushed authorization request expiration time in seconds
  I_OPT_PUSHED_AUTH_REQ_URI                   = 67, ///< request_uri sent by the par endpoint result, string
  I_OPT_USE_DPOP                              = 68, ///< Generate and use a DPoP when accessing endpoints userinfo, introspection and revocation
  I_OPT_DPOP_KID                              = 69, ///< key id to use when signing a DPoP
  I_OPT_DECRYPT_CODE                          = 70, ///< Decrypt code when received by the AS as a JWE
  I_OPT_DECRYPT_REFRESH_TOKEN                 = 71, ///< Decrypt refresh token when received by the AS as a JWE
  I_OPT_DECRYPT_ACCESS_TOKEN                  = 72, ///< Decrypt access token when received by the AS as a JWE
  I_OPT_DPOP_SIGN_ALG                         = 73, ///< signature algorithm to use when the client signs a DPoP, values available are 'none', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'EDDSA'
  I_OPT_TLS_KEY_FILE                          = 74, ///< Path to the private key PEM file to use in a TLS authentication
  I_OPT_TLS_CERT_FILE                         = 75, ///< Path to the certificate PEM file to use in a TLS authentication
  I_OPT_REMOTE_CERT_FLAG                      = 76, ///< Flags to use with remote connexions to ignore incorrect certificates, flags available are I_REMOTE_HOST_VERIFY_PEER, I_REMOTE_HOST_VERIFY_HOSTNAME, I_REMOTE_PROXY_VERIFY_PEER, I_REMOTE_PROXY_VERIFY_HOSTNAME, I_REMOTE_VERIFY_NONE, default is I_REMOTE_HOST_VERIFY_PEER|I_REMOTE_HOST_VERIFY_HOSTNAME|I_REMOTE_PROXY_VERIFY_PEER|I_REMOTE_PROXY_VERIFY_HOSTNAME
  I_OPT_PKCE_CODE_VERIFIER                    = 77, ///< PKCE code verifier, must be a string of 43 characters minumum only using the characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
  I_OPT_PKCE_CODE_VERIFIER_GENERATE           = 78, ///< Generate a random PKCE code verifier
  I_OPT_PKCE_METHOD                           = 79, ///< PKCE method to use, values available are I_PKCE_NONE (no PKCE, default), I_PKCE_METHOD_PLAIN or I_PKCE_METHOD_S256
  I_OPT_RESOURCE_INDICATOR                    = 80  ///< Resource indicator as detailed in the RFC 8707
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
  char        * end_session_endpoint;
  char        * check_session_iframe;
  char        * device_authorization_endpoint;
  char        * registration_endpoint;
  char        * pushed_authorization_request_endpoint;
  uint          result;
  char        * error;
  char        * error_description;
  char        * error_uri;
  char        * code;
  char        * refresh_token;
  char        * access_token;
  json_t      * access_token_payload;
  char        * token_target;
  char        * token_target_type_hint;
  char        * token_type;
  uint          expires_in;
  time_t        expires_at;
  char        * id_token;
  json_t      * id_token_payload;
  uint          auth_method;
  uint          token_method;
  jwks_t      * server_jwks;
  char        * server_kid;
  jwa_alg       server_enc_alg;
  jwa_enc       server_enc;
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
  json_t      * j_authorization_details;
  char        * device_auth_code;
  char        * device_auth_user_code;
  char        * device_auth_verification_uri;
  char        * device_auth_verification_uri_complete;
  uint          device_auth_expires_in;
  uint          device_auth_interval;
  uint          require_pushed_authorization_requests;
  uint          pushed_authorization_request_expires_in;
  char        * pushed_authorization_request_uri;
  int           use_dpop;
  char        * dpop_kid;
  jwa_alg       dpop_sign_alg;
  int           decrypt_code;
  int           decrypt_refresh_token;
  int           decrypt_access_token;
  char        * key_file;
  char        * cert_file;
  int           remote_cert_flag;
  char        * pkce_code_verifier;
  int           pkce_method;
  json_t      * j_claims;
  char        * resource_indicator;
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
 * I_RESPONSE_TYPE_ID_TOKEN, I_RESPONSE_TYPE_PASSWORD, I_RESPONSE_TYPE_CLIENT_CREDENTIALS,
 * I_RESPONSE_TYPE_REFRESH_TOKEN and I_RESPONSE_TYPE_DEVICE_CODE
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
 * options availble are I_OPT_RESULT, I_OPT_AUTH_METHOD, I_OPT_TOKEN_METHOD,
 * I_OPT_EXPIRES_IN, I_OPT_EXPIRES_AT, I_OPT_STATE_GENERATE, I_OPT_NONCE_GENERATE,
 * I_OPT_X5U_FLAGS, I_OPT_OPENID_CONFIG_STRICT, I_OPT_TOKEN_JTI_GENERATE,
 * I_OPT_TOKEN_EXP, I_OPT_DEVICE_AUTH_EXPIRES_IN, I_OPT_DEVICE_AUTH_INTERVAL,
 * I_OPT_PUSHED_AUTH_REQ_REQUIRED, I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN, I_OPT_USE_DPOP,
 * I_OPT_DECRYPT_CODE, I_OPT_DECRYPT_REFRESH_TOKEN, I_OPT_DECRYPT_ACCESS_TOKEN,
 * I_OPT_REMOTE_CERT_FLAG, I_OPT_PKCE_CODE_VERIFIER_GENERATE, I_OPT_PKCE_METHOD
 * @param i_value: The unsigned integer value to set
 * @return I_OK on success, an error value on error
 */
int i_set_int_parameter(struct _i_session * i_session, i_option option, uint i_value);

/**
 * Sets a char * property value
 * @param i_session: a reference to a struct _i_session *
 * @param option: the option to set
 * options available are I_OPT_SCOPE, I_OPT_SCOPE_APPEND, I_OPT_STATE,
 * I_OPT_NONCE, I_OPT_REDIRECT_URI, I_OPT_REDIRECT_TO, I_OPT_CLIENT_ID,
 * I_OPT_CLIENT_SECRET, I_OPT_AUTH_ENDPOINT, I_OPT_TOKEN_ENDPOINT,
 * I_OPT_OPENID_CONFIG_ENDPOINT, I_OPT_OPENID_CONFIG, I_OPT_USERINFO_ENDPOINT,
 * I_OPT_ERROR, I_OPT_ERROR_DESCRIPTION, I_OPT_ERROR_URI, I_OPT_CODE,
 * I_OPT_REFRESH_TOKEN, I_OPT_ACCESS_TOKEN, I_OPT_ID_TOKEN, I_OPT_TOKEN_TYPE,
 * I_OPT_USERNAME, I_OPT_USER_PASSWORD, I_OPT_ISSUER, I_OPT_USERINFO,
 * I_OPT_SERVER_KID, I_OPT_SERVER_ENC_ALG, I_OPT_SERVER_ENC, I_OPT_CLIENT_KID,
 * I_OPT_CLIENT_SIGN_ALG, I_OPT_CLIENT_ENC_ALG, I_OPT_CLIENT_ENC, I_OPT_TOKEN_JTI,
 * I_OPT_TOKEN_TARGET, I_OPT_TOKEN_TARGET_TYPE_HINT, I_OPT_REVOCATION_ENDPOINT,
 * I_OPT_INTROSPECTION_ENDPOINT, I_OPT_REGISTRATION_ENDPOINT,
 * I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, I_OPT_DEVICE_AUTH_CODE,
 * I_OPT_DEVICE_AUTH_USER_CODE, I_OPT_DEVICE_AUTH_VERIFICATION_URI,
 * I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE, I_OPT_END_SESSION_ENDPOINT,
 * I_OPT_CHECK_SESSION_IRAME, I_OPT_PUSHED_AUTH_REQ_ENDPOINT,
 * I_OPT_PUSHED_AUTH_REQ_URI, I_OPT_DPOP_KID, I_OPT_DPOP_SIGN_ALG,
 * I_OPT_TLS_KEY_FILE, I_OPT_TLS_CERT_FILE, I_OPT_PKCE_CODE_VERIFIER,
 * I_OPT_RESOURCE_INDICATOR
 * @param s_value: The const char * value to set
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
 * Adds a claim to the request
 * @param i_session: a reference to a struct _i_session *
 * @param target: where the claim should be returned, values available are I_CLAIM_TARGET_ALL,
 * I_CLAIM_TARGET_USERINFO or I_CLAIM_TARGET_ID_TOKEN
 * @param claim: the name of the claim
 * @param essential: is the claim essential value set or null
 * values available are I_CLAIM_ESSENTIAL_NULL, I_CLAIM_ESSENTIAL_TRUE, I_CLAIM_ESSENTIAL_FALSE
 * or I_CLAIM_ESSENTIAL_IGNORE
 * @param value: will override essential parameter if set, sets the claim value
 * with the content of the value parsed in JSON
 * @return I_OK on success, an error value on error
 */
int i_add_claim_request(struct _i_session * i_session, int target, const char * claim, int essential, const char * value);

/**
 * Removes a claim from the request
 * @param i_session: a reference to a struct _i_session *
 * @param target: where the claim should be returned, values available are I_CLAIM_TARGET_ALL,
 * I_CLAIM_TARGET_USERINFO or I_CLAIM_TARGET_ID_TOKEN
 * @param claim: the name of the claim to remove
 * @return I_OK on success, an error value on error
 */
int i_remove_claim_request(struct _i_session * i_session, int target, const char * claim);

/**
 * Adds an rich authorization request object in JSON format or replace it if the type already exists
 * @param i_session: a reference to a struct _i_session *
 * @param type: the type of the authorization request
 * @param j_value: the authorization request, must be a JSON object
 * @return I_OK on success, an error value on error
 */
int i_set_rich_authorization_request_json_t(struct _i_session * i_session, const char * type, json_t * j_value);

/**
 * Adds an rich authorization request object in stringified JSON format or replace it if the type already exists
 * @param i_session: a reference to a struct _i_session *
 * @param type: the type of the authorization request
 * @param value: the authorization request, must be a stringified JSON object
 * @return I_OK on success, an error value on error
 */
int i_set_rich_authorization_request_str(struct _i_session * i_session, const char * type, const char * value);

/**
 * Remove an authorization request object based on the type
 * @param i_session: a reference to a struct _i_session *
 * @param type: the type of the authorization request
 * @return I_OK on success, an error value on error
 */
int i_remove_rich_authorization_request(struct _i_session * i_session, const char * type);

/**
 * Returns an authorization request object based on the type
 * @param i_session: a reference to a struct _i_session *
 * @param type: the type of the authorization request
 * @return a json_t * containing a JSON authorization request, or NULL if not found, must be i_free'd after use
 */
json_t * i_get_rich_authorization_request_json_t(struct _i_session * i_session, const char * type);

/**
 * Returns an authorization request object based on the type
 * @param i_session: a reference to a struct _i_session *
 * @param type: the type of the authorization request
 * @return a char * containing a JSON stringified authorization request, or NULL if not found, must be i_free'd after use
 */
char * i_get_rich_authorization_request_str(struct _i_session * i_session, const char * type);

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
 * options availble are I_OPT_RESULT, I_OPT_AUTH_METHOD, I_OPT_TOKEN_METHOD,
 * I_OPT_EXPIRES_IN, I_OPT_EXPIRES_AT, I_OPT_STATE_GENERATE, I_OPT_NONCE_GENERATE,
 * I_OPT_X5U_FLAGS, I_OPT_OPENID_CONFIG_STRICT, I_OPT_TOKEN_JTI_GENERATE,
 * I_OPT_TOKEN_EXP, I_OPT_DEVICE_AUTH_EXPIRES_IN, I_OPT_DEVICE_AUTH_INTERVAL,
 * I_OPT_PUSHED_AUTH_REQ_REQUIRED, I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN, I_OPT_USE_DPOP,
 * I_OPT_DECRYPT_CODE, I_OPT_DECRYPT_REFRESH_TOKEN, I_OPT_DECRYPT_ACCESS_TOKEN,
 * I_OPT_REMOTE_CERT_FLAG, I_OPT_PKCE_CODE_VERIFIER_GENERATE, I_OPT_PKCE_METHOD
 * @return the option value
 */
uint i_get_int_parameter(struct _i_session * i_session, i_option option);

/**
 * Returns the char * value of an option
 * @param i_session: a reference to a struct _i_session *
 * @param option: the option to get
 * options available are I_OPT_SCOPE, I_OPT_SCOPE_APPEND, I_OPT_STATE,
 * I_OPT_NONCE, I_OPT_REDIRECT_URI, I_OPT_REDIRECT_TO, I_OPT_CLIENT_ID,
 * I_OPT_CLIENT_SECRET, I_OPT_AUTH_ENDPOINT, I_OPT_TOKEN_ENDPOINT,
 * I_OPT_OPENID_CONFIG_ENDPOINT, I_OPT_OPENID_CONFIG, I_OPT_USERINFO_ENDPOINT,
 * I_OPT_ERROR, I_OPT_ERROR_DESCRIPTION, I_OPT_ERROR_URI, I_OPT_CODE,
 * I_OPT_REFRESH_TOKEN, I_OPT_ACCESS_TOKEN, I_OPT_ID_TOKEN, I_OPT_TOKEN_TYPE,
 * I_OPT_USERNAME, I_OPT_USER_PASSWORD, I_OPT_ISSUER, I_OPT_USERINFO,
 * I_OPT_SERVER_KID, I_OPT_SERVER_ENC_ALG, I_OPT_SERVER_ENC, I_OPT_CLIENT_KID,
 * I_OPT_CLIENT_SIGN_ALG, I_OPT_CLIENT_ENC_ALG, I_OPT_CLIENT_ENC, I_OPT_TOKEN_JTI,
 * I_OPT_TOKEN_TARGET, I_OPT_TOKEN_TARGET_TYPE_HINT, I_OPT_REVOCATION_ENDPOINT,
 * I_OPT_INTROSPECTION_ENDPOINT, I_OPT_REGISTRATION_ENDPOINT,
 * I_OPT_DEVICE_AUTHORIZATION_ENDPOINT, I_OPT_DEVICE_AUTH_CODE,
 * I_OPT_DEVICE_AUTH_USER_CODE, I_OPT_DEVICE_AUTH_VERIFICATION_URI,
 * I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE, I_OPT_END_SESSION_ENDPOINT,
 * I_OPT_CHECK_SESSION_IRAME, I_OPT_PUSHED_AUTH_REQ_ENDPOINT,
 * I_OPT_PUSHED_AUTH_REQ_URI, I_OPT_DPOP_KID, I_OPT_DPOP_SIGN_ALG,
 * I_OPT_TLS_KEY_FILE, I_OPT_TLS_CERT_FILE, I_OPT_PKCE_CODE_VERIFIER,
 * I_OPT_RESOURCE_INDICATOR
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
 * Gets the server configuration
 * @param i_session: a reference to a struct _i_session *
 * @return the server configuration in json_t * format
 */
json_t * i_get_server_configuration(struct _i_session * i_session);

/**
 * Gets the server configuration
 * @param i_session: a reference to a struct _i_session *
 * @return the server public JWKS in json_t * format
 */
json_t * i_get_server_jwks(struct _i_session * i_session);

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
int i_get_openid_config(struct _i_session * i_session);

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
 * Validates the access_token signature and content if necessary
 * According to OAuth 2.0 Access Token JWT Profile Draft 12
 * https://datatracker.ietf.org/doc/html/draft-ietf-oauth-access-token-jwt-12
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_verify_jwt_access_token(struct _i_session * i_session);

/**
 * Loads the userinfo endpoint using the access_token
 * if the result is a JWT, validate the signature
 * and/or decrypt the token
 * sets the result to i_session->userinfo as char *
 * and i_session->j_userinfo as json_t * if the result is in JSON format
 * @param i_session: a reference to a struct _i_session *
 * @param get_jwt: Request result as a JWT
 * @return I_OK on success, an error value on error
 */
int i_get_userinfo(struct _i_session * i_session, int get_jwt);

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
int i_get_userinfo_custom(struct _i_session * i_session, const char * http_method, struct _u_map * additional_query, struct _u_map * additional_headers);

/**
 * Loads the introspection endpoint for the access_token_target
 * Using the access_token for authentication
 * @param i_session: a reference to a struct _i_session *
 * @param j_result: if not NULL, set an allocated json_t * object with the endpoint result
 * @param authentication: authentication type
 * types available are I_INTROSPECT_REVOKE_AUTH_NONE,
 * I_INTROSPECT_REVOKE_AUTH_ACCESS_TOKEN,
 * I_INTROSPECT_REVOKE_AUTH_CLIENT_TARGET
 * @param get_jwt: Request result as a JWT
 * @return I_OK on success and if the access_token_target is valid,
 * I_ERROR_UNAUTHORIZED if the access_token_target is invalid, another error value on error
 */
int i_get_token_introspection(struct _i_session * i_session, json_t ** j_result, int authentication, int get_jwt);

/**
 * Loads the revocation endpoint for the access_token_target
 * Using the access_token for authentication
 * @param i_session: a reference to a struct _i_session *
 * @param authentication: authentication type
 * types available are I_INTROSPECT_REVOKE_AUTH_NONE,
 * I_INTROSPECT_REVOKE_AUTH_ACCESS_TOKEN,
 * I_INTROSPECT_REVOKE_AUTH_CLIENT_TARGET
 * @return I_OK on success, an error value on error
 */
int i_revoke_token(struct _i_session * i_session, int authentication);

/**
 * Register a new client using the dynamic registration endpoint
 * Using the access_token for authentication if set
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
 * Manages a client registration using the dynamic registration endpoint
 * Using the access_token for authentication
 * @param i_session: a reference to a struct _i_session *
 * @param j_parameters: a json_t * object containing the client metadata
 * The metadata content depends on the registration endpoint but at least
 * the parameter redirect_uris (array of string) is required to register a new client
 * @param update_session: if the registration is succesfull, update the session with the new client_id and client_secret
 * @param j_result: if not NULL, set an allocated json_t * object with the endpoint result
 * @return I_OK on success, an error value on error
 */
int i_manage_registration_client(struct _i_session * i_session, json_t * j_parameters, int update_session, json_t ** j_result);

/**
 * Gets a client registration using the dynamic registration endpoint
 * Using the access_token for authentication
 * @param i_session: a reference to a struct _i_session *
 * @param j_result: if not NULL, set an allocated json_t * object with the endpoint result
 * @return I_OK on success, an error value on error
 */
int i_get_registration_client(struct _i_session * i_session, json_t ** j_result);

/**
 * Generates a DPoP token based on the given parameters and the internal state of the struct _i_session
 * The jti must be previously generated via I_OPT_TOKEN_JTI or generated via I_OPT_TOKEN_JTI_GENERATE
 * @param i_session: a reference to a struct _i_session *
 * @param htm: The htm claim value, the HTTP method used to access the protected resource (GET, POST, PATCH, etc.)
 * @param htu: The htu claim value, the HTTP url used to access the protected resource (ex: https://resource.tld/object)
 * @param iat: the iat claim value, the epoch time value when the DPoP token must be set. If 0, the current time will be used
 * @return a char * containing the DPoP token signed, must be i_free'd after use
 */
char * i_generate_dpop_token(struct _i_session * i_session, const char * htm, const char * htu, time_t iat);

/**
 * Sends an HTTP request to a REST API using the access token to authenticate
 * This functions uses ulfius' function ulfius_send_http_request
 * It will add the i_session's access token to the request
 * As well as a DPoP token if required
 * @param i_session: a reference to a struct _i_session *, mandatory
 * @param http_request: the request parameters, will store all the request data (method, url, headers, body parameters, etc.), mandatory
 * @param http_response: the response parameters, will store all the response data (status, headers, body response, etc.), may be NULL
 * @param refresh_if_expired: if set to true, the access token will be refreshed if expired
 * @param bearer_type: How the access token will be provided to the resource server
 * options available are: I_BEARER_TYPE_HEADER, I_BEARER_TYPE_BODY, I_BEARER_TYPE_URL
 * @param use_dpop: set this flag to 1 if you want to send the DPoP header in the request
 * The jti must be previously generated via I_OPT_TOKEN_JTI or generated via I_OPT_TOKEN_JTI_GENERATE
 * @param dpop_iat: the iat claim value, the epoch time value when the DPoP token must be set. If 0, the current time will be used
 * @return I_OK on success, an error value on error
 */
int i_perform_resource_service_request(struct _i_session * i_session, struct _u_request * http_request, struct _u_response * http_response, int refresh_if_expired, int bearer_type, int use_dpop, time_t dpop_iat);

/**
 * Executes a pushed authorization request
 * and sets the values I_OPT_PUSHED_AUTH_REQ_URI and I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN on success
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_run_par_request(struct _i_session * i_session);

/**
 * Executes a device authorization request
 * and sets the code, user code and verification uri in the _i_session *
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_run_device_auth_request(struct _i_session * i_session);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif // __IDDAWC_H_
