# Iddawc API documentation

Iddawc is a C library used to implement OAuth2/OIDC clients according to the [OAuth2 RFC](https://tools.ietf.org/html/rfc6749) and the [OpenID Connect Specs](https://openid.net/specs/openid-connect-core-1_0.html).

It's based on [Ulfius](https://github.com/babelouest/ulfius) library for the HTTP requests and response management and [Rhonabwy](https://github.com/babelouest/rhonabwy) library for the JOSE management.

Iddawc supports the following features:

- Loading openid-configuration endpoints and parsing the results
- Making `auth` requests using the given parameters (`client_id`, `client_secret`, `redirect_uri`, etc.) and parsing the result
- Making `token` requests using the given parameters (`code`, `client_id`, `client_secret`, `redirect_uri`, etc.) and parsing the result
- Making `userinfo`, `token introspection`, `token revocation` requests
- Parse responses, validate id_token
- Registering new clients using the `register` endpoint if any
- Sending signed and or encrypted requests in the `auth` and `token` endpoints
- Client TLS Authentication available
- Making Pushed Auth Requests
- Making Rich Auth Requests
- Adding claims to requests
- Sending DPoP proofs
- JWT Secured Authorization Response Mode
- End session and single-logout functionalities

## Return values

Lots of functions in Rhonabwy library return an int value. The returned value can be one of the following:

```C
#define I_OK                 0
#define I_ERROR              1
#define I_ERROR_PARAM        2
#define I_ERROR_MEMORY       3
#define I_ERROR_UNAUTHORIZED 4
#define I_ERROR_SERVER       5
```

If a function is successful, it will return `I_OK` (0), otherwise an error code is returned.

## Global init and close

It's **recommended** to use `i_global_init` and `i_global_close` at the beginning and at the end of your program to initialize and cleanup internal values and settings. This will make outgoing requests faster, especially if you use lots of them, and dispatch your memory allocation functions in curl and Jansson if you changed them. These functions are **NOT** thread-safe, so you must use them in a single thread context.

```C
int i_global_init();

void i_global_close();
```

## Log messages

Usually, a log message is displayed to explain more specifically what happened on error. The log manager used is [Yder](https://github.com/babelouest/yder). You can enable Yder log messages on the console with the following command at the beginning of your program:

```C
int main() {
  y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc client program");
  
  // Do your code here
  
  y_close_logs();
}
```

Example of an error log message:

```
2020-04-05T16:14:31 - Iddawc: i_run_auth_request - Unsupported auth_method
```

Go to Yder [API Documentation](https://babelouest.github.io/yder/) for more details.

## Core functions and struct _i_session * variables

Iddawc is based in the `struct _i_session` to store all the required parameters and results to work. You must use the init and clean functions before using a `struct _i_session *` and after finishing using it.

```C
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
```

### Get or set properties

To set or get parameters stored in the `struct _i_session *`, you must use the appropriate function

```C
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
 * options availble are I_OPT_RESULT, I_OPT_AUTH_METHOD, I_OPT_TOKEN_METHOD,
 * I_OPT_EXPIRES_IN, I_OPT_EXPIRES_AT, I_OPT_STATE_GENERATE, I_OPT_NONCE_GENERATE,
 * I_OPT_X5U_FLAGS, I_OPT_OPENID_CONFIG_STRICT, I_OPT_TOKEN_JTI_GENERATE,
 * I_OPT_TOKEN_EXP, I_OPT_DEVICE_AUTH_EXPIRES_IN, I_OPT_DEVICE_AUTH_INTERVAL,
 * I_OPT_PUSHED_AUTH_REQ_REQUIRED, I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN, I_OPT_USE_DPOP,
 * I_OPT_DECRYPT_CODE, I_OPT_DECRYPT_REFRESH_TOKEN, I_OPT_DECRYPT_ACCESS_TOKEN,
 * I_OPT_REMOTE_CERT_FLAG, I_OPT_PKCE_CODE_VERIFIER_GENERATE, I_OPT_PKCE_METHOD,
 * I_OPT_CIBA_MODE, I_OPT_CIBA_LOGIN_HINT_FORMAT, I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN_GENERATE,
 * I_OPT_CIBA_AUTH_REQ_EXPIRES_IN, I_OPT_CIBA_AUTH_REQ_INTERVAL,
 * I_OPT_FRONTCHANNEL_LOGOUT_SESSION_REQUIRED, I_OPT_BACKCHANNEL_LOGOUT_SESSION_REQUIRED,
 * I_OPT_SERVER_JWKS_CACHE_EXPIRATION, I_OPT_SAVE_HTTP_REQUEST_RESPONSE
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
 * I_OPT_RESOURCE_INDICATOR, I_OPT_ACCESS_TOKEN_SIGNING_ALG,
 * I_OPT_ACCESS_TOKEN_ENCRYPTION_ALG, I_OPT_ACCESS_TOKEN_ENCRYPTION_ENC,
 * I_OPT_ID_TOKEN_SIGNING_ALG, I_OPT_ID_TOKEN_ENCRYPTION_ALG, I_OPT_ID_TOKEN_ENCRYPTION_ENC,
 * I_OPT_USERINFO_SIGNING_ALG, I_OPT_USERINFO_ENCRYPTION_ALG, I_OPT_USERINFO_ENCRYPTION_ENC,
 * I_OPT_REQUEST_OBJECT_SIGNING_ALG, I_OPT_REQUEST_OBJECT_ENCRYPTION_ALG,
 * I_OPT_REQUEST_OBJECT_ENCRYPTION_ENC, I_OPT_TOKEN_ENDPOINT_SIGNING_ALG,
 * I_OPT_TOKEN_ENDPOINT_ENCRYPTION_ALG, I_OPT_TOKEN_ENDPOINT_ENCRYPTION_ENC,
 * I_OPT_CIBA_REQUEST_SIGNING_ALG, I_OPT_CIBA_REQUEST_ENCRYPTION_ALG,
 * I_OPT_CIBA_REQUEST_ENCRYPTION_ENC, I_OPT_AUTH_RESPONSE_SIGNING_ALG,
 * I_OPT_AUTH_RESPONSE_ENCRYPTION_ALG, I_OPT_AUTH_RESPONSE_ENCRYPTION_ENC,
 * I_OPT_CIBA_ENDPOINT, I_OPT_CIBA_USER_CODE, I_OPT_CIBA_LOGIN_HINT,
 * I_OPT_CIBA_LOGIN_HINT_KID, I_OPT_CIBA_BINDING_MESSAGE, I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN,
 * I_OPT_CIBA_AUTH_REQ_ID, I_OPT_CIBA_CLIENT_NOTIFICATION_ENDPOINT,
 * I_OPT_FRONTCHANNEL_LOGOUT_URI, I_OPT_BACKCHANNEL_LOGOUT_URI,
 * I_OPT_POST_LOGOUT_REDIRECT_URI, I_OPT_ID_TOKEN_SID,
 * I_OPT_DPOP_NONCE_AS, I_OPT_DPOP_NONCE_RS, I_OPT_HTTP_PROXY
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
 * I_OPT_RESOURCE_INDICATOR, I_OPT_ACCESS_TOKEN_SIGNING_ALG,
 * I_OPT_ACCESS_TOKEN_ENCRYPTION_ALG, I_OPT_ACCESS_TOKEN_ENCRYPTION_ENC,
 * I_OPT_ID_TOKEN_SIGNING_ALG, I_OPT_ID_TOKEN_ENCRYPTION_ALG, I_OPT_ID_TOKEN_ENCRYPTION_ENC,
 * I_OPT_USERINFO_SIGNING_ALG, I_OPT_USERINFO_ENCRYPTION_ALG, I_OPT_USERINFO_ENCRYPTION_ENC,
 * I_OPT_REQUEST_OBJECT_SIGNING_ALG, I_OPT_REQUEST_OBJECT_ENCRYPTION_ALG,
 * I_OPT_REQUEST_OBJECT_ENCRYPTION_ENC, I_OPT_TOKEN_ENDPOINT_SIGNING_ALG,
 * I_OPT_TOKEN_ENDPOINT_ENCRYPTION_ALG, I_OPT_TOKEN_ENDPOINT_ENCRYPTION_ENC,
 * I_OPT_CIBA_REQUEST_SIGNING_ALG, I_OPT_CIBA_REQUEST_ENCRYPTION_ALG,
 * I_OPT_CIBA_REQUEST_ENCRYPTION_ENC, I_OPT_AUTH_RESPONSE_SIGNING_ALG,
 * I_OPT_AUTH_RESPONSE_ENCRYPTION_ALG, I_OPT_AUTH_RESPONSE_ENCRYPTION_ENC,
 * I_OPT_CIBA_ENDPOINT, I_OPT_CIBA_USER_CODE, I_OPT_CIBA_LOGIN_HINT,
 * I_OPT_CIBA_LOGIN_HINT_KID, I_OPT_CIBA_BINDING_MESSAGE, I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN,
 * I_OPT_CIBA_AUTH_REQ_ID, I_OPT_CIBA_CLIENT_NOTIFICATION_ENDPOINT,
 * I_OPT_FRONTCHANNEL_LOGOUT_URI, I_OPT_BACKCHANNEL_LOGOUT_URI,
 * I_OPT_POST_LOGOUT_REDIRECT_URI, I_OPT_ID_TOKEN_SID,
 * I_OPT_DPOP_NONCE_AS, I_OPT_DPOP_NONCE_RS, I_OPT_HTTP_PROXY
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
 * Adds an authorization request object or replace it if the type already exists
 * @param i_session: a reference to a struct _i_session *
 * @param type: the type of the authorization request
 * @param value: the authorization request, must be a stringified JSON object
 * @return I_OK on success, an error value on error
 */
int i_set_rich_authorization_request(struct _i_session * i_session, const char * type, const char * value);

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
 * @return a char * containing a JSON stringified exported session, must be i_free'd after use, or NULL if not found
 */
char * i_get_rich_authorization_request(struct _i_session * i_session, const char * type);

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
```

### Import or export sessions

Iddawc supports importing or exporting `struct _i_session *`. The export format is `JSON`. Be careful, the JSON output is unsecured and contains all secrets and tokens without encryption!

You can import and export either in `json_t *` or `char *`, the `char *` format is a JSON stringified.

```C
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
```

## Run OAuth2 or OIDC requests

Finally, to run OAuth2 or OIDC requests, you must use the dedicated functions using the initialized and set `struct _i_session *` and some additional parameters if required.

### Load openid-config

When available, you can load the Openid Config endpoint. This will parse the result and fill the `struct _i_session *` parameters with all the required results (auth endpoint, public keys, signature algorithms, etc.). Using this function required to have set the property `I_OPT_OPENID_CONFIG_ENDPOINT`.

```C
/**
 * Loads and parse the openid_config endpoint, and sets the parameter values accordingly
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_get_openid_config(struct _i_session * i_session);
```

### Build and run auth request and parse results

The function `i_build_auth_url_get` can be used to build the full auth request with all the parameters in the URL query for a GET request.

```C
/**
 * Builds the url to GET the auth endpoint
 * sets the result to parameter I_OPT_REDIRECT_TO
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_build_auth_url_get(struct _i_session * i_session);
```

The function `i_run_auth_request` builds the full auth requests and executes it. If the OAuth2 server answers with a successful response, the response will be parsed in the session properties. Otherwise, the redirect_to value and the errors if any will be parsed and made available in the session properties.

```C
/**
 * Executes an auth request using the implicit endpoint
 * and sets the result values in the session variables
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_run_auth_request(struct _i_session * i_session);
```

If the auth request is executed by an external program such as the browser, you can parse the redirect_to response afterwards using this function. You must set the `I_OPT_REDIRECT_TO`.

```C
/**
 * Parses the redirect_uri given by the oauth2 server in the implicit flow
 * The redirect_uri may contain a code, a token, an id_token, or an error
 * Fills the session parameters with the values given in the redirect_uri
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_parse_redirect_to(struct _i_session * i_session);
```

### Build and run device authorization requests and parse results

If you need to run a device authorization request, you need to use the response type `I_RESPONSE_TYPE_DEVICE_CODE` and use the function `i_run_device_auth_request`, the parameter `I_OPT_DEVICE_AUTHORIZATION_ENDPOINT` must be set. On success, the parameters `I_OPT_DEVICE_AUTH_CODE`, `I_OPT_DEVICE_AUTH_USER_CODE`, `I_OPT_DEVICE_AUTH_VERIFICATION_URI`, `I_OPT_DEVICE_AUTH_VERIFICATION_URI_COMPLETE`, `I_OPT_DEVICE_AUTH_EXPIRES_IN` and `I_OPT_DEVICE_AUTH_INTERVAL` will be set. After that, you'll need to run `i_run_token_request` (see below) every few seconds until you get a success or a definitive error.

```C
/**
 * Executes a device authorization request
 * and sets the code, user code and verification uri in the _i_session *
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_run_device_auth_request(struct _i_session * i_session);
```

### Build and run pushed authorization requests and parse results

To run a device authorization request, you need to use the function `i_run_par_request`, and the other parameters as if the request was a normal `auth` request (`response_type`, `client_id`, `scope`, `redirect_uri`, authenticaiton type, etc.).

On success, the parameters `I_OPT_PUSHED_AUTH_REQ_URI` and `I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN` will be automatically set. Then the function `i_build_auth_url_get` will build an auth url using the request_uri and client_id parameters only.

```C
/**
 * Executes a pushed authorization request
 * and sets the values I_OPT_PUSHED_AUTH_REQ_URI and I_OPT_PUSHED_AUTH_REQ_EXPIRES_IN on success
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_run_par_request(struct _i_session * i_session);
```

### Build and run token requests and parse results

To execute a request in the token endpoint, get a refresh token from a code or refresh a token, 

```C
/**
 * Executes a token request using the implicit endpoint
 * and sets the result values in the session variables
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_run_token_request(struct _i_session * i_session);
```

Note: By default, token endpoint authentication method is `I_TOKEN_AUTH_METHOD_NONE`. If your client needs to be authenticated, you must specify the desired method by setting the `I_OPT_TOKEN_METHOD` with one of the following values:
- `I_TOKEN_AUTH_METHOD_SECRET_BASIC`: HTTP Basic Authentication
- `I_TOKEN_AUTH_METHOD_SECRET_POST`: Secret Post Authentication
- `I_TOKEN_AUTH_METHOD_TLS_CERTIFICATE`: [MTLS](https://datatracker.ietf.org/doc/html/rfc8705) authentication
- `I_TOKEN_AUTH_METHOD_JWT_SIGN_SECRET`: Client Assertion in JWT format signed with the client secret
- `I_TOKEN_AUTH_METHOD_JWT_SIGN_PRIVKEY`: Client Assertion in JWT format signed with the client private key
- `I_TOKEN_AUTH_METHOD_JWT_ENCRYPT_SECRET`: Client Assertion in JWT format encrypted using the client secret
- `I_TOKEN_AUTH_METHOD_JWT_ENCRYPT_PUBKEY`: Client Assertion in JWT format encrypted using the AS public key

The values `I_TOKEN_AUTH_METHOD_JWT_ENCRYPT_SECRET` and `I_TOKEN_AUTH_METHOD_JWT_ENCRYPT_PUBKEY` must be combined with the values `I_TOKEN_AUTH_METHOD_JWT_SIGN_SECRET` or `I_TOKEN_AUTH_METHOD_JWT_SIGN_PRIVKEY`.

### Verify an id_token

If the auth or token endpoints returns an id_token, this one will be parsed, the signature will be verified and the content will be validated to make sure the id_token is valid.

You can also manually validate an id_token using the dedicated function. The property `I_OPT_ID_TOKEN` and the public key property must be set.

When an id_token is validated, its claims are available in the property `json_t * struct _i_session.id_token_payload`.

```C
/**
 * Validates the id_token signature and content if necessary
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_verify_id_token(struct _i_session * i_session);
```

### Verify an access_token

If the access_token is a JWT, you can use the function `i_verify_jwt_access_token` to verify its signature and content. The access token must use the format specified in the [JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068) standard.

The function will verify the claims `iss`, `iat` and `aud`.

When an access_token is validated, its claims are available in the property `json_t * struct _i_session.access_token_payload`.

```C
/**
 * Validates the access_token signature and content if necessary
 * According to OAuth 2.0 Access Token JWT Profile Draft 12
 * https://datatracker.ietf.org/doc/html/draft-ietf-oauth-access-token-jwt-12
 * @param i_session: a reference to a struct _i_session *
 * @param aud: the aud claim to verify, set to NULL to ignore aud claim
 * @return I_OK on success, an error value on error
 */
int i_verify_jwt_access_token(struct _i_session * i_session, const char * aud);
```

If your Authorization Server provides JWT Access Tokens but not strictly according to the RFC, you can disable or enable the following JWT AT checks by (un)setting the following flags to the int property `I_OPT_OPENID_CONFIG_STRICT`:

- `I_STRICT_JWT_AT_SIGNATURE`: verify JWT AT signature
- `I_STRICT_JWT_AT_HEADER_TYP`: verify JWT AT header typ to be 'jwt+at' or 'application/jwt+at'
- `I_STRICT_JWT_AT_CLAIM`: verify mandatory other claims (iss, iat, etc.)

```
// Example setting to verify the access token signature and the claims, but not the `typ` header
i_set_int_parameter(i_session, I_OPT_OPENID_CONFIG_STRICT, I_STRICT_JWT_AT_SIGNATURE|I_STRICT_JWT_AT_CLAIM); 

if (i_verify_jwt_access_token(i_session, NULL) != I_OK) {
  // Error in token validation
}
```

### Load userinfo

If an access_token is available, you can make a request to the userinfo endpoint to get information about the user.

The function `i_load_userinfo_custom` is a more advanced userinfo request where you can specify query or header parameters, to request more claims or the result as a signed JWT.

```C
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
```

### Introspect or revoke tokens

To execute introspection or revocation requests, you must set the session property `I_OPT_TOKEN_TARGET` and `I_OPT_TOKEN_TARGET_TYPE_HINT` if required.

```C
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
```

### Register new clients

You can register a new client using this dedicated functions.

You may have to set a `I_OPT_ACCESS_TOKEN` property, depending on the server configuration. If `update_session` is true and the registration is successful, the properties `I_OPT_CLIENT_ID` and `I_OPT_CLIENT_SECRET` will be set to the session, and the first `redirect_to` entry will be used as `I_OPT_REDIRECT_TO` value.

```C
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
```

### Manage clients registration

You can manage a client registration by changing its metadata or get the client registration metadata. These functions will use the access_token in the session if one is set.

```C
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
```

### Generate a DPoP token

You can use your client's private key parameters to generate a DPoP token. If you set the session property `I_OPT_USE_DPOP` to true, the functions `i_run_device_auth_request`, `i_run_par_request`, `i_get_userinfo_custom`, `i_get_userinfo`, `i_run_token_request`, `i_revoke_token`, `i_get_token_introspection` or `i_perform_resource_service_request` will add a DPoP header.

```C
/**
 * Generates a DPoP token based on the given parameters and the internal state of the struct _i_session
 * The jti must be previously generated via I_OPT_TOKEN_JTI or generated via I_OPT_TOKEN_JTI_GENERATE
 * @param i_session: a reference to a struct _i_session *
 * @param htm: The htm claim value, the HTTP method used to access the protected resource (GET, POST, PATCH, etc.)
 * @param htu: The htu claim value, the HTTP url used to access the protected resource (ex: https://resource.tld/object)
 * @param iat: the iat claim value, the epoch time value when the DPoP token must be set. If 0, the current time will be used
 * @param add_ath: Add access token hash (ath) based on the access token in the i_session
 * @return a char * containing the DPoP token signed, must be i_free'd after use
 */
char * i_generate_dpop_token(struct _i_session * i_session, const char * htm, const char * htu, time_t iat, int add_ath);
```

### Verify a DPoP proof

If you are using Iddawc in a Resource Service (RS), you can check the DPoP sent by the client using the function `i_verify_dpop_proof`. The parameter `const char * access_token` is mandatory to comply with DPoP Definition, Draft 04.

```C
/**
 * Verifies the dpop_header is valid with the jkt specified
 * @param dpop_header: the dpop header in a serialized JWT format
 * @param htm: The htm claim value, the HTTP method used to access the protected resource (GET, POST, PATCH, etc.)
 * @param htu: The htu claim value, the HTTP url used to access the protected resource (ex: https://resource.tld/object)
 * @param max_iat: the maximum age of the dpop, based on the claim iat, if set to 0, no expiration date will be checked
 * @param jkt: the signature identifier specified by the access_token
 * @param access_token: the access token linked with this proof
 * @return I_OK on success, an error value on error
 */
int i_verify_dpop_proof(const char * dpop_header, const char * htm, const char * htu, time_t max_iat, const char * jkt, const char * access_token);
```

### DPoP nonce

When a request is sent to an Auth server or a Resource server, if the server can require a nonce in the DPoP to mitigate pre-generated DPoP tokens. If so, the server sends and error response with the status 400 for the AS and 401 for the RS, and the nonce required set int the HTTP response header `"DPoP-Nonce"`. When the server sends such an error response, Iddawc will return a `I_ERROR_PARAM` value when relevant, but will set the nonce in the `struct _i_session`. It's up to the app using Iddawc to send another request by using the same function.

Example:

```C
// First call to i_get_userinfo, without DPoP nonce
res = i_get_userinfo(i_session, 0);
if (res == I_ERROR_PARAM && i_get_str_parameter(i_session, I_OPT_DPOP_NONCE_RS) != NULL) {
  // Second call to i_get_userinfo, with the DPoP nonce set automatically
  res = i_get_userinfo(i_session, 0);
}
```

### Perform a HTTP request to a Resource Service

This features uses Ulfius' `ulfius_send_http_request` function to proceed. This function requires at least a `struct _u_request` with all the request parameters.

Iddawc will add the access token previously obtained to the HTTP request using the [Bearer usage](https://tools.ietf.org/html/rfc6750) specified.

If the access token is expired, Iddawc will attempt to refresh the token.

If specified, Iddawc will generate and add a DPoP token in the request using the request parameters.

```C
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
```

Here is an example of how to use `i_perform_resource_service_request`:

```C
struct _i_session i_session;
struct _u_request req;
struct _u_response resp;
json_t * j_resp;

i_init_session(&i_session);
/*
 * All the process to get an access token is hidden, this example considers the _i_session has an access token
 */
ulfius_init_request(&req);
ulfius_init_response(&resp);

ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET", U_OPT_HTTP_URL, "https://resource.tld/object", U_OPT_NONE);

if (i_perform_resource_service_request(&i_session, &req, &resp, 1, I_BEARER_TYPE_HEADER, 1) == I_OK && resp.status == 200) {
  // j_resp contains the JSON response of the protected resource
  j_resp = ulfius_get_json_body_response(&resp, NULL);
}

i_clean_session(&i_session);
ulfius_clean_request(&req);
ulfius_clean_response(&resp);
json_decref(j_resp);
```

### CIBA Requests

Iddawc can run CIBA requests as defined in the documentation [OpenID Connect Client-Initiated Backchannel Authentication Flow - Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html).

```C
/**
 * Executes a CIBA request
 * and sets the auth_req_id, expires_in and interval in the _i_session *
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_run_ciba_request(struct _i_session * i_session);
```

Example of using `i_run_ciba_request`:

```C
struct _i_session i_session;
i_init_session(&i_session);
i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CIBA,
                                 I_OPT_OPENID_CONFIG_ENDPOINT, "https://as.tld/.well-known/openid-configuration",
                                 I_OPT_CLIENT_ID, "client",
                                 I_OPT_CLIENT_SECRET, "secret",
                                 I_OPT_AUTH_METHOD, I_TOKEN_AUTH_METHOD_SECRET_BASIC,
                                 I_OPT_SCOPE, "openid",
                                 I_OPT_CIBA_LOGIN_HINT, "{\"username\":\"ciba\"}",
                                 I_OPT_CIBA_MODE, I_CIBA_MODE_POLL,
                                 I_OPT_CIBA_LOGIN_HINT_FORMAT, I_CIBA_LOGIN_HINT_FORMAT_JSON,
                                 I_OPT_NONE);

i_get_openid_config(&i_session); // get CIBA endpoint
i_run_ciba_request(&i_session); // run request and store auth_req_id
i_run_token_request(&i_session); // get access_token and refresh_token when the user has completed the authentication
```

Note that when using ping or push mode, Iddawc doesn't implement the client notification endpoint, its implementation and communication with iddawc's session will be yours to make.

### End session

Iddawc provides 3 functions dedicated to end session capabilities: [OpenID Connect Front-Channel Logout](https://openid.net/specs/openid-connect-frontchannel-1_0.html) and [OpenID Connect Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html).

```C
/**
 * Generates an end session url to access the single logout page
 * @param i_session: a reference to a struct _i_session *
 * The session must contain an end_session_endpoint and an id_token at least
 * If a post_logout_redirect_uri is available in the session, this will be added to the url
 * @return a char * containing the end session url, must be i_free'd after use
 */
char * i_build_end_session_url(struct _i_session * i_session);

/**
 * Validates the end session token sent by the AS via the backchannel_logout_uri
 * @param i_session: a reference to a struct _i_session *
 * @param token: the end session token to validate
 * @return I_OK on success, an error value on error
 */
int i_verify_end_session_backchannel_token(struct _i_session * i_session, const char * token);

/**
 * Closes the current session by cleaning the following values of the session:
 * code, refresh token, access token, id_token, nonce, userinfo, jti,
 * device auth code, device auth user code, device auth verification uri,
 * device auth verification uri complete, PKCE code verifier,
 * CIBA user code, CIBA auth req id, id_token sid
 * @param i_session: a reference to a struct _i_session *
 * @param sid: the session ID, this parameter is optional, although if present,
 * the value will be checked with the session sid value, if they don't match,
 * i_close_session will return an error and the session will not be cleaned
 * @return I_OK on success, an error value on error
 */
int i_close_session(struct _i_session * i_session, const char * sid);
```

Even if Iddawc doesn't provide Front-Channel or Back-Channel logout endpoints, you can use the function `i_verify_end_session_backchannel_token` to verify an end_session backchannel token, and `i_close_session` to clean the current session.

### Rich Authorization Requests

Iddawc supports [OAuth 2.0 Rich Authorization Requests Draft 11](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rar-11). You can manage RAR types using the following functions:

```C
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
```

Then, when using the authentication functions (auth, device, ciba, par), the `authorization_details` parameter will be set accordingly.
