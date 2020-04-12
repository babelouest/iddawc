# Iddawc API documentation

Iddawc is a C library used to implement OAuth2/OIDC clients according to the [OAuth2 RFC](https://tools.ietf.org/html/rfc6749) and the [OpenID Connect Specs](https://openid.net/specs/openid-connect-core-1_0.html).

It's based on [Ulfius](https://github.com/babelouest/ulfius) library for the HTTP requests and response management and [Rhonabwy](https://github.com/babelouest/rhonabwy) library for the JWKs management.

Iddawc supports the following features:

- Loading openid-configuration endpoints and parsing the results
- Making `auth` requests using the given parameters (`client_id`, `client_secret`, `redirect_uri`, etc.) and parsing the result
- Making `token` requests using the given parameters (`code`, `client_id`, `client_secret`, `redirect_uri`, etc.) and parsing the result
- Making `userinfo`, `token introspection`, `token revocation` requests
- Parse responses, validate id_token
- Registering new clients using the `register` endpoint if any
- Sending signed and or encrypted requests in the `auth` and `token` endpoints

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

If a function is succesfull, it will return `I_OK` (0), otherwise an error code is returned.

## Log messages

Usually, a log message is displayed to explain more specifically what happened on error. The log manager used is [Yder](https://github.com/babelouest/yder). You can enable yder log messages on the console with the following command at the beginning of your program:

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
int i_load_openid_config(struct _i_session * i_session);
```

### Build and run auth request and parse results

The function `i_build_auth_url_get` can be used to build the full auth request with all the parameters in the url query for a GET request.

```C
/**
 * Builds the url to GET the auth endpoint
 * sets the result to parameter I_OPT_REDIRECT_TO
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_build_auth_url_get(struct _i_session * i_session);
```

The function `i_run_auth_request` builds the full auth requests and executes it. If the OAuth2 server answers with a succesfull response, the response will be parsed in the session properties. Otherwise, the rediect_to value and the errors if any will be parsed and made available in the session properties.

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

### Build and run token requests and parse results

If you need to execute a request in the token endpoint, to get a refresh token from a code or refresh a token for example, 

```C
/**
 * Executes a token request using the implicit endpoint
 * and sets the result values in the session variables
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_run_token_request(struct _i_session * i_session);
```

### Verify an id_token

If the auth or token endpoints returns an id_token, this one will be parsed, the signature will be verified and the content will be validated to make sure the id_token is valid. You can also manually validate an id_token using the dedicated function. The property `I_OPT_ID_TOKEN` and the publick key property must be set.

```C
/**
 * Validates the id_token signature and content if necessary
 * @param i_session: a reference to a struct _i_session *
 * @return I_OK on success, an error value on error
 */
int i_verify_id_token(struct _i_session * i_session);
```

### Load userinfo

If an access_token is available, you can make a request to the userinfo endpoint to get information about the user. The function `i_load_userinfo_custom` is a more advanced userinfo request where you can specify query or header parameters, to request more claims or the result a signed JWT.

```C
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

If available, you can register a new client. You may have to set a `I_OPT_ACCESS_TOKEN` property, depending on the server configuration. If `update_session` is true and the registration is successfull, the properties `I_OPT_CLIENT_ID` and `I_OPT_CLIENT_SECRET` will be set to the session, and the first `redirect_to` entry will be used as `I_OPT_REDIRECT_TO` value.

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
