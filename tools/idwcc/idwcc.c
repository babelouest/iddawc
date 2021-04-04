/**
 * 
 * idwcc: OAuth2/OIDC client program to test or validate OAuth2/OIDC AS
 * 
 * Copyright 2021 Nicolas Mora <mail@babelouest.org>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU GENERAL PUBLIC LICENSE
 * License as published by the Free Software Foundation;
 * version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <orcania.h>
#include <yder.h>
#include <ulfius.h>
#include <rhonabwy.h>
#include <iddawc.h>

#include "static_compressed_inmemory_website_callback.h"
#include "http_compression_callback.h"

#define _IDWCC_VERSION "0.9"
#define _DEFAULT_PORT 4398
#define PREFIX_STATIC "/"

#define CHUNK 0x4000

static void print_help(FILE * output, const char * command) {
  fprintf(output, "idwcc - OAuth2/OIDC client program to test or validate OAuth2/OIDC AS.\n");
  fprintf(output, "\nUsage: %s [OPTIONS]", command);
  fprintf(output, "\n");
  fprintf(output, "Version %s\n", _IDWCC_VERSION);
  fprintf(output, "\n");
  fprintf(output, "Copyright 2021 Nicolas Mora <mail@babelouest.org>\n");
  fprintf(output, "\n");
  fprintf(output, "This program is free software; you can redistribute it and/or\n");
  fprintf(output, "modify it under the terms of the GPL 3\n");
  fprintf(output, "\n");
  fprintf(output, "Command-line options:\n");
  fprintf(output, "\n");
  fprintf(output, "-p, --port <PORT_NUMBER>\n");
  fprintf(output, "\tTCP Port number to listen to, default %d\n", _DEFAULT_PORT);
  fprintf(output, "-f, --session-file <PATH>\n");
  fprintf(output, "\tLoad session file specified by <PATH>\n");
  fprintf(output, "-b, --bind-localhost [true|false]\n");
  fprintf(output, "\tBind to localhost only, default true\n");
  fprintf(output, "-h, --help\n");
  fprintf(output, "\tdisplay this help and exit\n");
  fprintf(output, "-v, --version\n");
  fprintf(output, "\toutput version information and exit\n");
}

/**
 * Streaming callback function to ease sending large files
 */
static ssize_t callback_static_file_uncompressed_stream(void * cls, uint64_t pos, char * buf, size_t max) {
  (void)(pos);
  if (cls != NULL) {
    return fread (buf, sizeof(char), max, (FILE *)cls);
  } else {
    return U_STREAM_END;
  }
}

/**
 * Cleanup FILE* structure when streaming is complete
 */
static void callback_static_file_uncompressed_stream_free(void * cls) {
  if (cls != NULL) {
    fclose((FILE *)cls);
  }
}

static int _i_load_session(struct _i_session * session, json_t * j_new_session) {
  int ret = 1;
  char * tmp;
  
  if (i_import_session_json_t(session, j_new_session) == I_OK) {
    ret = 1;
  } else {
    tmp = json_dumps(j_new_session, JSON_INDENT(2));
    y_log_message(Y_LOG_LEVEL_ERROR, "Error loading session\n%s", tmp);
    ret = 0;
    o_free(tmp);
  }
  return ret;
}

static int _i_load_session_file(struct _i_session * session, const char * file) {
  json_t * j_new_session = json_load_file(file, JSON_DECODE_ANY, NULL);
  int ret;
  
  ret = _i_load_session(session, j_new_session);
  json_decref(j_new_session);
  
  return ret;
}

static int callback_get_session(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _i_session * session = (struct _i_session *)user_data;
  json_t * j_session = i_export_session_json_t(session);
  
  ulfius_set_response_properties(response, U_OPT_STATUS, 200, U_OPT_JSON_BODY, j_session, U_OPT_NONE);
  json_decref(j_session);
  return U_CALLBACK_CONTINUE;
}

static int callback_save_session(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _i_session * session = (struct _i_session *)user_data;
  json_t * j_session = ulfius_get_json_body_request(request, NULL), * j_return;
  
  if (j_session != NULL) {
    if (json_object_size(j_session)) {
      if (i_import_session_json_t(session, j_session) != I_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "Session invalid");
        j_return = json_pack("{ss}", "error", "Session invalid");
        ulfius_set_json_body_response(response, 400, j_return);
        json_decref(j_return);
      }
    } else {
      i_clean_session(session);
      i_init_session(session);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "No session");
    j_return = json_pack("{ss}", "error", "No session");
    ulfius_set_json_body_response(response, 400, j_return);
    json_decref(j_return);
  }
  json_decref(j_session);
  return U_CALLBACK_CONTINUE;
}

static int callback_generate(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _i_session * session = (struct _i_session *)user_data;
  
  if (0 == o_strcmp("nonce", u_map_get(request->map_post_body, "property"))) {
    i_set_int_parameter(session, I_OPT_NONCE_GENERATE, 32);
  } else if (0 == o_strcmp("state", u_map_get(request->map_post_body, "property"))) {
    i_set_int_parameter(session, I_OPT_STATE_GENERATE, 16);
  } else if (0 == o_strcmp("jti", u_map_get(request->map_post_body, "property"))) {
    i_set_int_parameter(session, I_OPT_TOKEN_JTI_GENERATE, 16);
  } else if (0 == o_strcmp("pkce", u_map_get(request->map_post_body, "property"))) {
    i_set_int_parameter(session, I_OPT_PKCE_CODE_VERIFIER_GENERATE, 43);
  }
  return U_CALLBACK_CONTINUE;
}

static int callback_run_auth(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _i_session * session = (struct _i_session *)user_data;
  int ret;
  json_t * j_return;
  
  if (i_get_str_parameter(session, I_OPT_NONCE) == NULL) {
    i_set_int_parameter(session, I_OPT_NONCE_GENERATE, 32);
  }
  if (session->token_method & (I_TOKEN_AUTH_METHOD_JWT_SIGN_SECRET|I_TOKEN_AUTH_METHOD_JWT_SIGN_PRIVKEY) && !o_strlen(i_get_str_parameter(session, I_OPT_TOKEN_JTI))) {
    i_set_int_parameter(session, I_OPT_TOKEN_JTI_GENERATE, 16);
  }
  if (0 == o_strcmp("true", u_map_get(request->map_post_body, "use_par"))) {
    if ((ret = i_run_par_request(session)) == I_OK) {
      if ((ret = i_build_auth_url_get(session)) == I_OK) {
        j_return = json_pack("{ss}", "url", i_get_str_parameter(session, I_OPT_REDIRECT_TO));
        ulfius_set_json_body_response(response, 200, j_return);
        json_decref(j_return);
      } else if (ret == I_ERROR_PARAM) {
        j_return = json_pack("{ss? ss? ss?}", "error", i_get_str_parameter(session, I_OPT_ERROR), "error_description", i_get_str_parameter(session, I_OPT_ERROR_DESCRIPTION), "error_uri", i_get_str_parameter(session, I_OPT_ERROR_URI));
        ulfius_set_json_body_response(response, 400, j_return);
        json_decref(j_return);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "Error i_build_auth_url_get");
        response->status = 500;
      }
    } else if (ret == I_ERROR_PARAM) {
      j_return = json_pack("{ss? ss? ss?}", "error", i_get_str_parameter(session, I_OPT_ERROR), "error_description", i_get_str_parameter(session, I_OPT_ERROR_DESCRIPTION), "error_uri", i_get_str_parameter(session, I_OPT_ERROR_URI));
      ulfius_set_json_body_response(response, 400, j_return);
      json_decref(j_return);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error i_build_auth_url_get");
      response->status = 500;
    }
  } else if (session->auth_method & I_AUTH_METHOD_POST) {
    if ((ret = i_run_auth_request(session)) == I_OK) {
      j_return = json_pack("{ss}", "url", i_get_str_parameter(session, I_OPT_REDIRECT_TO));
      ulfius_set_json_body_response(response, 200, j_return);
      json_decref(j_return);
    } else if (ret == I_ERROR_PARAM) {
      j_return = json_pack("{ss? ss? ss?}", "error", i_get_str_parameter(session, I_OPT_ERROR), "error_description", i_get_str_parameter(session, I_OPT_ERROR_DESCRIPTION), "error_uri", i_get_str_parameter(session, I_OPT_ERROR_URI));
      ulfius_set_json_body_response(response, 400, j_return);
      json_decref(j_return);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error i_build_auth_url_get");
      response->status = 500;
    }
  } else if (session->auth_method & I_AUTH_METHOD_GET) {
    if ((ret = i_build_auth_url_get(session)) == I_OK) {
      j_return = json_pack("{ss}", "url", i_get_str_parameter(session, I_OPT_REDIRECT_TO));
      ulfius_set_json_body_response(response, 200, j_return);
      json_decref(j_return);
    } else if (ret == I_ERROR_PARAM) {
      j_return = json_pack("{ss? ss? ss?}", "error", i_get_str_parameter(session, I_OPT_ERROR), "error_description", i_get_str_parameter(session, I_OPT_ERROR_DESCRIPTION), "error_uri", i_get_str_parameter(session, I_OPT_ERROR_URI));
      ulfius_set_json_body_response(response, 400, j_return);
      json_decref(j_return);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error i_build_auth_url_get");
      response->status = 500;
    }
  }
  return U_CALLBACK_CONTINUE;
}

static int callback_run_token(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _i_session * session = (struct _i_session *)user_data;
  int ret;
  json_t * j_return;
  
  if (session->token_method & (I_TOKEN_AUTH_METHOD_JWT_SIGN_SECRET|I_TOKEN_AUTH_METHOD_JWT_SIGN_PRIVKEY) && !o_strlen(i_get_str_parameter(session, I_OPT_TOKEN_JTI))) {
    i_set_int_parameter(session, I_OPT_TOKEN_JTI_GENERATE, 16);
  }
  if ((ret = i_run_token_request(session)) == I_ERROR_PARAM) {
    j_return = json_pack("{ss? ss? ss?}", "error", i_get_str_parameter(session, I_OPT_ERROR), "error_description", i_get_str_parameter(session, I_OPT_ERROR_DESCRIPTION), "error_uri", i_get_str_parameter(session, I_OPT_ERROR_URI));
    ulfius_set_json_body_response(response, 400, j_return);
    json_decref(j_return);
  } else if (ret == I_ERROR_UNAUTHORIZED) {
    j_return = json_pack("{ss? ss? ss?}", "error", i_get_str_parameter(session, I_OPT_ERROR), "error_description", i_get_str_parameter(session, I_OPT_ERROR_DESCRIPTION), "error_uri", i_get_str_parameter(session, I_OPT_ERROR_URI));
    ulfius_set_json_body_response(response, 403, j_return);
    json_decref(j_return);
  } else if (ret != I_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error i_run_token_request");
    response->status = 500;
  }
  return U_CALLBACK_CONTINUE;
}

static int callback_run_device_auth(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _i_session * session = (struct _i_session *)user_data;
  int ret;
  json_t * j_return;
  
  if (session->token_method & (I_TOKEN_AUTH_METHOD_JWT_SIGN_SECRET|I_TOKEN_AUTH_METHOD_JWT_SIGN_PRIVKEY) && !o_strlen(i_get_str_parameter(session, I_OPT_TOKEN_JTI))) {
    i_set_int_parameter(session, I_OPT_TOKEN_JTI_GENERATE, 16);
  }
  if ((ret = i_run_device_auth_request(session)) == I_ERROR_PARAM) {
    j_return = json_pack("{ss? ss? ss?}", "error", i_get_str_parameter(session, I_OPT_ERROR), "error_description", i_get_str_parameter(session, I_OPT_ERROR_DESCRIPTION), "error_uri", i_get_str_parameter(session, I_OPT_ERROR_URI));
    ulfius_set_json_body_response(response, 400, j_return);
    json_decref(j_return);
  } else if (ret == I_ERROR_UNAUTHORIZED) {
    j_return = json_pack("{ss? ss? ss?}", "error", i_get_str_parameter(session, I_OPT_ERROR), "error_description", i_get_str_parameter(session, I_OPT_ERROR_DESCRIPTION), "error_uri", i_get_str_parameter(session, I_OPT_ERROR_URI));
    ulfius_set_json_body_response(response, 403, j_return);
    json_decref(j_return);
  } else if (ret != I_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error i_run_device_auth_request");
    response->status = 500;
  }
  return U_CALLBACK_CONTINUE;
}

static int callback_revoke_token(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _i_session * session = (struct _i_session *)user_data;
  int ret, auth = I_INTROSPECT_REVOKE_AUTH_NONE;
  char * save_at = o_strdup(i_get_str_parameter(session, I_OPT_ACCESS_TOKEN));
  json_t * j_return;
  
  if (session->use_dpop) {
    i_set_int_parameter(session, I_OPT_TOKEN_JTI_GENERATE, 16);
  }
  if (0 == o_strcmp("client", u_map_get(request->map_post_body, "authentication"))) {
    auth = I_INTROSPECT_REVOKE_AUTH_CLIENT_TARGET;
  } else if (0 == o_strcmp("access_token", u_map_get(request->map_post_body, "authentication"))) {
    auth = I_INTROSPECT_REVOKE_AUTH_ACCESS_TOKEN;
    i_set_str_parameter(session, I_OPT_ACCESS_TOKEN, u_map_get(request->map_post_body, "access_token"));
  }
  if ((ret = i_revoke_token(session, auth)) == I_ERROR_PARAM) {
    j_return = json_pack("{ss? ss? ss?}", "error", i_get_str_parameter(session, I_OPT_ERROR), "error_description", i_get_str_parameter(session, I_OPT_ERROR_DESCRIPTION), "error_uri", i_get_str_parameter(session, I_OPT_ERROR_URI));
    ulfius_set_json_body_response(response, 400, j_return);
    json_decref(j_return);
  } else if (ret == I_ERROR_UNAUTHORIZED) {
    j_return = json_pack("{ss? ss? ss?}", "error", i_get_str_parameter(session, I_OPT_ERROR), "error_description", i_get_str_parameter(session, I_OPT_ERROR_DESCRIPTION), "error_uri", i_get_str_parameter(session, I_OPT_ERROR_URI));
    ulfius_set_json_body_response(response, 403, j_return);
    json_decref(j_return);
  } else if (ret != I_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error i_revoke_token");
    response->status = 500;
  }
  i_set_str_parameter(session, I_OPT_ACCESS_TOKEN, save_at);
  o_free(save_at);
  return U_CALLBACK_CONTINUE;
}

static int callback_introspect_token(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _i_session * session = (struct _i_session *)user_data;
  int ret, auth = I_INTROSPECT_REVOKE_AUTH_NONE;
  json_t * j_result = NULL, * j_return;
  char * save_at = o_strdup(i_get_str_parameter(session, I_OPT_ACCESS_TOKEN));
  
  if (session->use_dpop) {
    i_set_int_parameter(session, I_OPT_TOKEN_JTI_GENERATE, 16);
  }
  if (0 == o_strcmp("client", u_map_get(request->map_post_body, "authentication"))) {
    auth = I_INTROSPECT_REVOKE_AUTH_CLIENT_TARGET;
  } else if (0 == o_strcmp("access_token", u_map_get(request->map_post_body, "authentication"))) {
    auth = I_INTROSPECT_REVOKE_AUTH_ACCESS_TOKEN;
    i_set_str_parameter(session, I_OPT_ACCESS_TOKEN, u_map_get(request->map_post_body, "access_token"));
  }
  if ((ret = i_get_token_introspection(session, &j_result, auth, 0)) == I_OK) {
    ulfius_set_json_body_response(response, 200, j_result);
  } else if (ret == I_ERROR_PARAM) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error params");
    j_return = json_pack("{ss? ss? ss?}", "error", i_get_str_parameter(session, I_OPT_ERROR), "error_description", i_get_str_parameter(session, I_OPT_ERROR_DESCRIPTION), "error_uri", i_get_str_parameter(session, I_OPT_ERROR_URI));
    ulfius_set_json_body_response(response, 400, j_return);
    json_decref(j_return);
  } else if (ret == I_ERROR_UNAUTHORIZED) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error unauthorized");
    j_return = json_pack("{ss? ss? ss?}", "error", i_get_str_parameter(session, I_OPT_ERROR), "error_description", i_get_str_parameter(session, I_OPT_ERROR_DESCRIPTION), "error_uri", i_get_str_parameter(session, I_OPT_ERROR_URI));
    ulfius_set_json_body_response(response, 403, j_return);
    json_decref(j_return);
  } else if (ret != I_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error i_get_token_introspection");
    response->status = 500;
  }
  json_decref(j_result);
  i_set_str_parameter(session, I_OPT_ACCESS_TOKEN, save_at);
  o_free(save_at);
  return U_CALLBACK_CONTINUE;
}

static int callback_redirect_uri(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _i_session * session = (struct _i_session *)user_data;
  size_t length;
  FILE * f;
  
  if (u_map_get(request->map_url, "code") != NULL) {
    i_set_str_parameter(session, I_OPT_CODE, u_map_get(request->map_url, "code"));
    u_map_put(response->map_header, "Location", "/");
    response->status = 302;
  } else {
    if (access("static/callback.html", F_OK) != -1) {
      f = fopen ("static/callback.html", "rb");
      if (f) {
        u_map_put(response->map_header, "Content-Type", "text/html");
        fseek (f, 0, SEEK_END);
        length = ftell (f);
        fseek (f, 0, SEEK_SET);
        if (ulfius_set_stream_response(response, 200, callback_static_file_uncompressed_stream, callback_static_file_uncompressed_stream_free, length, CHUNK, f) != U_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_redirect_uri File Server - Error ulfius_set_stream_response");
        }
      }
    } else {
      response->status = 404;
    }
  }
  return U_CALLBACK_CONTINUE;
}

static int callback_parse_redirect_to(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _i_session * session = (struct _i_session *)user_data;
  int ret;
  
  if (u_map_get(request->map_post_body, "redirectTo") != NULL) {
    i_set_str_parameter(session, I_OPT_REDIRECT_TO, u_map_get(request->map_post_body, "redirectTo"));
    if ((ret = i_parse_redirect_to(session)) != I_OK && ret != I_ERROR) {
      response->status = 400;
    } else if (ret == I_ERROR) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error i_parse_redirect_to");
      response->status = 500;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error invalid redirectTo parameter");
    response->status = 400;
  }
  return U_CALLBACK_CONTINUE;
}

static int callback_config_download(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _i_session * session = (struct _i_session *)user_data;
  int ret;
  
  if ((ret = i_get_openid_config(session)) == I_ERROR_PARAM) {
    ulfius_set_string_body_response(response, 400, "Invalid configuration endpoint");
  } else if (ret != I_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error i_get_openid_config %d", ret);
    response->status = 500;
  }
  return U_CALLBACK_CONTINUE;
}

static int callback_userinfo_download(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _i_session * session = (struct _i_session *)user_data;
  int ret;
  
  if (session->use_dpop) {
    i_set_int_parameter(session, I_OPT_TOKEN_JTI_GENERATE, 16);
  }
  if ((ret = i_get_userinfo(session, 0)) == I_ERROR_PARAM) {
    response->status = 400;
  } else if (ret == I_ERROR_UNAUTHORIZED) {
    response->status = 403;
  } else if (ret != I_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error i_get_userinfo");
    response->status = 500;
  }
  return U_CALLBACK_CONTINUE;
}

static int callback_client_register(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _i_session * session = (struct _i_session *)user_data;
  int ret;
  json_t * j_result = NULL, * j_return, * j_parameters = json_loads(u_map_get(request->map_post_body, "parameters"), JSON_DECODE_ANY, NULL);
  char * save_at = o_strdup(i_get_str_parameter(session, I_OPT_ACCESS_TOKEN));
  
  if (0 == o_strcmp("access_token", u_map_get(request->map_post_body, "authentication"))) {
    i_set_str_parameter(session, I_OPT_ACCESS_TOKEN, u_map_get(request->map_post_body, "access_token"));
  }
  if ((ret = i_register_client(session, j_parameters, 0==o_strcmp("1", u_map_get(request->map_post_body, "update")), &j_result)) == I_OK) {
    ulfius_set_json_body_response(response, 200, j_result);
  } else if (ret == I_ERROR_PARAM) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error params");
    j_return = json_pack("{ss? ss? ss?}", "error", i_get_str_parameter(session, I_OPT_ERROR), "error_description", i_get_str_parameter(session, I_OPT_ERROR_DESCRIPTION), "error_uri", i_get_str_parameter(session, I_OPT_ERROR_URI));
    ulfius_set_json_body_response(response, 400, j_return);
    json_decref(j_return);
  } else if (ret == I_ERROR_UNAUTHORIZED) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error unauthorized");
    j_return = json_pack("{ss? ss? ss?}", "error", i_get_str_parameter(session, I_OPT_ERROR), "error_description", i_get_str_parameter(session, I_OPT_ERROR_DESCRIPTION), "error_uri", i_get_str_parameter(session, I_OPT_ERROR_URI));
    ulfius_set_json_body_response(response, 403, j_return);
    json_decref(j_return);
  } else if (ret != I_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error i_register_client");
    response->status = 500;
  }
  json_decref(j_result);
  json_decref(j_parameters);
  i_set_str_parameter(session, I_OPT_ACCESS_TOKEN, save_at);
  o_free(save_at);
  return U_CALLBACK_CONTINUE;
}

static int callback_client_manage_registration(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _i_session * session = (struct _i_session *)user_data;
  int ret;
  json_t * j_result = NULL, * j_return, * j_parameters = json_loads(u_map_get(request->map_post_body, "parameters"), JSON_DECODE_ANY, NULL);
  char * save_at = o_strdup(i_get_str_parameter(session, I_OPT_ACCESS_TOKEN));
  
  i_set_str_parameter(session, I_OPT_ACCESS_TOKEN, u_map_get(request->map_post_body, "access_token"));
  if ((ret = i_manage_registration_client(session, j_parameters, 0==o_strcmp("1", u_map_get(request->map_post_body, "update")), &j_result)) == I_OK) {
    ulfius_set_json_body_response(response, 200, j_result);
  } else if (ret == I_ERROR_PARAM) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error params");
    j_return = json_pack("{ss? ss? ss?}", "error", i_get_str_parameter(session, I_OPT_ERROR), "error_description", i_get_str_parameter(session, I_OPT_ERROR_DESCRIPTION), "error_uri", i_get_str_parameter(session, I_OPT_ERROR_URI));
    ulfius_set_json_body_response(response, 400, j_return);
    json_decref(j_return);
  } else if (ret == I_ERROR_UNAUTHORIZED) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error unauthorized");
    j_return = json_pack("{ss? ss? ss?}", "error", i_get_str_parameter(session, I_OPT_ERROR), "error_description", i_get_str_parameter(session, I_OPT_ERROR_DESCRIPTION), "error_uri", i_get_str_parameter(session, I_OPT_ERROR_URI));
    ulfius_set_json_body_response(response, 403, j_return);
    json_decref(j_return);
  } else if (ret != I_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error i_manage_registration_client");
    response->status = 500;
  }
  json_decref(j_result);
  json_decref(j_parameters);
  i_set_str_parameter(session, I_OPT_ACCESS_TOKEN, save_at);
  o_free(save_at);
  return U_CALLBACK_CONTINUE;
}

static int callback_client_get_registration(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _i_session * session = (struct _i_session *)user_data;
  int ret;
  json_t * j_result = NULL, * j_return;
  char * save_at = o_strdup(i_get_str_parameter(session, I_OPT_ACCESS_TOKEN));
  
  i_set_str_parameter(session, I_OPT_ACCESS_TOKEN, u_map_get(request->map_url, "access_token"));
  if ((ret = i_get_registration_client(session, &j_result)) == I_OK) {
    ulfius_set_json_body_response(response, 200, j_result);
  } else if (ret == I_ERROR_PARAM) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error params");
    j_return = json_pack("{ss? ss? ss?}", "error", i_get_str_parameter(session, I_OPT_ERROR), "error_description", i_get_str_parameter(session, I_OPT_ERROR_DESCRIPTION), "error_uri", i_get_str_parameter(session, I_OPT_ERROR_URI));
    ulfius_set_json_body_response(response, 400, j_return);
    json_decref(j_return);
  } else if (ret == I_ERROR_UNAUTHORIZED) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error unauthorized");
    j_return = json_pack("{ss? ss? ss?}", "error", i_get_str_parameter(session, I_OPT_ERROR), "error_description", i_get_str_parameter(session, I_OPT_ERROR_DESCRIPTION), "error_uri", i_get_str_parameter(session, I_OPT_ERROR_URI));
    ulfius_set_json_body_response(response, 403, j_return);
    json_decref(j_return);
  } else if (ret != I_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error i_get_registration_client");
    response->status = 500;
  }
  json_decref(j_result);
  i_set_str_parameter(session, I_OPT_ACCESS_TOKEN, save_at);
  o_free(save_at);
  return U_CALLBACK_CONTINUE;
}

static int callback_access_token_verify(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _i_session * session = (struct _i_session *)user_data;
  json_t * j_return;
  int ret;
  
  if ((ret = i_verify_jwt_access_token(session)) == I_ERROR_PARAM) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error params");
    j_return = json_pack("{ss? ss? ss?}", "error", i_get_str_parameter(session, I_OPT_ERROR), "error_description", i_get_str_parameter(session, I_OPT_ERROR_DESCRIPTION), "error_uri", i_get_str_parameter(session, I_OPT_ERROR_URI));
    ulfius_set_json_body_response(response, 400, j_return);
    json_decref(j_return);
  } else if (ret == I_ERROR) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error i_verify_jwt_access_token");
    response->status = 500;
  }
  return U_CALLBACK_CONTINUE;
}

static int callback_resource_request(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _i_session * session = (struct _i_session *)user_data;
  json_t * j_params = ulfius_get_json_body_request(request, NULL), * j_return, * j_element = NULL, * j_response = NULL;
  const char * key = NULL, ** keys = NULL;
  int ret;
  size_t i;
  struct _u_request req;
  struct _u_response resp;
  
  if (j_params != NULL) {
    ulfius_init_request(&req);
    ulfius_init_response(&resp);
    
    ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, json_string_value(json_object_get(j_params, "method")),
                                        U_OPT_HTTP_URL, json_string_value(json_object_get(j_params, "url")),
                                        U_OPT_NONE);
    if (json_object_get(j_params, "headers") != NULL) {
      json_object_foreach(json_object_get(j_params, "headers"), key, j_element) {
        ulfius_set_request_properties(&req, U_OPT_HEADER_PARAMETER, key, json_string_value(j_element), U_OPT_NONE);
      }
    }
    if (json_object_get(j_params, "body") != NULL) {
      if (0 == o_strcmp("JSON", json_string_value(json_object_get(j_params, "bodyType")))) {
        ulfius_set_json_body_request(&req, json_object_get(j_params, "body"));
      } else {
        json_object_foreach(json_object_get(j_params, "body"), key, j_element) {
          ulfius_set_request_properties(&req, U_OPT_POST_BODY_PARAMETER, key, json_string_value(j_element), U_OPT_NONE);
        }
      }
    }
    if ((ret = i_perform_resource_service_request(session, &req, &resp, 0, I_BEARER_TYPE_HEADER, session->use_dpop, 0)) == I_OK) {
      j_return = json_pack("{sis{}}", "status", resp.status, "headers");
      keys = u_map_enum_keys(resp.map_header);
      for (i=0; keys[i]!=NULL; i++) {
        json_object_set_new(json_object_get(j_return, "headers"), keys[i], json_string(u_map_get(resp.map_header, keys[i])));
      }
      if ((j_response = ulfius_get_json_body_response(&resp, NULL)) != NULL) {
        json_object_set_new(j_return, "bodyType", json_string("JSON"));
        json_object_set_new(j_return, "body", j_response);
        json_decref(j_response);
      } else if (resp.binary_body_length) {
        json_object_set_new(j_return, "bodyType", json_string("URL Encode"));
        json_object_set_new(j_return, "body", json_stringn((const char *)resp.binary_body, resp.binary_body_length));
      }
      ulfius_set_json_body_response(response, 200, j_return);
      json_decref(j_return);
    } else if (ret == I_ERROR_PARAM) {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error params");
      response->status = 400;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error i_perform_resource_service_request");
      response->status = 500;
    }
    ulfius_clean_request(&req);
    ulfius_clean_response(&resp);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error params");
    response->status = 400;
  }
  json_decref(j_params);
  return U_CALLBACK_CONTINUE;
}

static int callback_default(const struct _u_request * request, struct _u_response * response, void * user_data) {
  response->status = 404;
  return U_CALLBACK_CONTINUE;
}

static int callback_static_close(const struct _u_request * request, struct _u_response * response, void * user_data) {
  if (!request->callback_position) {
    response->status = 404;
  }
  return U_CALLBACK_CONTINUE;
}

int main(int argc, char ** argv) {
  struct _u_instance instance;
  unsigned int port = _DEFAULT_PORT;
  unsigned long int s_port;
  char * endptr = NULL;
  int next_option, exit_loop = 0, ret = 0, bind_localhost = 1;
  struct _i_session session;
  struct _u_compressed_inmemory_website_config file_config;
  struct sockaddr_in bind_address;
  
  const char * short_options = "p:f:b:v::h";
  static const struct option long_options[]= {
    {"port", required_argument, NULL, 'p'},
    {"session-file", required_argument, NULL, 'f'},
    {"bind-localhost", required_argument, NULL, 'b'},
    {"version", no_argument, NULL, 'v'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
  };

  y_init_logs("Idwcc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Idwcc");
  i_init_session(&session);

  do {
    next_option = getopt_long(argc, argv, short_options, long_options, NULL);
    
    switch (next_option) {
      case 'p':
        s_port = strtoul(optarg, &endptr, 10);
        if (*endptr == '\0' && port < 65536) {
          port = (unsigned int)s_port;
        } else {
          print_help(stderr, argv[0]);
          exit_loop = 1;
          ret = 1;
        }
        break;
      case 'f':
        if (!_i_load_session_file(&session, optarg)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "Error loading session file");
          exit_loop = 1;
          ret = 1;
        }
        break;
      case 'b':
        if (0 == o_strcasecmp("no", optarg) || 0 == o_strcasecmp("false", optarg) || 0 == o_strcasecmp("0", optarg) || 0 == o_strcasecmp("hellno", optarg)) {
          bind_localhost = 0;
        }
        break;
      case 'v':
        fprintf(stdout, "%s %s\n", argv[0], _IDWCC_VERSION);
        fprintf(stdout, "Copyright 2021 Nicolas Mora <mail@babelouest.org>\n");
        fprintf(stdout, "This program is free software; you can redistribute it and/or\n");
        fprintf(stdout, "modify it under the terms of the GPL 3\n");
        exit_loop = 1;
        break;
      case 'h':
        print_help(stdout, argv[0]);
        exit_loop = 1;
        break;
      default:
        break;
    }
  } while (next_option != -1 && !exit_loop);

  if (!exit_loop) {
    if (bind_localhost) {
      bind_address.sin_family = AF_INET;
      bind_address.sin_port = htons(port);
      inet_aton("127.0.0.1", (struct in_addr *)&bind_address.sin_addr.s_addr);
    }

    if (ulfius_init_instance(&instance, port, bind_localhost?&bind_address:NULL, NULL) == U_OK) {
      if (u_init_compressed_inmemory_website_config(&file_config) == U_OK) {
        u_map_put(&file_config.mime_types, ".html", "text/html");
        u_map_put(&file_config.mime_types, ".css", "text/css");
        u_map_put(&file_config.mime_types, ".js", "application/javascript");
        u_map_put(&file_config.mime_types, ".png", "image/png");
        u_map_put(&file_config.mime_types, ".jpg", "image/jpeg");
        u_map_put(&file_config.mime_types, ".jpeg", "image/jpeg");
        u_map_put(&file_config.mime_types, ".ttf", "font/ttf");
        u_map_put(&file_config.mime_types, ".woff", "font/woff");
        u_map_put(&file_config.mime_types, ".woff2", "font/woff2");
        u_map_put(&file_config.mime_types, ".map", "application/octet-stream");
        u_map_put(&file_config.mime_types, ".json", "application/json");
        u_map_put(&file_config.mime_types, ".ico", "image/x-icon");
        u_map_put(&file_config.mime_types, "*", "application/octet-stream");
        file_config.files_path = "static";
        file_config.url_prefix = PREFIX_STATIC;
        file_config.allow_cache_compressed = 0;
        file_config.allow_gzip = 1;
        file_config.allow_deflate = 1;

        ulfius_add_endpoint_by_val(&instance, "GET", "/api", "/session", 0, &callback_get_session, &session);
        ulfius_add_endpoint_by_val(&instance, "POST", "/api", "/session", 0, &callback_save_session, &session);
        ulfius_add_endpoint_by_val(&instance, "POST", "/api", "/configDownload", 0, &callback_config_download, &session);
        ulfius_add_endpoint_by_val(&instance, "POST", "/api", "/userinfoDownload", 0, &callback_userinfo_download, &session);
        ulfius_add_endpoint_by_val(&instance, "POST", "/api", "/introspectDownload", 0, &callback_introspect_token, &session);
        ulfius_add_endpoint_by_val(&instance, "POST", "/api", "/accessTokenVerify", 0, &callback_access_token_verify, &session);
        ulfius_add_endpoint_by_val(&instance, "PUT", "/api", "/generate", 0, &callback_generate, &session);
        ulfius_add_endpoint_by_val(&instance, "PUT", "/api", "/auth", 0, &callback_run_auth, &session);
        ulfius_add_endpoint_by_val(&instance, "PUT", "/api", "/token", 0, &callback_run_token, &session);
        ulfius_add_endpoint_by_val(&instance, "PUT", "/api", "/device", 0, &callback_run_device_auth, &session);
        ulfius_add_endpoint_by_val(&instance, "PUT", "/api", "/revoke", 0, &callback_revoke_token, &session);
        ulfius_add_endpoint_by_val(&instance, "POST", "/api", "/register", 0, &callback_client_register, &session);
        ulfius_add_endpoint_by_val(&instance, "GET", "/api", "/register", 0, &callback_client_get_registration, &session);
        ulfius_add_endpoint_by_val(&instance, "PUT", "/api", "/register", 0, &callback_client_manage_registration, &session);
        ulfius_add_endpoint_by_val(&instance, "POST", "/api", "/resourceRequest", 0, &callback_resource_request, &session);
        ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/callback", 0, &callback_redirect_uri, &session);
        ulfius_add_endpoint_by_val(&instance, "POST", "/api", "/parseRedirectTo", 0, &callback_parse_redirect_to, &session);
        ulfius_add_endpoint_by_val(&instance, "*", "/api", "*", 1, &callback_http_compression, NULL);
        ulfius_add_endpoint_by_val(&instance, "GET", PREFIX_STATIC, "*", 0, &callback_static_compressed_inmemory_website, &file_config);
        ulfius_add_endpoint_by_val(&instance, "GET", PREFIX_STATIC, "*", 2, &callback_static_close, NULL);
        ulfius_set_default_endpoint(&instance, &callback_default, NULL);
        ulfius_start_framework(&instance);

        y_log_message(Y_LOG_LEVEL_INFO, "Start idwcc on port %u, url: http://localhost:%u/", port, port);
        y_log_message(Y_LOG_LEVEL_INFO, "Press <enter> to quit");
        getchar();
        ulfius_stop_framework(&instance);
        ulfius_clean_instance(&instance);
        u_clean_compressed_inmemory_website_config(&file_config);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "Error initializing file config");
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error initializing ulfius instance");
    }
  }
  i_clean_session(&session);
  y_close_logs();

  return ret;
}
