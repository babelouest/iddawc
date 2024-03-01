/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <jansson.h>
#include <check.h>
#include <yder.h>
#include <iddawc.h>

#define UNUSED(x) (void)(x)

#define TOKEN "accessTokenXyz1234"

const char client_id[] = "s6BhdRkqt3";
const char client_secret[] = "ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk";
const char register_pattern[] = "{\"client_id\": \"s6BhdRkqt3\",\"client_secret\":\"ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk\",\"client_secret_expires_at\": 1577858400,\"registration_access_token\":\"this.is.an.access.token.value.ffx83\",\"registration_client_uri\":\"https://server.example.com/connect/register?client_id=s6BhdRkqt3\",\"token_endpoint_auth_method\":\"client_secret_basic\",\"application_type\": \"web\",\"redirect_uris\":[],\"client_name\": \"My Example\",\"client_name#ja-Jpan-JP\":\"クライアント名\",\"logo_uri\": \"https://client.example.org/logo.png\",\"subject_type\": \"pairwise\",\"sector_identifier_uri\":\"https://other.example.net/file_of_redirect_uris.json\",\"jwks_uri\": \"https://client.example.org/my_public_keys.jwks\",\"userinfo_encrypted_response_alg\": \"RSA1_5\",\"userinfo_encrypted_response_enc\": \"A128CBC-HS256\",\"contacts\": [\"ve7jtb@example.org\", \"mary@example.org\"],\"request_uris\":[],\"frontchannel_logout_uri\": \"https://iddawc.tld/frontlogout\",\"frontchannel_logout_session_required\": true,\"backchannel_logout_uri\": \"https://iddawc.tld/backlogout\",\"backchannel_logout_session_required\": true}";
const char register_pattern_2[] = "{\"client_id\": \"s6BhdRkqt3\",\"client_secret\":\"ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk\",\"client_secret_expires_at\": 1577858400,\"registration_access_token\":\"this.is.an.access.token.value.ffx83\",\"registration_client_uri\":\"https://server.example.com/connect/register?client_id=s6BhdRkqt3\",\"token_endpoint_auth_method\":\"client_secret_basic\",\"application_type\": \"web\",\"redirect_uris\":[],\"client_name\": \"My Example\",\"client_name#ja-Jpan-JP\":\"クライアント名\",\"logo_uri\": \"https://client.example.org/logo.png\",\"subject_type\": \"pairwise\",\"sector_identifier_uri\":\"https://other.example.net/file_of_redirect_uris.json\",\"jwks_uri\": \"https://client.example.org/my_public_keys.jwks\",\"contacts\": [\"ve7jtb@example.org\", \"mary@example.org\"],\"request_uris\":[],\"frontchannel_logout_uri\": \"https://iddawc.tld/frontlogout\",\"frontchannel_logout_session_required\": true,\"backchannel_logout_uri\": \"https://iddawc.tld/backlogout\",\"backchannel_logout_session_required\": true}";
const char register_management_pattern[] = "{\"token_endpoint_auth_method\":\"client_secret_basic\",\"application_type\": \"web\",\"redirect_uris\":[],\"client_name\": \"My Example\",\"client_name#ja-Jpan-JP\":\"クライアント名\",\"logo_uri\": \"https://client.example.org/logo.png\",\"subject_type\": \"pairwise\",\"sector_identifier_uri\":\"https://other.example.net/file_of_redirect_uris.json\",\"jwks_uri\": \"https://client.example.org/my_public_keys.jwks\",\"userinfo_encrypted_response_alg\": \"RSA1_5\",\"userinfo_encrypted_response_enc\": \"A128CBC-HS256\",\"contacts\": [\"ve7jtb@example.org\", \"mary@example.org\"],\"request_uris\":[],\"frontchannel_logout_uri\": \"https://iddawc.tld/frontlogout\",\"frontchannel_logout_session_required\": true,\"backchannel_logout_uri\": \"https://iddawc.tld/backlogout\",\"backchannel_logout_session_required\": true}";

int callback_register (const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(user_data);
  if (0 == o_strcmp("Bearer "TOKEN, u_map_get(request->map_header, "Authorization"))) {
    json_t * j_parameters = ulfius_get_json_body_request(request, NULL);
    json_t * j_result = json_loads(register_pattern, JSON_DECODE_ANY, NULL);
    json_array_extend(json_object_get(j_result, "redirect_uris"), json_object_get(j_parameters, "redirect_uris"));
    ulfius_set_json_body_response(response, 200, j_result);
    json_decref(j_parameters);
    json_decref(j_result);
  }
  return U_CALLBACK_CONTINUE;
}

int callback_register_from_params (const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(user_data);
  if (0 == o_strcmp("Bearer "TOKEN, u_map_get(request->map_header, "Authorization"))) {
    json_t * j_parameters = ulfius_get_json_body_request(request, NULL);
    json_t * j_result = json_loads(register_pattern, JSON_DECODE_ANY, NULL);
    json_array_extend(json_object_get(j_result, "redirect_uris"), json_object_get(j_parameters, "redirect_uris"));
    json_object_set(j_result, "access_token_signing_alg", json_object_get(j_parameters, "access_token_signing_alg"));
    json_object_set(j_result, "access_token_encryption_alg", json_object_get(j_parameters, "access_token_encryption_alg"));
    json_object_set(j_result, "access_token_encryption_enc", json_object_get(j_parameters, "access_token_encryption_enc"));
    json_object_set(j_result, "backchannel_client_notification_endpoint", json_object_get(j_parameters, "backchannel_client_notification_endpoint"));
    json_object_set(j_result, "backchannel_token_delivery_mode", json_object_get(j_parameters, "backchannel_token_delivery_mode"));
    json_object_set(j_result, "frontchannel_logout_uri", json_object_get(j_parameters, "frontchannel_logout_uri"));
    json_object_set(j_result, "frontchannel_logout_session_required", json_object_get(j_parameters, "frontchannel_logout_session_required"));
    json_object_set(j_result, "backchannel_logout_uri", json_object_get(j_parameters, "backchannel_logout_uri"));
    json_object_set(j_result, "backchannel_logout_session_required", json_object_get(j_parameters, "backchannel_logout_session_required"));
    json_object_set(j_result, "post_logout_redirect_uri", json_object_get(j_parameters, "post_logout_redirect_uri"));
    ulfius_set_json_body_response(response, 200, j_result);
    json_decref(j_parameters);
    json_decref(j_result);
  }
  return U_CALLBACK_CONTINUE;
}

int callback_register_management (const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(user_data);
  if (0 == o_strcmp("Bearer "TOKEN, u_map_get(request->map_header, "Authorization"))) {
    json_t * j_parameters = ulfius_get_json_body_request(request, NULL);
    json_t * j_result = json_loads(register_management_pattern, JSON_DECODE_ANY, NULL);
    json_array_extend(json_object_get(j_result, "redirect_uris"), json_object_get(j_parameters, "redirect_uris"));
    ulfius_set_json_body_response(response, 200, j_result);
    json_decref(j_parameters);
    json_decref(j_result);
  }
  return U_CALLBACK_CONTINUE;
}

int callback_register_delete (const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(request);
  UNUSED(response);
  UNUSED(user_data);
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_iddawc_registration_invalid)
{
  struct _i_session i_session;
  json_t * j_parameters = json_pack("{s[s]}", "redirect_uris", "https://www.example.com/callback");
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_register_client(&i_session, j_parameters, 0, NULL), I_ERROR_PARAM);
  
  ck_assert_int_eq(i_set_str_parameter(&i_session, I_OPT_REGISTRATION_ENDPOINT, "http://localhost:8080/register"), I_OK);
  ck_assert_int_eq(i_register_client(&i_session, NULL, 0, NULL), I_ERROR_PARAM);
  json_decref(j_parameters);
  j_parameters = json_pack("{s[s]}", "error", "https://www.example.com/callback");
  ck_assert_int_eq(i_register_client(&i_session, j_parameters, 0, NULL), I_ERROR_PARAM);
  json_decref(j_parameters);
  
  i_clean_session(&i_session);
  
}
END_TEST

START_TEST(test_iddawc_registration_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  json_t * j_expected = NULL, * j_result = NULL, * j_parameters = json_pack("{s[ss]}", "redirect_uris", "https://www.example.com/callback", "https://www.example.com/callback2");
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/register", 0, &callback_register, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_REGISTRATION_ENDPOINT, "http://localhost:8080/register",
                                                  I_OPT_ACCESS_TOKEN, TOKEN,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_register_client(&i_session, j_parameters, 1, &j_result), I_OK);
  j_expected = json_loads(register_pattern, JSON_DECODE_ANY, NULL);
  json_array_append_new(json_object_get(j_expected, "redirect_uris"), json_string("https://www.example.com/callback"));
  json_array_append_new(json_object_get(j_expected, "redirect_uris"), json_string("https://www.example.com/callback2"));
  ck_assert_int_eq(1, json_equal(j_expected, j_result));
  ck_assert_str_eq(client_id, i_get_str_parameter(&i_session, I_OPT_CLIENT_ID));
  ck_assert_str_eq("https://server.example.com/connect/register?client_id=s6BhdRkqt3", i_get_str_parameter(&i_session, I_OPT_REGISTRATION_CLIENT_URI));
  ck_assert_str_eq("this.is.an.access.token.value.ffx83", i_get_str_parameter(&i_session, I_OPT_ACCESS_TOKEN));
  ck_assert_str_eq(client_secret, i_get_str_parameter(&i_session, I_OPT_CLIENT_SECRET));
  ck_assert_str_eq("https://www.example.com/callback", i_get_str_parameter(&i_session, I_OPT_REDIRECT_URI));
  json_decref(j_result);
  json_decref(j_expected);
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                  I_OPT_REGISTRATION_ENDPOINT, "http://localhost:8080/register",
                                                  I_OPT_ACCESS_TOKEN, TOKEN,
                                                  I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_register_client(&i_session, j_parameters, 0, &j_result), I_OK);
  j_expected = json_loads(register_pattern, JSON_DECODE_ANY, NULL);
  json_array_append_new(json_object_get(j_expected, "redirect_uris"), json_string("https://www.example.com/callback"));
  json_array_append_new(json_object_get(j_expected, "redirect_uris"), json_string("https://www.example.com/callback2"));
  ck_assert_int_eq(1, json_equal(j_expected, j_result));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_CLIENT_ID));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_CLIENT_SECRET));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_REGISTRATION_CLIENT_URI));
  json_decref(j_result);
  json_decref(j_expected);
  i_clean_session(&i_session);
  
  json_decref(j_parameters);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_registration_from_params_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  json_t * j_expected = NULL, * j_result = NULL;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8080, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "/register", 0, &callback_register_from_params, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_REDIRECT_URI, "https://www.example.com/callback",
                                                    I_OPT_REGISTRATION_ENDPOINT, "http://localhost:8080/register",
                                                    I_OPT_ACCESS_TOKEN, TOKEN,
                                                    I_OPT_CIBA_MODE, I_CIBA_MODE_PING,
                                                    I_OPT_CIBA_CLIENT_NOTIFICATION_ENDPOINT, "https://www.example.com/ciba",
                                                    I_OPT_ACCESS_TOKEN_SIGNING_ALG, "RS512",
                                                    I_OPT_ACCESS_TOKEN_ENCRYPTION_ALG, "RSA1_5",
                                                    I_OPT_ACCESS_TOKEN_ENCRYPTION_ENC, "A128GCM",
                                                    I_OPT_FRONTCHANNEL_LOGOUT_URI, "https://iddawc.tld/frontlogout",
                                                    I_OPT_FRONTCHANNEL_LOGOUT_SESSION_REQUIRED, 1,
                                                    I_OPT_BACKCHANNEL_LOGOUT_URI, "https://iddawc.tld/backlogout",
                                                    I_OPT_BACKCHANNEL_LOGOUT_SESSION_REQUIRED, 1,
                                                    I_OPT_POST_LOGOUT_REDIRECT_URI, "https://iddawc.tld/postlogout",
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_register_client(&i_session, NULL, 1, &j_result), I_OK);
  j_expected = json_loads(register_pattern, JSON_DECODE_ANY, NULL);
  json_array_append_new(json_object_get(j_expected, "redirect_uris"), json_string("https://www.example.com/callback"));
  json_object_set_new(j_expected, "access_token_signing_alg", json_string("RS512"));
  json_object_set_new(j_expected, "access_token_encryption_alg", json_string("RSA1_5"));
  json_object_set_new(j_expected, "access_token_encryption_enc", json_string("A128GCM"));
  json_object_set_new(j_expected, "backchannel_token_delivery_mode", json_string("ping"));
  json_object_set_new(j_expected, "backchannel_client_notification_endpoint", json_string("https://www.example.com/ciba"));
  json_object_set_new(j_expected, "frontchannel_logout_uri", json_string("https://iddawc.tld/frontlogout"));
  json_object_set_new(j_expected, "frontchannel_logout_session_required", json_true());
  json_object_set_new(j_expected, "backchannel_logout_uri", json_string("https://iddawc.tld/backlogout"));
  json_object_set_new(j_expected, "backchannel_logout_session_required", json_true());
  json_object_set_new(j_expected, "post_logout_redirect_uri", json_string("https://iddawc.tld/postlogout"));
  ck_assert_int_eq(1, json_equal(j_expected, j_result));
  ck_assert_str_eq(client_id, i_get_str_parameter(&i_session, I_OPT_CLIENT_ID));
  ck_assert_str_eq(client_secret, i_get_str_parameter(&i_session, I_OPT_CLIENT_SECRET));
  ck_assert_str_eq("https://www.example.com/callback", i_get_str_parameter(&i_session, I_OPT_REDIRECT_URI));
  json_decref(j_result);
  json_decref(j_expected);
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_REDIRECT_URI, "https://www.example.com/callback",
                                                    I_OPT_REGISTRATION_ENDPOINT, "http://localhost:8080/register",
                                                    I_OPT_ACCESS_TOKEN, TOKEN,
                                                    I_OPT_CIBA_MODE, I_CIBA_MODE_PING,
                                                    I_OPT_CIBA_CLIENT_NOTIFICATION_ENDPOINT, "https://www.example.com/ciba",
                                                    I_OPT_ACCESS_TOKEN_SIGNING_ALG, "RS512",
                                                    I_OPT_ACCESS_TOKEN_ENCRYPTION_ALG, "RSA1_5",
                                                    I_OPT_ACCESS_TOKEN_ENCRYPTION_ENC, "A128GCM",
                                                    I_OPT_FRONTCHANNEL_LOGOUT_URI, "https://iddawc.tld/frontlogout",
                                                    I_OPT_FRONTCHANNEL_LOGOUT_SESSION_REQUIRED, 1,
                                                    I_OPT_BACKCHANNEL_LOGOUT_URI, "https://iddawc.tld/backlogout",
                                                    I_OPT_BACKCHANNEL_LOGOUT_SESSION_REQUIRED, 1,
                                                    I_OPT_POST_LOGOUT_REDIRECT_URI, "https://iddawc.tld/postlogout",
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_register_client(&i_session, NULL, 0, &j_result), I_OK);
  j_expected = json_loads(register_pattern, JSON_DECODE_ANY, NULL);
  json_array_append_new(json_object_get(j_expected, "redirect_uris"), json_string("https://www.example.com/callback"));
  json_object_set_new(j_expected, "access_token_signing_alg", json_string("RS512"));
  json_object_set_new(j_expected, "access_token_encryption_alg", json_string("RSA1_5"));
  json_object_set_new(j_expected, "access_token_encryption_enc", json_string("A128GCM"));
  json_object_set_new(j_expected, "backchannel_token_delivery_mode", json_string("ping"));
  json_object_set_new(j_expected, "backchannel_client_notification_endpoint", json_string("https://www.example.com/ciba"));
  json_object_set_new(j_expected, "frontchannel_logout_uri", json_string("https://iddawc.tld/frontlogout"));
  json_object_set_new(j_expected, "frontchannel_logout_session_required", json_true());
  json_object_set_new(j_expected, "backchannel_logout_uri", json_string("https://iddawc.tld/backlogout"));
  json_object_set_new(j_expected, "backchannel_logout_session_required", json_true());
  json_object_set_new(j_expected, "post_logout_redirect_uri", json_string("https://iddawc.tld/postlogout"));
  ck_assert_int_eq(1, json_equal(j_expected, j_result));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_CLIENT_ID));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_CLIENT_SECRET));
  json_decref(j_result);
  json_decref(j_expected);
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_manage_registration_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  json_t * j_expected = NULL, * j_result = NULL, * j_parameters = json_pack("{s[ss]}", "redirect_uris", "https://www.example.com/callback", "https://www.example.com/callback2");
  ck_assert_int_eq(ulfius_init_instance(&instance, 8081, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "PUT", NULL, "/register/s6BhdRkqt3", 0, &callback_register_management, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, client_id,
                                                    I_OPT_REGISTRATION_CLIENT_URI, "http://localhost:8081/register/s6BhdRkqt3",
                                                    I_OPT_ACCESS_TOKEN, TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_manage_registration_client(&i_session, j_parameters, 1, &j_result), I_OK);
  j_expected = json_loads(register_management_pattern, JSON_DECODE_ANY, NULL);
  json_array_append_new(json_object_get(j_expected, "redirect_uris"), json_string("https://www.example.com/callback"));
  json_array_append_new(json_object_get(j_expected, "redirect_uris"), json_string("https://www.example.com/callback2"));
  ck_assert_int_eq(1, json_equal(j_expected, j_result));
  ck_assert_str_eq("https://www.example.com/callback", i_get_str_parameter(&i_session, I_OPT_REDIRECT_URI));
  json_decref(j_result);
  json_decref(j_expected);
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, client_id,
                                                    I_OPT_REGISTRATION_CLIENT_URI, "http://localhost:8081/register/s6BhdRkqt3",
                                                    I_OPT_ACCESS_TOKEN, TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_manage_registration_client(&i_session, j_parameters, 0, &j_result), I_OK);
  j_expected = json_loads(register_management_pattern, JSON_DECODE_ANY, NULL);
  json_array_append_new(json_object_get(j_expected, "redirect_uris"), json_string("https://www.example.com/callback"));
  json_array_append_new(json_object_get(j_expected, "redirect_uris"), json_string("https://www.example.com/callback2"));
  ck_assert_int_eq(1, json_equal(j_expected, j_result));
  ck_assert_ptr_eq(NULL, i_get_str_parameter(&i_session, I_OPT_CLIENT_SECRET));
  json_decref(j_result);
  json_decref(j_expected);
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                    I_OPT_CLIENT_ID, client_id,
                                                    I_OPT_REGISTRATION_ENDPOINT, "http://localhost:8081/register",
                                                    I_OPT_ACCESS_TOKEN, TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_manage_registration_client(&i_session, j_parameters, 1, &j_result), I_OK);
  j_expected = json_loads(register_management_pattern, JSON_DECODE_ANY, NULL);
  json_array_append_new(json_object_get(j_expected, "redirect_uris"), json_string("https://www.example.com/callback"));
  json_array_append_new(json_object_get(j_expected, "redirect_uris"), json_string("https://www.example.com/callback2"));
  ck_assert_int_eq(1, json_equal(j_expected, j_result));
  ck_assert_str_eq("https://www.example.com/callback", i_get_str_parameter(&i_session, I_OPT_REDIRECT_URI));
  json_decref(j_result);
  json_decref(j_expected);
  i_clean_session(&i_session);
  
  json_decref(j_parameters);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_iddawc_delete_registration_valid)
{
  struct _i_session i_session;
  struct _u_instance instance;
  ck_assert_int_eq(ulfius_init_instance(&instance, 8082, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "DELETE", NULL, "/register/s6BhdRkqt3", 0, &callback_register_delete, NULL), U_OK);
  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_CLIENT_ID, client_id,
                                                    I_OPT_REGISTRATION_CLIENT_URI, "http://localhost:8082/register/s6BhdRkqt3",
                                                    I_OPT_ACCESS_TOKEN, TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_delete_registration_client(&i_session), I_OK);
  i_clean_session(&i_session);
  
  ck_assert_int_eq(i_init_session(&i_session), I_OK);
  ck_assert_int_eq(i_set_parameter_list(&i_session, I_OPT_CLIENT_ID, client_id,
                                                    I_OPT_REGISTRATION_CLIENT_URI, "http://localhost:8082/register/error",
                                                    I_OPT_ACCESS_TOKEN, TOKEN,
                                                    I_OPT_NONE), I_OK);
  ck_assert_int_eq(i_delete_registration_client(&i_session), I_ERROR_PARAM);
  i_clean_session(&i_session);
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

static Suite *iddawc_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Iddawc token registration tests");
  tc_core = tcase_create("test_iddawc_registration");
  tcase_add_test(tc_core, test_iddawc_registration_invalid);
  tcase_add_test(tc_core, test_iddawc_registration_valid);
  tcase_add_test(tc_core, test_iddawc_registration_from_params_valid);
  tcase_add_test(tc_core, test_iddawc_manage_registration_valid);
  tcase_add_test(tc_core, test_iddawc_delete_registration_valid);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(void)
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Iddawc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Iddawc token registration tests");
  i_global_init();
  s = iddawc_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  i_global_close();
  //y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
