/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <jansson.h>
#include <check.h>
#include <yder.h>
#include <iddawc.h>

#define TOKEN "accessTokenXyz1234"

const char client_id[] = "s6BhdRkqt3";
const char client_secret[] = "ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk";
const char register_pattern[] = "{\"client_id\": \"s6BhdRkqt3\",\"client_secret\":\"ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk\",\"client_secret_expires_at\": 1577858400,\"registration_access_token\":\"this.is.an.access.token.value.ffx83\",\"registration_client_uri\":\"https://server.example.com/connect/register?client_id=s6BhdRkqt3\",\"token_endpoint_auth_method\":\"client_secret_basic\",\"application_type\": \"web\",\"redirect_uris\":[],\"client_name\": \"My Example\",\"client_name#ja-Jpan-JP\":\"クライアント名\",\"logo_uri\": \"https://client.example.org/logo.png\",\"subject_type\": \"pairwise\",\"sector_identifier_uri\":\"https://other.example.net/file_of_redirect_uris.json\",\"jwks_uri\": \"https://client.example.org/my_public_keys.jwks\",\"userinfo_encrypted_response_alg\": \"RSA1_5\",\"userinfo_encrypted_response_enc\": \"A128CBC-HS256\",\"contacts\": [\"ve7jtb@example.org\", \"mary@example.org\"],\"request_uris\":[]}";

int callback_register (const struct _u_request * request, struct _u_response * response, void * user_data) {
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
  json_decref(j_result);
  json_decref(j_expected);
  i_clean_session(&i_session);
  
  json_decref(j_parameters);
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
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
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
