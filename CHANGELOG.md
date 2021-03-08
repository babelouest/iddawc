# Iddawc Changelog

## 0.9.9

- Improve OAuth 2.0 Rich Authorization Requests
- Add `i_set_rich_authorization_request_json_t`, `i_remove_rich_authorization_request_json_t`, `i_manage_registration_client`
- Rename `i_set_rich_authorization_request` to `i_set_rich_authorization_request_str`, `i_remove_rich_authorization_request` to `i_remove_rich_authorization_request_str`
- Supports [OAuth 2.0 Dynamic Client Registration Management Protocol](https://tools.ietf.org/html/rfc7592)

## 0.9.8

- Supports [OAuth 2.0 Rich Authorization Requests Draft 03](https://www.ietf.org/archive/id/draft-ietf-oauth-rar-03.html)
- Supports [OAuth 2.0 Device Authorization Grant (rfc #8628)](https://tools.ietf.org/html/rfc8628)
- Supports [OAuth 2.0 Pushed Authorization Requests Draft 05](https://tools.ietf.org/html/draft-ietf-oauth-par-05)
- Add `i_set_rich_authorization_request`, `i_remove_rich_authorization_request`, `i_get_rich_authorization_request` for rich authorization requests
- Add `i_run_device_auth_request` for device authorization requests
- Add `i_run_par_request` for pushed authorization requests
- Remove Travis CI tests

## 0.9.7

- Add `i_global_init`, `i_global_close`, `i_free`
- Add `i_generate_dpop_token`

## 0.9.6

- Allow encrypted JWT requests
- Bugfixes

## 0.9.5

- Use rhonabwy instead of libjwt for JWT management
- Add JWT requests in `/auth` and `/token` endpoints
- Add `i_load_userinfo_custom`
- Add functions `i_revoke_token`, `i_introspect_token`, `i_register_client`

## 0.9.4

- Bugfixes

## 0.9.3

- Rename `i_get_flag_parameter` to `i_get_int_parameter` and `i_get_parameter` to `i_get_str_parameter`
- Rename `i_export_session` to `i_export_session_json_t`, `i_import_session` to `i_import_session_json_t` and add `i_export_session_str` and `i_import_session_str`
- Improve examples

## 0.9.2

- First release
- Implements OAuth2 and OpenID Connect clients
- Parses server response and set properties values
- Validates `id_token`
- Add examples for mainstream OAuth2 providers: Google, Facebook, GitHub, GitLab, Microsoft provided
- Imports and exports Iddawc sessions
