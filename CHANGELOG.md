# Iddawc Changelog

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
