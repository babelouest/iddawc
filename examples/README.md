# Iddawc examples use

The following examples are for some well-known OAuth2 providers. For each example, you may change at least the folling values with your own:

```C
#define CLIENT_ID "clientXyz"
#define CLIENT_SECRET "secretXyz"
#define REDIRECT_URI "https://www.example.com/"
```

Please check each provider docmentation for how to register OAuth2 clients.

## Build an example

Update the source file `*.c` with your client parameters, then run `make '*_example'`.

Example:

```C
$ make glewlwyd_oidc_id_token_code
```
