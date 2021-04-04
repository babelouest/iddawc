# idwcc: Universal OAuth2/OIDC client

Copyright 2021 Nicolas Mora <mail@babelouest.org>

This program is free software; you can redistribute it and/or modify it under the terms of the GPL3 License.

## Overview

Client program to test or validate an OAuth2/OIDC authorization server.

![idwcc](idwcc.png)

## Options

Options available:

```shell
-p, --port <PORT_NUMBER>
	TCP Port number to listen to, default 4398
-f, --session-file <PATH>
	Load session file specified by <PATH>
-b, --bind-localhost [true|false]
	Bind to localhost only, default true
-h, --help
	display this help and exit
-v, --version
	output version information and exit
```

## Secuity concerns

This web application is **NOT** intended to run in production mode, because all the client secrets, keys configuration and metadata are fully accessible to the user via the form or the javascript console.

By default, the application is available to localhost only, for security reason. You can make it available to any host by adding the option `-b false`.
