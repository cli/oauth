# oauth

A library for Go client applications that need to perform OAuth authorization against a server, typically GitHub.com.

Traditionally, OAuth for web applications involves redirecting to a URI after the user authorizes an app. While web apps (and some native client apps) can receive a browser redirect, client apps such as CLI applications do not have such an option.

To accommodate client apps, this library implements the [OAuth Device Authorization Grant][oauth-device] which GitHub.com [now supports][gh-device]. To transparently enable OAuth authorization on _any GitHub host_ (e.g. GHES instances without OAuth “Device flow” support), this library also bundles an implementation of OAuth web application flow in which the client app starts a local server at `http://127.0.0.1:<port>/` that acts as a receiver for the browser redirect. First, Device flow is attempted, and the localhost server is used as fallback.


[oauth-device]: https://oauth.net/2/device-flow/
[gh-device]: https://docs.github.com/en/free-pro-team@latest/developers/apps/authorizing-oauth-apps#device-flow
