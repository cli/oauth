# oauth

A library for Go client applications that need to perform OAuth authorization against a server, typically GitHub.com.

<p align="center">
  <img width="598" alt="" src="https://user-images.githubusercontent.com/887/102650961-f2751e80-416b-11eb-8b37-d82b076eb2d1.png"><br>
  <img width="976" alt="" src="https://user-images.githubusercontent.com/887/102650543-5e0abc00-416b-11eb-8e54-7b6e334ab092.png">
</p>

Traditionally, OAuth for web applications involves redirecting to a URI after the user authorizes an app. While web apps (and some native client apps) can receive a browser redirect, client apps such as CLI applications do not have such an option.

To accommodate client apps, this library implements the [OAuth Device Authorization Grant][oauth-device] which [GitHub.com now supports][gh-device]. With Device flow, the user is presented with a one-time code that they will have to enter in a web browser while authorizing the app on the server. Device flow is suitable for cases where the web browser may be running on a separate device than the client app itself; for example a CLI application could run within a headless, containerized instance, but the user may complete authorization using a browser on their phone.

To transparently enable OAuth authorization on _any GitHub host_ (e.g. GHES instances without OAuth “Device flow” support), this library also bundles an implementation of OAuth web application flow in which the client app starts a local server at `http://127.0.0.1:<port>/` that acts as a receiver for the browser redirect. First, Device flow is attempted, and the localhost server is used as fallback. With the localhost server, the user's web browser must be running on the same machine as the client application itself.

## Usage

- [OAuth Device flow with fallback](./examples_test.go)
- [manual OAuth Device flow](./device/examples_test.go)
- [manual OAuth web application flow](./webapp/examples_test.go)

Applications that need more control over the user experience around authentication should directly interface with `github.com/cli/oauth/device` and `github.com/cli/oauth/webapp` packages.

In theory, these packages would enable authorization on any OAuth-enabled host. In practice, however, this was only tested for authorizing with GitHub.


[oauth-device]: https://oauth.net/2/device-flow/
[gh-device]: https://docs.github.com/en/free-pro-team@latest/developers/apps/authorizing-oauth-apps#device-flow
