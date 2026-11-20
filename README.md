# gateway

The front door to Mogul: it routes `/api/**` to the api and everything else to the studio (the client), and it decides who gets through.

## two ways in

**The browser** logs in here.
The gateway is the oauth client (the `auth0` registration in `MogulSettingsAwareClientRegistrationRepository`), keeps the user's tokens in their http session (in redis), and the token relay puts the access token on each request it forwards.
A request without a login is sent to `/login`, and on to auth0.

**The apps** (Mogul Clip on Android and iOS) log in to auth0 themselves, with PKCE, as a native application of their own, and send `Authorization: Bearer <token>` with each request.
For those requests, the gateway is a resource server: `bearerTokenSecurityFilterChain` in `SecurityConfiguration` checks the token against the same issuer and audience as the api, keeps no session, and answers a bad token with a 401 rather than a login page.
The token relay only acts for someone who logged in at the gateway, so the app's token goes on to the api untouched.
Only `/api/**` is reachable this way, and requests made this way carry no WordPress token, because that lives in the browser's session.

## the apps' auth0 application

The apps need an auth0 application of type **Native** (a public client: PKCE, no secret), separate from the gateway's own.

* **Allowed Callback URLs**: `com.joshlong.mogul://callback`, the custom scheme the apps register.
* **Allowed Logout URLs**: `com.joshlong.mogul://logout`.
* **Grant Types** (under Advanced Settings): Authorization Code and Refresh Token.
* **Refresh Token Rotation**: on.
* **Connections**: the same ones as the gateway's application, so that a person is the same auth0 user, and so the same mogul, from either one.

The apps ask for the same audience as the gateway (`auth0.audience`, `https://api.mogul.tools`) and for `openid profile email offline_access`; the api looks a new mogul up at auth0's `/userinfo` with the caller's token, which needs the first three.

## the auth0 api

`https://api.mogul.tools` is the identifier of an api in auth0 (**Applications → APIs**) that stands for Mogul's api: every access token is issued for it, and the api and the gateway turn down tokens issued for anything else.
It's only a name (nothing has to answer at that url), and it's in every token, so it doesn't change.
It signs with RS256, and allows offline access, so the apps get refresh tokens.
