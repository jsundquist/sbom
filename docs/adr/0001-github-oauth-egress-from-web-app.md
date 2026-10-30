# The web app may call GitHub, and only GitHub, for sign-in

AGENTS.md restricts external HTTP to `src/worker/`. Sign-in with GitHub OAuth (`next-auth` v4) needs the web process to call `github.com/login/oauth/*` and `api.github.com/user`, so we grant one narrow exception: that traffic only, in one auth module, through the injectable `FetchFn` so tests never hit the network. We chose GitHub sign-in over an owner password so there is no password to brute-force and a non-owner can later sign in without seeing anything; relaxing the rule globally was rejected.
