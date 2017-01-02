[![Build Status](https://travis-ci.org/tsani/servant-github-webhook.svg?branch=master)](https://travis-ci.org/tsani/servant-github-webhook)

servant-github-webhook
======================

This library facilitates writing Servant routes that can safely act as GitHub
webhooks.

Features:

  * Dispatching to routes based on the type of repository event.
  * Automatic verification of request signatures.

See the
[documentation](https://hackage.haskell.org/package/servant-github-webhook-0.2.0.0/docs/Servant-GitHub-Webhook.html)
for more details about how the library works, and how to use it.

TODO
-----

  * `servant-client` and `servant-docs` instances.
  * Tests.
