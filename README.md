servant-github-webhook
======================

[![Build Status][badge-travis]][travis]
[![Hackage][badge-hackage]][hackage]
[![servant-github-webhook][badge-stackage-lts]][stackage-lts]
[![servant-github-webhook][badge-stackage-nightly]][stackage-nightly]

This library facilitates writing Servant routes that can safely act as GitHub
webhooks.

Features:

  * Dispatching to routes based on the type of repository event.
  * Automatic verification of request signatures.
  * Route protection expressed in the type system, so webhook routes and
    regular routes cannot be confused.

Why use servant-github-webhook?
-------------------------------

A webhook server needs to be publicly hosted. How can legitimate requests sent
by GitHub be distinguished from (malicious) requests sent by other clients?

When a webhook is configured on a repository, a *secret key* is added. This key
is used by GitHub to compute a *signature* of the request body that it sends;
this signature is included in the request headers. The routing combinators in
servant-github-webhook compute the signature of the received request body using
the same key, and check that the signature in the request headers matches. If
it does, then the request is legitimate.

[hackage]: https://hackage.haskell.org/package/servant-github-webhook
[badge-hackage]: https://img.shields.io/hackage/v/servant-github-webhook.svg
[travis]: https://travis-ci.org/tsani/servant-github-webhook?branch=master
[badge-travis]: https://travis-ci.org/tsani/servant-github-webhook.svg?branch=master

[badge-stackage-lts]: http://stackage.org/package/servant-github-webhook/badge/lts
[stackage-lts]: https://stackage.org/lts/package/servant-github-webhook
[badge-stackage-nightly]: http://stackage.org/package/servant-github-webhook/badge/nightly
[stackage-nightly]: http://stackage.org/nightly/package/servant-github-webhook
