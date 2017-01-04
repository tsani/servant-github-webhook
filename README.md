servant-github-webhook
======================

[![Build Status][badge-travis]][travis]
[![Hackage][badge-hackage]][hackage]

This library facilitates writing Servant routes that can safely act as GitHub
webhooks.

Features:

  * Dispatching to routes based on the type of repository event.
  * Automatic verification of request signatures.
  * Route protection expressed in the type system, so webhook routes are
    regular routes cannot be confused.

[hackage]: https://hackage.haskell.org/package/servant-github-webhook
[badge-hackage]: https://img.shields.io/hackage/v/servant-github-webhook.svg
[travis]: https://travis-ci.org/tsani/servant-github-webhook?branch=master
[badge-travis]: https://travis-ci.org/tsani/servant-github-webhook.svg?branch=master
