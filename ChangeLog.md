# Revision history for servant-github-webhook

## 0.3.2.0  -- 2017-12-25

* Support GHC 8.2 / `base` 4.10.
* Bump up version bound for `github` to 0.18.

## 0.3.1.0  -- 2017-08-06

* Drop support for GHC <8.
* Drop support for Servant <0.11.
* Switch from Crypto package to cryptonite package.
* Now servant-github-webhook builds with stack.

## 0.3.0.0  -- 2016-09-22

* Pass reflected key index to the handler function for GitHubSignedReqBody.
  This allows for more generic handler functions, as they can determine
  programmatically which repository they are responding to.

## 0.2.0.1  -- 2016-09-13

* Improve documentation (formatting and typos) and examples (remove unnecessary
  verbosity).

## 0.2.0.0  -- 2016-09-11

* Generalize `GitHubSignedReqBody` combinator to `GitHubSignedReqBody''` to
  allow for configuring multiple signing keys, on a per-route basis.
* Make `GitHubKey` take a function instead of simply an `IO` action.
* Reexport `KProxy`, to make writing `Demote'` instances easier.

## 0.1.0.0  -- 2016-09-10

Initial release.

* Implement `GitHubSignedReqBody` combinator for automatic signature
  verification during routing.
* Implement `GitHubEvent` combinator for dispatching to routes based on the
  webhook type.
* Known issue: only one global `GitHubKey` can be used across all routes.
