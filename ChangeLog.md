# Revision history for servant-github-webhook

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
