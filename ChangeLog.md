# Revision history for servant-github-webhook

## 0.1.0.0  -- 2016-09-10

Initial release.

* Implement `GitHubSignedReqBody` combinator for automatic signature
  verification during routing.
* Implement `GitHubEvent` combinator for dispatching to routes based on the
  webhook type.
* Known issue: only one global `GitHubKey` can be used across all routes.
