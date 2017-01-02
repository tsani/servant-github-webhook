{-|
Module      : Servant.GitHub.Webhook
Description : Easily write safe GitHub webhook handlers with Servant
Copyright   : (c) Jacob Thomas Errington, 2016
License     : MIT
Maintainer  : servant-github-webhook@mail.jerrington.me
Stability   : experimental

The GitHub webhook machinery will attach three headers to the HTTP requests
that it fires: @X-Github-Event@, @X-Hub-Signature@, and @X-Github-Delivery@.
The former two headers correspond with the 'GitHubEvent' and
'GitHubSignedReqBody''' routing combinators. This library ignores the
@X-Github-Delivery@ header; if you would like to access its value, then use the
builtin 'Header' combinator from Servant.

Usage of the library is straightforward: protect routes with the 'GitHubEvent'
combinator to ensure that the route is only reached for specific
'RepoWebhookEvent's, and replace any 'ReqBody' combinators you would write
under that route with 'GitHubSignedReqBody'. It is advised to always include a
'GitHubSignedReqBody''', as this is the only way you can be sure that it is
GitHub who is sending the request, and not a malicious user. If you don't care
about the request body, then simply use Aeson\'s 'Object' type as the
deserialization target -- @GitHubSignedReqBody' key '[JSON] Object@ -- and
ignore the @Object@ in the handler.

The 'GitHubSignedReqBody''' combinator makes use of the Servant 'Context' in
order to extract the signing key. This is the same key that must be entered in
the configuration of the webhook on GitHub. See 'GitHubKey'' for more details.

In order to support multiple keys on a per-route basis, the basic combinator
@GitHubSignedReqBody''@ takes as a type parameter as a key index. To use this,
create a datatype, e.g. @KeyIndex@ whose constructors identify the different
keys you will be using. Generally, this means one constructor per repository.
Use the @DataKinds@ extension to promote this datatype to a kind, and write an
instance of 'Reflect' for each promoted constructor of your datatype. Finally,
create a 'Context' containing 'GitHubKey'' whose wrapped function's domain is
the datatype you've built up. Thus, your function can determine which key to
retrieve.
-}

{-# LANGUAGE CPP #-}

{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

-- GHC 8 seems to have improved its decidability check for type family
-- instances and class instances. In particular, without UndecidableInstances
-- enabled, the Demote' instance for lists, which we need, will not compile.
-- Similarly, the Reflect instance for Symbol, which just requires KnownSymbol,
-- won't compile on GHC < 8 because the instance head is no smaller than the
-- instance head.
#if __GLASGOW_HASKELL__ < 800
{-# LANGUAGE UndecidableInstances #-}
#endif

module Servant.GitHub.Webhook
( -- * Servant combinators
  GitHubSignedReqBody''
, GitHubSignedReqBody'
, GitHubSignedReqBody
, GitHubEvent

  -- ** Security
, GitHubKey'(..)
, GitHubKey
, gitHubKey

  -- * Reexports
  --
  -- | We reexport a few datatypes that are typically needed to use the
  -- library.
, RepoWebhookEvent(..)
, KProxy(..)

  -- * Implementation details

  -- ** Type-level programming machinery
, Demote
, Demote'
, Reflect(..)

  -- ** Stringy stuff
, parseHeaderMaybe
, matchEvent

  -- * Examples
  --
  -- $example1
  --
  -- $example2
) where

import Control.Monad.IO.Class ( liftIO )
import Data.Aeson ( decode', encode )
import qualified Data.ByteString as BS
import Data.ByteString.Lazy ( fromStrict, toStrict )
import qualified Data.ByteString.Base16 as B16
import Data.HMAC ( hmac_sha1 )
import Data.List ( intercalate )
import Data.Maybe ( catMaybes, fromMaybe )
import Data.Monoid ( (<>) )
import Data.Proxy
import Data.String.Conversions ( cs )
import qualified Data.Text.Encoding as E
import GHC.TypeLits
import GitHub.Data.Webhooks
import Network.HTTP.Types hiding (Header, ResponseHeaders)
import Network.Wai ( requestHeaders, strictRequestBody )
import Servant
import Servant.API.ContentTypes ( AllCTUnrender(..) )
import Servant.Server.Internal


-- | A clone of Servant's 'ReqBody' combinator, except that it will also
-- verify the signature provided by GitHub in the @X-Hub-Signature@ header by
-- computing the SHA1 HMAC of the request body and comparing.
--
-- The use of this combinator will require that the router context contain an
-- appropriate 'GitHubKey'' entry. Specifically, the type parameter of
-- 'GitHubKey'' must correspond with @Demote k@ where @k@ is the kind of the
-- index @key@ used here. Consequently, it will be necessary to use
-- 'serveWithContext' instead of 'serve'.
--
-- Other routes are not tried upon the failure of this combinator, and a 401
-- response is generated.
--
-- Use of this datatype directly is discouraged, since the choice of the index
-- @key@ determines its kind @k@ and hence @proxy@, which is . Instead, use
-- 'GitHubSignedReqBody'', which computes the @proxy@ argument given just
-- @key@. The proxy argument is necessary to avoid @UndecidableInstances@ for
-- the implementation of the 'HasServer' instance for the datatype.
data GitHubSignedReqBody''
  (proxy :: KProxy k)
  (key :: k)
  (list :: [*])
  (result :: *) where

-- | Convenient synonym for 'GitHubSignedReqBody''' that computes its first
-- type argument given just the second one.
--
-- Use this type synonym if you are creating a webhook server to handle
-- webhooks from multiple repositories, with different secret keys.
type GitHubSignedReqBody' (key :: k)
  = GitHubSignedReqBody'' ('KProxy :: KProxy k) key

-- | A convenient alias for a trivial key index.
--
-- USe this type synonym if you are creating a webhook server to handle only
-- webhooks from a single repository, or for mutliple repositories using the
-- same secret key.
type GitHubSignedReqBody = GitHubSignedReqBody' '()

-- | A routing combinator that succeeds only for a webhook request that matches
-- one of the given 'RepoWebhookEvent' given in the type-level list @events@.
--
-- If the list contains 'WebhookWildcardEvent', then all events will be
-- matched.
--
-- The combinator will require that its associated handler take a
-- 'RepoWebhookEvent' parameter, and the matched event will be passed to the
-- handler. This allows the handler to determine which event triggered it from
-- the list.
--
-- Other routes are tried if there is a mismatch.
data GitHubEvent (events :: [RepoWebhookEvent]) where

-- | A wrapper for an IO strategy to obtain the signing key for the webhook as
-- configured in GitHub. The strategy is executed each time the
-- 'GitHubSignedReqBody''s routing logic is executed.
--
-- We allow the use of @IO@ here so that you can fetch the key from a cache or
-- a database. If the key is a constant or read only once, just use 'pure'.
--
-- The type @key@ used here must correspond with @'Demote' k@ where @k@ is the
-- kind whose types are used as indices in 'GitHubSignedReqBody''.
--
-- If you don't care about indices and just want to write a webhook using a
-- global key, see 'GitHubKey' which fixes @key@ to @()@ and use 'gitHubKey',
-- which fills the newtype with a constant function.
newtype GitHubKey' key = GitHubKey { unGitHubKey :: key -> IO BS.ByteString }

-- | A synonym for strategies producing so-called /global/ keys, in which the
-- key index is simply @()@.
type GitHubKey = GitHubKey' ()

-- | Smart constructor for 'GitHubKey', for a so-called /global/ key.
gitHubKey :: IO BS.ByteString -> GitHubKey
gitHubKey = GitHubKey . const

instance forall sublayout context list result (key :: k).
  ( HasServer sublayout context
  , HasContextEntry context (GitHubKey' (Demote key))
  , Reflect key
  , AllCTUnrender list result
  )
  => HasServer
    (GitHubSignedReqBody'' ('KProxy :: KProxy k) key list result :> sublayout)
    context where

  type ServerT
    (GitHubSignedReqBody'' ('KProxy :: KProxy k) key list result :> sublayout)
    m
    = (Demote key, result) -> ServerT sublayout m

  route
    :: forall env.
       Proxy (
         GitHubSignedReqBody'' ('KProxy :: KProxy k) key list result
         :> sublayout
       )
    -> Context context
    -> Delayed env ((Demote key, result) -> Server sublayout)
    -> Router env
  route _ context subserver
    = route (Proxy :: Proxy sublayout) context (addBodyCheck subserver go)
    where
      lookupSig = lookup "X-Hub-Signature"

      keyIndex :: Demote key
      keyIndex = reflect (Proxy :: Proxy key)

      go :: DelayedIO (Demote key, result)
      go = withRequest $ \req -> do
        let hdrs = requestHeaders req
        key <- BS.unpack <$>
          liftIO (unGitHubKey (getContextEntry context) keyIndex)
        msg <- BS.unpack <$> liftIO (toStrict <$> strictRequestBody req)
        let sig = B16.encode $ BS.pack $ hmac_sha1 key msg
        let contentTypeH = fromMaybe "application/octet-stream"
                         $ lookup hContentType $ hdrs
        let mrqbody =
              handleCTypeH (Proxy :: Proxy list) (cs contentTypeH) $
              fromStrict (BS.pack msg)

        case mrqbody of
          Nothing -> delayedFailFatal err415
          Just (Left e) -> delayedFailFatal err400 { errBody = cs e }
          Just (Right v) -> case parseHeaderMaybe =<< lookupSig hdrs of
            Nothing -> delayedFailFatal err401
            Just h -> do
              let h' = BS.drop 5 $ E.encodeUtf8 h -- remove "sha1=" prefix
              if h' == sig
              then pure (keyIndex, v)
              else delayedFailFatal err401

instance forall sublayout context events.
  (Reflect events, HasServer sublayout context)
  => HasServer (GitHubEvent events :> sublayout) context where

  type ServerT (GitHubEvent events :> sublayout) m
    = RepoWebhookEvent -> ServerT sublayout m

  route
    :: forall env. Proxy (GitHubEvent events :> sublayout)
    -> Context context
    -> Delayed env (RepoWebhookEvent -> Server sublayout)
    -> Router env
  route Proxy context subserver
    = route
      (Proxy :: Proxy sublayout)
      context
      (addAuthCheck subserver go)
    where
      lookupGHEvent = lookup "X-Github-Event"

      events :: [RepoWebhookEvent]
      events = reflect (Proxy :: Proxy events)

      eventNames :: String
      eventNames = intercalate ", " $ (cs . encode) <$> events

      go :: DelayedIO RepoWebhookEvent
      go = withRequest $ \req -> do
        case lookupGHEvent (requestHeaders req) of
          Nothing -> delayedFail err401
          Just h -> do
            case catMaybes $ map (`matchEvent` h) events of
              [] -> delayedFail err404
                { errBody = cs $ "supported events: " <> eventNames }
              (event:_) -> pure event

-- | Type function that reflects a kind to a type.
type family Demote' (kparam :: KProxy k) :: *

-- | Convient alias for 'Demote'' that allows us to avoid using 'KProxy'
-- explicitly.
type Demote (a :: k) = Demote' ('KProxy :: KProxy k)

type instance Demote' ('KProxy :: KProxy ()) = ()
type instance Demote' ('KProxy :: KProxy Symbol) = String
type instance Demote' ('KProxy :: KProxy [k]) = [Demote' ('KProxy :: KProxy k)]
type instance Demote' ('KProxy :: KProxy RepoWebhookEvent) = RepoWebhookEvent

-- | Class of types that can be reflected to values.
class Reflect (a :: k) where
  reflect :: Proxy (a :: k) -> Demote a

instance KnownSymbol s => Reflect (s :: Symbol) where
  reflect = symbolVal

instance Reflect '() where
  reflect _ = ()

instance Reflect '[] where
  reflect _ = []

instance (Reflect x, Reflect xs) => Reflect (x ': xs) where
  reflect _ = reflect x : reflect xs where
    x = Proxy :: Proxy x
    xs = Proxy :: Proxy xs

instance Reflect 'WebhookWildcardEvent where
  reflect _ = WebhookWildcardEvent

instance Reflect 'WebhookCommitCommentEvent where
  reflect _ = WebhookCommitCommentEvent

instance Reflect 'WebhookCreateEvent where
  reflect _ = WebhookCreateEvent

instance Reflect 'WebhookDeleteEvent where
  reflect _ = WebhookDeleteEvent

instance Reflect 'WebhookDeploymentEvent where
  reflect _ = WebhookDeploymentEvent

instance Reflect 'WebhookDeploymentStatusEvent where
  reflect _ = WebhookDeploymentStatusEvent

instance Reflect 'WebhookForkEvent where
  reflect _ = WebhookForkEvent

instance Reflect 'WebhookGollumEvent where
  reflect _ = WebhookGollumEvent

instance Reflect 'WebhookIssueCommentEvent where
  reflect _ = WebhookIssueCommentEvent

instance Reflect 'WebhookIssuesEvent where
  reflect _ = WebhookIssuesEvent

instance Reflect 'WebhookMemberEvent where
  reflect _ = WebhookMemberEvent

instance Reflect 'WebhookPageBuildEvent where
  reflect _ = WebhookPageBuildEvent

instance Reflect 'WebhookPingEvent where
  reflect _ = WebhookPingEvent

instance Reflect 'WebhookPublicEvent where
  reflect _ = WebhookPublicEvent

instance Reflect 'WebhookPullRequestReviewCommentEvent where
  reflect _ = WebhookPullRequestReviewCommentEvent

instance Reflect 'WebhookPullRequestEvent where
  reflect _ = WebhookPullRequestEvent

instance Reflect 'WebhookPushEvent where
  reflect _ = WebhookPushEvent

instance Reflect 'WebhookReleaseEvent where
  reflect _ = WebhookReleaseEvent

instance Reflect 'WebhookStatusEvent where
  reflect _ = WebhookStatusEvent

instance Reflect 'WebhookTeamAddEvent where
  reflect _ = WebhookTeamAddEvent

instance Reflect 'WebhookWatchEvent where
  reflect _ = WebhookWatchEvent

-- | Helper that parses a header using a 'FromHttpApiData' instance and
-- discards the parse error message if any.
parseHeaderMaybe :: FromHttpApiData a => BS.ByteString -> Maybe a
parseHeaderMaybe = eitherMaybe . parseHeader where
  eitherMaybe :: Either e a -> Maybe a
  eitherMaybe e = case e of
    Left _ -> Nothing
    Right x -> Just x

-- | Determines whether a given webhook event matches a given raw
-- representation of one. The result is 'Nothing' if there is no match. This
-- function accounts for the 'WebhookWildcardEvent' matching everything, so it
-- returns the result of parsing the raw representation when trying to match
-- against the wildcard.
matchEvent :: RepoWebhookEvent -> BS.ByteString -> Maybe RepoWebhookEvent
matchEvent WebhookWildcardEvent s = decode' (fromStrict s') where
  s' = "\"" <> s <> "\""
matchEvent e name
  | toStrict (encode e) == name' = Just e
  | otherwise = Nothing
  where name' = "\"" <> name <> "\""

-- $example1
--
-- === Using a global key
--
-- > {-# LANGUAGE DataKinds #-}
-- > {-# LANGUAGE TypeFamilies #-}
-- > {-# LANGUAGE TypeOperators #-}
-- >
-- > module Main
-- > ( main
-- > ) where
-- >
-- > import Control.Monad.IO.Class ( liftIO )
-- > import Data.Aeson ( Object )
-- > import qualified Data.ByteString as BS
-- > import qualified Data.ByteString.Char8 as C8
-- > import Servant
-- > import Servant.GitHub.Webhook
-- > import Network.Wai ( Application )
-- > import Network.Wai.Handler.Warp ( run )
-- >
-- > main :: IO ()
-- > main = do
-- >   [key, _] <- C8.lines <$> BS.readFile "test/test-keys"
-- >   run 8080 (app (gitHubKey $ pure key))
-- >
-- > app :: GitHubKey -> Application
-- > app key
-- >   = serveWithContext
-- >     (Proxy :: Proxy API)
-- >     (key :. EmptyContext)
-- >     server
-- >
-- > server :: Server API
-- > server = anyEvent
-- >
-- > anyEvent :: RepoWebhookEvent -> ((), Object) -> Handler ()
-- > anyEvent e _
-- >   = liftIO $ putStrLn $ "got event: " ++ show e
-- >
-- > type API
-- >   = "repo1"
-- >     :> GitHubEvent '[ 'WebhookPushEvent ]
-- >     :> GitHubSignedReqBody '[JSON] Object
-- >     :> Post '[JSON] ()

-- $example2
--
-- === Using multiple keys
--
-- > {-# LANGUAGE DataKinds #-}
-- > {-# LANGUAGE TypeFamilies #-}
-- > {-# LANGUAGE TypeOperators #-}
-- >
-- > module Main
-- > ( main
-- > ) where
-- >
-- > import Control.Monad.IO.Class ( liftIO )
-- > import Data.Aeson ( Object )
-- > import qualified Data.ByteString as BS
-- > import qualified Data.ByteString.Char8 as C8
-- > import Network.Wai ( Application )
-- > import Network.Wai.Handler.Warp ( run )
-- > import Servant
-- > import Servant.GitHub.Webhook
-- >
-- > main :: IO ()
-- > main = do
-- >   [k1, k2] <- C8.lines <$> BS.readFile "test/test-keys"
-- >   run 8080 (app (constKeys k1 k2))
-- >
-- > app :: MyGitHubKey -> Application
-- > app k = serveWithContext api (k :. EmptyContext) server
-- >
-- > server :: Server WebhookApi
-- > server = repo1any :<|> repo2any
-- >
-- > repo1any :: RepoWebhookEvent -> (Key, Object) -> Handler ()
-- > repo1any WebhookPingEvent _ = liftIO $ putStrLn "got ping on repo1!"
-- > repo1any e _ = liftIO $ putStrLn $ "got event on repo 1: " ++ show e
-- >
-- > repo2any :: RepoWebhookEvent -> (Key, Object) -> Handler ()
-- > repo2any e _ = liftIO $ putStrLn $ "got event on repo 2: " ++ show e
-- >
-- > api :: Proxy WebhookApi
-- > api = Proxy
-- >
-- > type WebhookApi
-- >   = "repo1"
-- >     :> GitHubEvent '[ 'WebhookWildcardEvent ]
-- >     :> GitHubSignedReqBody' 'Repo1 '[JSON] Object
-- >     :> Post '[JSON] ()
-- >   :<|>
-- >     "repo2"
-- >     :> GitHubEvent '[ 'WebhookWildcardEvent ]
-- >     :> GitHubSignedReqBody' 'Repo2 '[JSON] Object
-- >     :> Post '[JSON] ()
-- >
-- > type MyGitHubKey = GitHubKey' Key
-- >
-- > data Key
-- >   = Repo1
-- >   | Repo2
-- >
-- > constKeys :: BS.ByteString -> BS.ByteString -> MyGitHubKey
-- > constKeys k1 k2 = GitHubKey $ \k -> pure $ case k of
-- >   Repo1 -> k1
-- >   Repo2 -> k2
-- >
-- > type instance Demote' ('KProxy :: KProxy Key) = Key
-- > instance Reflect 'Repo1 where
-- >   reflect _ = Repo1
-- > instance Reflect 'Repo2 where
-- >   reflect _ = Repo2
