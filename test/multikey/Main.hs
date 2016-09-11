{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

module Main
( main
) where

import Control.Monad.IO.Class ( liftIO )
import Data.Aeson ( Object )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Network.Wai ( Application )
import Network.Wai.Handler.Warp ( run )
import Servant
import Servant.GitHub.Webhook

main :: IO ()
main = do
  [k1, k2] <- C8.lines <$> BS.readFile "test/test-keys"
  run 8080 (app (constKeys k1 k2))

app :: MyGitHubKey -> Application
app k = serveWithContext api (k :. EmptyContext) server

server :: Server WebhookApi
server = (repo1ping :<|> repo1any) :<|> repo2any

repo1ping :: RepoWebhookEvent -> Object -> Handler ()
repo1ping _ _ = liftIO $ putStrLn "got ping on repo1!"

repo1any :: RepoWebhookEvent -> Object -> Handler ()
repo1any e _ = liftIO $ putStrLn $ "got event on repo 1: " ++ show e

repo2any :: RepoWebhookEvent -> Object -> Handler ()
repo2any e _ = liftIO $ putStrLn $ "got event on repo 2: " ++ show e

api :: Proxy WebhookApi
api = Proxy

type WebhookApi
  = "repo1" :> (
      GitHubEvent '[ 'WebhookPingEvent ]
    :> GitHubSignedReqBody' 'Repo1 '[JSON] Object
    :> Post '[JSON] ()
    :<|>
      GitHubEvent '[ 'WebhookWildcardEvent ]
    :> GitHubSignedReqBody' 'Repo1 '[JSON] Object
    :> Post '[JSON] ()
  )
  :<|>
    "repo2"
    :> GitHubEvent '[ 'WebhookWildcardEvent ]
    :> GitHubSignedReqBody' 'Repo2 '[JSON] Object
    :> Post '[JSON] ()

type MyGitHubKey = GitHubKey' Key

data Key
  = Repo1
  | Repo2

constKeys :: BS.ByteString -> BS.ByteString -> MyGitHubKey
constKeys k1 k2 = GitHubKey $ \k -> pure $ case k of
  Repo1 -> k1
  Repo2 -> k2

type instance Demote' ('KProxy :: KProxy Key) = Key
instance Reflect 'Repo1 where
  reflect _ = Repo1
instance Reflect 'Repo2 where
  reflect _ = Repo2
