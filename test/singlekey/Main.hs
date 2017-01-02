{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

import Control.Monad.IO.Class ( liftIO )
import Data.Aeson ( Object )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Servant
import Servant.GitHub.Webhook
import Network.Wai ( Application )
import Network.Wai.Handler.Warp ( run )

main :: IO ()
main = pure ()

realMain :: IO ()
realMain = do
  [key, _] <- C8.lines <$> BS.readFile "test/test-keys"
  run 8080 (app (gitHubKey $ pure key))

app :: GitHubKey -> Application
app key
  = serveWithContext
    (Proxy :: Proxy API)
    (key :. EmptyContext)
    server

server :: Server API
server = anyEvent

anyEvent :: RepoWebhookEvent -> ((), Object) -> Handler ()
anyEvent e _
  = liftIO $ putStrLn $ "got event: " ++ show e

type API
  = "repo1"
    :> GitHubEvent '[ 'WebhookPushEvent ]
    :> GitHubSignedReqBody '[JSON] Object
    :> Post '[JSON] ()
