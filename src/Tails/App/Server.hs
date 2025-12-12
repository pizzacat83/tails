module Tails.App.Server (runServer, handleConnEcho) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import Network.Socket (Socket)
import Tails.TCP (acceptLoop, recvSome, sendAll, withServer)

runServer :: IO ()
runServer =
  withServer "127.0.0.1" "8443" $ \sock -> do
    putStrLn "listening on 127.0.0.1:8443"
    acceptLoop sock handleConnEcho

handleConnEcho :: Socket -> IO ()
handleConnEcho sock = do
  putStrLn "client connected"
  loop
  putStrLn "client disconnected"
  where
    loop = do
      bs <- recvSome sock 4096
      if BS.null bs
        then pure ()
        else do
          putStrLn ("received: " <> B8.unpack (B8.take 200 bs))
          sendAll sock bs
          loop
