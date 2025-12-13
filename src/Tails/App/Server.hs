module Tails.App.Server (runServer, handleConnEcho) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import Network.Socket (Socket)
import Numeric (showHex)
import Tails.TCP (acceptLoop, recvSome, sendAll, withServer)
import Tails.TLS.Record.Codec (DecodeError (..), decodeTLSPlainText)
import Tails.TLS.Record.Types (TLSPlainText (..))

runServer :: IO ()
runServer =
  withServer "127.0.0.1" "8443" $ \sock -> do
    putStrLn "listening on 127.0.0.1:8443"
    acceptLoop sock handleConnEcho

handleConnEcho :: Socket -> IO ()
handleConnEcho sock = do
  putStrLn "client connected"
  loop BS.empty
  putStrLn "client disconnected"
  where
    loop buf = do
      bs <- recvSome sock 4096
      if BS.null bs
        then pure ()
        else do
          putStrLn $ "received " ++ show (BS.length bs) ++ " bytes"
          loop' $ BS.append buf bs

    loop' buf =
      case decodeTLSPlainText buf of
        Right (record, rest) -> do
          putStrLn $
            "decoded TLS record: type="
              ++ show (contentType record)
              ++ " length="
              ++ show (BS.length (fragment record))
              ++ " data="
              -- show first 16 bytes in hex
              ++ concatMap (`showHex` "") (BS.unpack $ BS.take 16 (fragment record))
              ++ if BS.length (fragment record) > 16 then "..." else ""

          loop' rest
        Left NeedMoreData -> loop buf
        Left (Malformed err) -> do
          putStrLn $ "malformed TLS record: " ++ show err
          pure ()
