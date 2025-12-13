module Tails.App.Server (runServer, handleConnEcho) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import Network.Socket (Socket)
import Numeric (showHex)
import Tails.TCP (acceptLoop, recvSome, sendAll, withServer)
import Tails.TLS.Codec (DecodeError (..))
import Tails.TLS.Handshake.Codec (decodeHandshake)
import Tails.TLS.Handshake.Types (Handshake (..))
import Tails.TLS.Record.Codec (decodeTLSPlainText)
import Tails.TLS.Record.Types (ContentType (Handshake), TLSPlainText (..))

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

          -- TODO: move this case to TLS/ ?
          case contentType record of
            Tails.TLS.Record.Types.Handshake -> do
              case decodeHandshake (fragment record) of
                Left err -> putStrLn $ "failed to decode handshake: " ++ show err
                Right (handshake, r) ->
                  if not $ BS.null r
                    then putStrLn $ "handshake decoded, but has trailing data: " ++ show (BS.length r)
                    else putStrLn $ "handshake decoded successfully: type=" ++ show (msgType handshake)
              pure ()
            _ -> pure ()
          loop' rest
        Left NeedMoreData -> loop buf
        Left (Malformed err) -> do
          putStrLn $ "malformed TLS record: " ++ show err
          pure ()
