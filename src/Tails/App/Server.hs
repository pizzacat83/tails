module Tails.App.Server (runServer, handleConnEcho) where

import Control.Monad (unless)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import Network.Socket (Socket)
import Numeric (showHex)
import Tails.TCP (acceptLoop, recvSome, sendAll, withServer)
import Tails.TLS.Codec (DecodeError (..))
import Tails.TLS.Handshake.Codec (decodeClientHello, decodeHandshake)
import Tails.TLS.Handshake.Types (ClientHello (ClientHello), Handshake (..), HandshakeType (ClientHelloType), Random (Random))
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

          unless (contentType record == Tails.TLS.Record.Types.Handshake) $
            ioError $
              userError $
                "handshake record expected but got" ++ show (contentType record)

          (handshake, rest) <- either (ioError . userError . \err -> "failed to decode handshake" ++ show err) pure $ decodeHandshake (fragment record)
          unless (BS.null rest) $ ioError $ userError $ "handshake decoded, but has trailing data: " ++ show (BS.length rest)
          putStrLn $ "handshake decoded successfully: type=" ++ show (msgType handshake)

          unless (msgType handshake == ClientHelloType) $
            ioError $
              userError
                "not a ClientHello message"

          putStrLn "ClientHello received"
          (clientHello, rest) <- either (ioError . userError . \err -> "failed to decode ClientHello" ++ show err) pure $ decodeClientHello (msg handshake)
          putStrLn $ "ClientHello random: " ++ concatMap (`showHex` "") (BS.unpack $ let (ClientHello (Random r) _ _) = clientHello in r)
          loop' rest
        Left NeedMoreData -> loop buf
        Left (Malformed err) -> do
          ioError $ userError $ "malformed TLS record: " ++ show err
