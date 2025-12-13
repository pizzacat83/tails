module Tails.App.Server (runServer, handleConnEcho) where

import Control.Monad (unless)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import Network.Socket (Socket)
import Numeric (showHex)
import Tails.TCP (acceptLoop, recvSome, sendAll, withServer)
import Tails.TLS.Codec (DecodeError (..))
import Tails.TLS.Handshake.Codec (decodeClientHello, decodeHandshake, encodeHandshake, encodeKeyShareServerHelloExtension, encodeServerHello, encodeServerSupportedVersionExtension)
import Tails.TLS.Handshake.Types (CipherSuite (..), ClientHello (ClientHello, legacySessionId), Extension (Extension), ExtensionType (KeyShareType, SupportedVersionsType), Handshake (..), HandshakeType (ClientHelloType, ServerHelloType), KeyShareEntry (..), KeyShareServerHello (..), NamedGroup (..), ProtocolVersion (..), Random (Random), ServerHello (..), ServerSupportedVersion (..))
import Tails.TLS.Record.Codec (decodeTLSPlainText, encodeTLSPlainText)
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

          putStrLn "Sending ServerHello in response"
          sendAll sock $
            encodeTLSPlainText $
              TLSPlainText
                { contentType = Tails.TLS.Record.Types.Handshake,
                  fragment =
                    encodeHandshake $
                      Tails.TLS.Handshake.Types.Handshake
                        { msgType = ServerHelloType,
                          msg =
                            encodeServerHello $
                              ServerHello
                                { randomSH = Random (BS.replicate 32 0x83), -- TODO: use real randomness
                                  legacySessionIdEcho = legacySessionId clientHello,
                                  cipherSuiteSH = TLS_AES_256_GCM_SHA384,
                                  extensionsSH =
                                    -- it would be nice if we have a type safe way so that the correct pair of type and encoder is used
                                    [ Extension SupportedVersionsType $ encodeServerSupportedVersionExtension $ ServerSupportedVersion TLS1_3,
                                      Extension KeyShareType $
                                        encodeKeyShareServerHelloExtension $
                                          KeyShareServerHello $
                                            KeyShareEntry
                                              { group = X25519,
                                                keyExchange = BS.replicate 32 0x84 -- TODO: use real key exchange data
                                              }
                                    ]
                                }
                        }
                }

          -- it would be nice if we can print the sent and received data without WireShark, but how can we design that, considering that a meaningful data (e.g. Handshake) can split across multiple chunks of the envelope?

          loop' rest
        Left NeedMoreData -> loop buf
        Left (Malformed err) -> do
          ioError $ userError $ "malformed TLS record: " ++ show err
