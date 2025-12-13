module Tails.TLS.Handshake.Codec (decodeHandshake, decodeClientHello) where

import Data.ByteString (ByteString)
import Data.Word (Word8)
import Tails.Bytes (getBytes, getOpaque24, getOpaqueVector, getU16, getU24, getU8)
import Tails.TLS.Codec (DecodeError (Malformed), Decoder (runDecoder), failDecode, wrapGet)
import Tails.TLS.Handshake.Types (ClientHello (..), Handshake (..), HandshakeType (..), Random (..))

decodeHandshake :: ByteString -> Either DecodeError (Handshake, ByteString)
decodeHandshake = runDecoder $ do
  rawType <- wrapGet getU8
  body <- wrapGet getOpaque24

  ht <- decodeHandshakeType rawType

  pure $
    Handshake
      { msgType = ht,
        msg = body
      }

decodeHandshakeType :: Word8 -> Decoder HandshakeType
decodeHandshakeType b =
  case b of
    1 -> pure ClientHelloType
    2 -> pure ServerHelloType
    _ -> failDecode $ Malformed $ "Unknown HandshakeType: " ++ show b

decodeClientHello :: ByteString -> Either DecodeError (ClientHello, ByteString)
decodeClientHello = runDecoder $ do
  _ <- wrapGet getU16 -- legacy_version
  rawRandom <- wrapGet $ getBytes 32
  _ <- wrapGet $ getOpaqueVector 0 32 -- legacy_session_id
  rawCypherSuites <- wrapGet $ getOpaqueVector 2 ((2 ^ 16) - 1)
  _ <- wrapGet $ getOpaqueVector 1 ((2 ^ 8) - 1) -- legacy_compression_methods
  rawExtensions <- wrapGet $ getOpaqueVector 8 ((2 ^ 16) - 1)

  pure $
    ClientHello
      { random = Random rawRandom,
        cipherSuites = [],
        extensions = []
      }
