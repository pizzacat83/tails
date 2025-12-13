module Tails.TLS.Handshake.Codec (decodeHandshake) where

import Data.ByteString (ByteString)
import Data.Word (Word8)
import Tails.Bytes (getBytes, getU24, getU8)
import Tails.TLS.Codec (DecodeError (Malformed), Decoder (runDecoder), failDecode, wrapGet)
import Tails.TLS.Handshake.Types (Handshake (..), HandshakeType (..))

decodeHandshake :: ByteString -> Either DecodeError (Handshake, ByteString)
decodeHandshake = runDecoder $ do
  rawType <- wrapGet getU8
  len <- wrapGet getU24
  body <- wrapGet $ getBytes (fromIntegral len)

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
