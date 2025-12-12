module Tails.TLS.Record.Codec where

import Data.ByteString
import qualified Data.ByteString as ByteString
import Data.Word (Word8)
import Tails.Bytes (DecodeError (..), Get (Get, runGet), Put, getBytes, getU16, getU8, putBytes, putU16, putU8, runPut)
import Tails.TLS.Record.Types (ContentType (..), TLSPlainText (..), contentType)

-- newtype DecodeError = DecodeError String deriving (Show)

decodeTLSPlainText :: ByteString -> Either DecodeError (TLSPlainText, ByteString)
decodeTLSPlainText = runGet $ do
  ctRaw <- getU8
  _ <- getU16 -- legacy_record_version, ignored in TLS 1.3
  len <- getU16
  frag <- getBytes (fromIntegral len)

  ct <- decodeContentType ctRaw

  pure $
    TLSPlainText
      { contentType = ct,
        fragment = frag
      }

encodeTLSPlainText :: TLSPlainText -> ByteString
encodeTLSPlainText (TLSPlainText ct frag) = runPut $ do
  encodeContentType ct
  putU16 0x0303 -- legacy_record_version for TLS 1.3
  putU16 $ fromIntegral $ ByteString.length frag
  putBytes frag

decodeContentType :: Word8 -> Get ContentType
decodeContentType b =
  case b of
    0 -> pure Invalid
    20 -> pure ChangeCipherSpec
    21 -> pure Alert
    22 -> pure Handshake
    23 -> pure ApplicationData
    _ -> failGet $ DecodeError $ "Unknown ContentType: " ++ show b

encodeContentType :: ContentType -> Put ()
encodeContentType ct =
  putU8 $ case ct of
    Invalid -> 0
    ChangeCipherSpec -> 20
    Alert -> 21
    Handshake -> 22
    ApplicationData -> 23

failGet :: DecodeError -> Get a
failGet err = Get $ \_ -> Left err
