module Tails.TLS.Record.Codec where

import Data.ByteString
import qualified Data.ByteString as ByteString
import Data.Word (Word8)
import Tails.Bytes (Get (Get, runGet), Put, getBytes, getU16, getU8, putBytes, putU16, putU8, runPut)
import qualified Tails.Bytes as Bytes
import Tails.TLS.Record.Types (ContentType (..), TLSPlainText (..), contentType)

newtype Decoder a = Decoder {runDecoder :: ByteString -> Either DecodeError (a, ByteString)}

data DecodeError = NeedMoreData | Malformed String deriving (Show)

decodeTLSPlainText :: ByteString -> Either DecodeError (TLSPlainText, ByteString)
decodeTLSPlainText = runDecoder $ do
  ctRaw <- wrapGet getU8
  _ <- wrapGet getU16 -- legacy_record_version, ignored in TLS 1.3
  len <- wrapGet getU16
  frag <- wrapGet $ getBytes (fromIntegral len)
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

decodeContentType :: Word8 -> Decoder ContentType
decodeContentType b =
  case b of
    0 -> pure Invalid
    20 -> pure ChangeCipherSpec
    21 -> pure Alert
    22 -> pure Handshake
    23 -> pure ApplicationData
    _ -> failDecode $ Malformed $ "Unknown ContentType: " ++ show b

encodeContentType :: ContentType -> Put ()
encodeContentType ct =
  putU8 $ case ct of
    Invalid -> 0
    ChangeCipherSpec -> 20
    Alert -> 21
    Handshake -> 22
    ApplicationData -> 23

-- TODO: I think the monad stuff are pretty refactorable...

wrapGet :: Get a -> Decoder a
wrapGet g = Decoder $ \bs ->
  case runGet g bs of
    Left _ -> Left NeedMoreData
    Right (a, rest) -> Right (a, rest)

failDecode :: DecodeError -> Decoder a
failDecode err = Decoder $ \_ -> Left err

instance Functor Decoder where
  fmap f (Decoder g) = Decoder $ \bs ->
    case g bs of
      Left err -> Left err
      Right (a, rest) -> Right (f a, rest)

instance Applicative Decoder where
  pure x = Decoder $ \bs -> Right (x, bs)
  (Decoder f) <*> (Decoder g) = Decoder $ \bs ->
    case f bs of
      Left err -> Left err
      Right (func, rest) -> case g rest of
        Left err -> Left err
        Right (a, rest') -> Right (func a, rest')

instance Monad Decoder where
  (Decoder g) >>= f = Decoder $ \bs ->
    case g bs of
      Left err -> Left err
      Right (a, rest) ->
        let (Decoder g') = f a
         in g' rest
