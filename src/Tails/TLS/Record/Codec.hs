module Tails.TLS.Record.Codec where

import Data.ByteString
import Data.Word (Word8)
import Tails.Bytes (DecodeError (..), Get (runGet), Put, getBytes, getU16, getU8)
import Tails.TLS.Record.Types (ContentType, TLSPlainText (..), contentType)

-- newtype DecodeError = DecodeError String deriving (Show)

decodeTLSPlainText :: ByteString -> Either DecodeError (TLSPlainText, ByteString)
decodeTLSPlainText = runGet getTLSPlainText
  where
    getTLSPlainText :: Get TLSPlainText
    getTLSPlainText = do
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
encodeTLSPlainText = undefined

decodeContentType :: Word8 -> Get ContentType
decodeContentType = undefined
