module Tails.Bytes (Get (..), getU8, DecodeError (..)) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8)

newtype DecodeError = DecodeError String deriving (Show)

newtype Get a = Get {runGet :: ByteString -> Either DecodeError (a, ByteString)}

getU8 :: Get Word8
getU8 = Get $ \bs ->
  case BS.uncons bs of
    Nothing -> Left $ DecodeError "getU8: no more input"
    Just (w, rest) -> Right (w, rest)
