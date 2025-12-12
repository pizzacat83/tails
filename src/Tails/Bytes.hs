module Tails.Bytes (Get (..), getU8, getU16, getBytes, DecodeError (..), Put (..)) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8)
import GHC.Word (Word16)

newtype DecodeError = DecodeError String deriving (Show)

newtype Get a = Get {runGet :: ByteString -> Either DecodeError (a, ByteString)}

getU8 :: Get Word8
getU8 = Get $ \bs ->
  case BS.uncons bs of
    Nothing -> Left $ DecodeError "getU8: no more input"
    Just (w, rest) -> Right (w, rest)

newtype Put a = Put {runPut :: a -> ByteString}

instance Functor Get where
  fmap f (Get g) = Get $ \bs -> case g bs of
    Left err -> Left err
    Right (a, rest) -> Right (f a, rest)

instance Applicative Get where
  pure x = Get $ \bs -> Right (x, bs)
  (Get f) <*> (Get g) = Get $ \bs -> case f bs of
    Left err -> Left err
    Right (func, rest) -> case g rest of
      Left err2 -> Left err2
      Right (a, rest2) -> Right (func a, rest2)

instance Monad Get where
  return = pure
  (Get g) >>= f = Get $ \bs -> case g bs of
    Left err -> Left err
    Right (a, rest) -> runGet (f a) rest

getU16 :: Get Word16
getU16 = undefined

getBytes :: Int -> Get ByteString
getBytes n = undefined
