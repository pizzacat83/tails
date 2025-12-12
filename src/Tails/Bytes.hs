{-# LANGUAGE InstanceSigs #-}

module Tails.Bytes
  ( Get (..),
    getU8,
    getU16,
    getBytes,
    DecodeError (..),
    Put,
    runPut,
    putU8,
    putU16,
    putBytes,
  )
where

import Data.Bits (Bits (shiftR, (.&.), (.|.)), shiftL)
import Data.ByteString (ByteString, toStrict)
import qualified Data.ByteString as BS
import Data.ByteString.Builder (Builder, toLazyByteString)
import qualified Data.ByteString.Builder as Builder
import Data.Word (Word8)
import GHC.Word (Word16)

newtype DecodeError = DecodeError String deriving (Show)

newtype Get a = Get {runGet :: ByteString -> Either DecodeError (a, ByteString)}

-- multi-byte numbers are big-endian
-- https://datatracker.ietf.org/doc/html/rfc8446#section-3.3

getU8 :: Get Word8
getU8 = Get $ \bs ->
  case BS.uncons bs of
    Nothing -> Left $ DecodeError "getU8: no more input"
    Just (w, rest) -> Right (w, rest)

getU16 :: Get Word16
getU16 = do
  b1 <- getU8
  b2 <- getU8
  pure $ (fromIntegral b1 `shiftL` 8) .|. fromIntegral b2

getBytes :: Int -> Get ByteString
getBytes n =
  Get $ \bs ->
    let (prefix, rest) = BS.splitAt n bs
     in if BS.length prefix < n
          then Left $ DecodeError "getBytes: not enough input"
          else Right (prefix, rest)

instance Functor Get where
  fmap f (Get g) = Get $ \bs -> case g bs of
    Left err -> Left err
    Right (a, rest) -> Right (f a, rest)

instance Applicative Get where
  pure x = Get $ \bs -> Right (x, bs)
  (<*>) :: Get (a -> b) -> Get a -> Get b
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

runPut :: Put a -> ByteString
runPut p =
  let (_, builder) = runPutInternal p
   in toStrict . toLazyByteString $ builder

newtype Put a = Put {runPutInternal :: (a, Builder)}

instance Functor Put where
  fmap f (Put (a, b)) = Put (f a, b)

instance Applicative Put where
  pure x = Put (x, mempty)
  (Put (f, b1)) <*> (Put (a, b2)) = Put (f a, b1 <> b2)

instance Monad Put where
  return = pure
  (Put (a, b1)) >>= f = let (Put (a', b2)) = f a in Put (a', b1 <> b2)

putU8 :: Word8 -> Put ()
putU8 w =
  Put ((), Builder.word8 w)

putU16 :: Word16 -> Put ()
putU16 w = do
  putU8 $ fromIntegral (w `shiftR` 8)
  putU8 $ fromIntegral (w .&. 0x00FF)

putBytes :: ByteString -> Put ()
putBytes bs = Put ((), Builder.byteString bs)
