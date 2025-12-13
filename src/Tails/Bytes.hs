{-# LANGUAGE InstanceSigs #-}

module Tails.Bytes
  ( Get (..),
    getU8,
    getU16,
    getU24,
    getBytes,
    getOpaque24,
    getOpaqueVector,
    DecodeError (..),
    Put,
    runPut,
    putU8,
    putU16,
    putU24,
    putBytes,
    putOpaque24,
    putOpaqueVector,
    putVector,
  )
where

import Control.Monad (when)
import Data.Bits (Bits (shiftR, (.&.), (.|.)), shiftL)
import Data.ByteString (ByteString, toStrict)
import qualified Data.ByteString as BS
import Data.ByteString.Builder (Builder, toLazyByteString)
import qualified Data.ByteString.Builder as Builder
import Data.Word (Word8)
import GHC.Word (Word16)

newtype DecodeError = DecodeError () deriving (Show)

newtype Get a = Get {runGet :: ByteString -> Either DecodeError (a, ByteString)}

-- multi-byte numbers are big-endian
-- https://datatracker.ietf.org/doc/html/rfc8446#section-3.3

getU8 :: Get Word8
getU8 = Get $ \bs ->
  case BS.uncons bs of
    Nothing -> Left $ DecodeError ()
    Just (w, rest) -> Right (w, rest)

getU16 :: Get Word16
getU16 = do
  b1 <- getU8
  b2 <- getU8
  pure $ (fromIntegral b1 `shiftL` 8) .|. fromIntegral b2

getU24 :: Get Word
getU24 = do
  b1 <- getU8
  b2 <- getU8
  b3 <- getU8
  pure $ (fromIntegral b1 `shiftL` 16) .|. (fromIntegral b2 `shiftL` 8) .|. fromIntegral b3

getBytes :: Int -> Get ByteString
getBytes n =
  Get $ \bs ->
    let (prefix, rest) = BS.splitAt n bs
     in if BS.length prefix < n
          then Left $ DecodeError ()
          else Right (prefix, rest)

getOpaque24 :: Get ByteString
getOpaque24 = do
  len <- getU24
  getBytes (fromIntegral len)

-- https://datatracker.ietf.org/doc/html/rfc8446#section-3.4
getOpaqueVector :: Int -> Int -> Get ByteString
getOpaqueVector fl cl = do
  len <-
    if cl < 0x100
      then fromIntegral <$> getU8
      else
        if cl < 0x10000
          then fromIntegral <$> getU16
          else
            if cl < 0x1000000
              then fromIntegral <$> getU24
              else error "getOpaqueVector: ceiling too large"
  if len < fl || len > cl
    then undefined -- this is not "need more data". It's a malformed error!
    else getBytes (fromIntegral len)

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

putU8 :: Word8 -> Put ()
putU8 w =
  Put ((), Builder.word8 w)

putU16 :: Word16 -> Put ()
putU16 w = do
  putU8 $ fromIntegral (w `shiftR` 8)
  putU8 $ fromIntegral (w .&. 0x00FF)

putU24 :: Word -> Put ()
putU24 w = do
  putU8 $ fromIntegral (w `shiftR` 16)
  putU8 $ fromIntegral ((w `shiftR` 8) .&. 0x00FF)
  putU8 $ fromIntegral (w .&. 0x0000FF)

putBytes :: ByteString -> Put ()
putBytes bs = Put ((), Builder.byteString bs)

putOpaque24 :: ByteString -> Put ()
putOpaque24 bs = do
  putU24 (fromIntegral $ BS.length bs)
  putBytes bs

putOpaqueVector :: Int -> Int -> ByteString -> Put ()
putOpaqueVector fl cl bs = do
  let len = BS.length bs
  when (len < fl || len > cl) undefined -- this is an error on the sender side. what should we return in this case?

  -- TODO: clearer implementation?
  if cl < 0x100
    then putU8 (fromIntegral len)
    else
      if cl < 0x10000
        then putU16 (fromIntegral len)
        else
          if cl < 0x1000000
            then putU24 (fromIntegral len)
            else error "putOpaqueVector: ceiling too large"

  putBytes bs

putVector :: Int -> Int -> (a -> Put ()) -> [a] -> Put ()
putVector fl cl putElem elems = do
  -- calling runPut seems a bit awkward but can't find a better way. How does popular libraries do this?
  let payload = runPut $ do
        mapM_ putElem elems
  putOpaqueVector fl cl payload

instance Functor Put where
  fmap f (Put (a, b)) = Put (f a, b)

instance Applicative Put where
  pure x = Put (x, mempty)
  (Put (f, b1)) <*> (Put (a, b2)) = Put (f a, b1 <> b2)

instance Monad Put where
  return = pure
  (Put (a, b1)) >>= f = let (Put (a', b2)) = f a in Put (a', b1 <> b2)
