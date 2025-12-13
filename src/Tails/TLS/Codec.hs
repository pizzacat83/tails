module Tails.TLS.Codec
  ( Decoder (..),
    DecodeError (..),
    wrapGet,
    failDecode,
  )
where

import Data.ByteString (ByteString)
import Tails.Bytes (Get (runGet))

newtype Decoder a = Decoder {runDecoder :: ByteString -> Either DecodeError (a, ByteString)}

data DecodeError = NeedMoreData | Malformed String deriving (Show)

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
