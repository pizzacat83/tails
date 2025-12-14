module Tails.TLS.Crypto.KeySchedule where

import Crypto.Hash (Digest, HashAlgorithm (hashDigestSize))
import qualified Crypto.Hash
import qualified Crypto.Hash.Algorithms
import qualified Crypto.MAC.HMAC
import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import Data.List (unfoldr)
import Tails.Bytes (putOpaqueVector, putU16, runPut)

deriveSecrets psk ecdhe = do
  let earlySecret = hkdfExtract psk BS.empty

  let derivedSecret = deriveSecret earlySecret (B8.pack "derived") []

  -- we need ecdhe here

  let handshakeSecret = hkdfExtract ecdhe derivedSecret

  -- oh! we need client and server hello messages for transcript hash
  -- TODO: Need a state machine or a cool monad?
  let clientHello = undefined
  let serverHello = undefined
  let clientHandshakeTrafficSecret = deriveSecret handshakeSecret (B8.pack "c hs traffic") [clientHello, serverHello]

  let serverHandshakeTrafficSecret = deriveSecret handshakeSecret (B8.pack "s hs traffic") [clientHello, serverHello]

  let derivedSecret2 = deriveSecret handshakeSecret (B8.pack "derived") []

  let masterSecret = hkdfExtract BS.empty derivedSecret2

  let encryptedExtensions = undefined
  let certificate = undefined
  let certificateVerify = undefined
  let serverFinished = undefined

  -- We need more messages here!!

  let clientHandshakeTrafficSecret = deriveSecret masterSecret (B8.pack "c ap traffic") [clientHello, serverHello, encryptedExtensions, certificate, certificateVerify, serverFinished]

  pure ()

-- Crypto DSL
-- TODO: Move these to a proper Crypto module

-- TODO: Very not confident about the correctness. Want tests!!

deriveSecret secret label messages =
  hkdfExpandLabel secret label (transcriptHash messages) (hashDigestSize Crypto.Hash.Algorithms.SHA384)

transcriptHash messages =
  hash (BS.concat messages)

hkdfExpandLabel secret label context length =
  hkdfExpand secret hkdfLabel length
  where
    hkdfLabel = runPut $ do
      putU16 (fromIntegral length)
      putOpaqueVector 7 255 (B8.pack "tls13 " <> label)
      putOpaqueVector 0 255 context

hkdfExpand :: ByteString -> ByteString -> Int -> ByteString
hkdfExpand prk info length =
  BS.take length $ BS.concat blocks
  where
    blocks :: [ByteString]
    blocks = unfoldr go (1, BS.empty)
    go (i, t) =
      if i > stepCount
        then Nothing
        else
          let block = step i t
           in Just (block, (i + 1, block))
    step i t = hmacHash prk $ BS.concat [t, info, BS.singleton (fromIntegral i)]
    stepCount = (length + hashLen - 1) `div` hashLen
    hashLen = hashDigestSize Crypto.Hash.Algorithms.SHA384

hkdfExtract = hmacHash

hash :: ByteString -> ByteString
hash msg =
  let digest = Crypto.Hash.hash msg :: Crypto.Hash.Digest Crypto.Hash.Algorithms.SHA384
   in BA.convert digest :: ByteString

hmacHash :: ByteString -> ByteString -> ByteString
hmacHash key msg =
  let digest = Crypto.MAC.HMAC.hmacGetDigest (Crypto.MAC.HMAC.hmac key msg :: Crypto.MAC.HMAC.HMAC Crypto.Hash.Algorithms.SHA384)
   in BA.convert digest :: ByteString
