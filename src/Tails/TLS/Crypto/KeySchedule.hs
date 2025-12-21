{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}

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

newtype EarlySecret = EarlySecret ByteString deriving (Show, Eq)

newtype HandshakeSecret = HandshakeSecret ByteString deriving (Show, Eq)

newtype MasterSecret = MasterSecret ByteString deriving (Show, Eq)

deriveEarlySecret :: ByteString -> EarlySecret
deriveEarlySecret psk = EarlySecret $ hkdfExtract psk zeroVector

deriveHandshakeSecret :: EarlySecret -> ByteString -> HandshakeSecret
deriveHandshakeSecret (EarlySecret es) ecdhe =
  let d = deriveSecret es (B8.pack "derived") thEmpty
   in HandshakeSecret $ hkdfExtract ecdhe d

deriveClientHandshakeTrafficSecret :: HandshakeSecret -> THContext 'TS_SH -> ByteString
deriveClientHandshakeTrafficSecret (HandshakeSecret hs) ctx =
  deriveSecret hs (B8.pack "c hs traffic") ctx

deriveServerHandshakeTrafficSecret :: HandshakeSecret -> THContext 'TS_SH -> ByteString
deriveServerHandshakeTrafficSecret (HandshakeSecret hs) ctx =
  deriveSecret hs (B8.pack "s hs traffic") ctx

deriveMasterSecret :: HandshakeSecret -> MasterSecret
deriveMasterSecret (HandshakeSecret hs) =
  let derivedSecret = deriveSecret hs (B8.pack "derived") thEmpty
   in MasterSecret $ hkdfExtract zeroVector derivedSecret

deriveClientApplicationTrafficSecret :: MasterSecret -> THContext 'TS_SF -> ByteString
deriveClientApplicationTrafficSecret (MasterSecret ms) ctx =
  deriveSecret ms (B8.pack "c ap traffic") ctx

deriveServerApplicationTrafficSecret :: MasterSecret -> THContext 'TS_SF -> ByteString
deriveServerApplicationTrafficSecret (MasterSecret ms) ctx =
  deriveSecret ms (B8.pack "s ap traffic") ctx

-- "0" indicates a string of Hash.length bytes set to zero.
zeroVector :: ByteString
zeroVector = BS.replicate (hashDigestSize Crypto.Hash.Algorithms.SHA384) 0

-- TODO: Move to appropriate modules?

data TSPhase
  = TS_EMPTY
  | TS_SH
  | TS_CR
  | TS_SF
  | TS_CF
  deriving (Show, Eq)

newtype THContext (p :: TSPhase) = THContext (Crypto.Hash.Context Crypto.Hash.Algorithms.SHA384)

transcriptHash :: THContext p -> ByteString
transcriptHash (THContext ctx) = BA.convert $ Crypto.Hash.hashFinalize ctx

thEmpty :: THContext 'TS_EMPTY
thEmpty = THContext (Crypto.Hash.hashInit :: Crypto.Hash.Context Crypto.Hash.Algorithms.SHA384)

makeTHUntilServerHello :: ClientHelloRaw -> ServerHelloRaw -> THContext 'TS_SH
makeTHUntilServerHello (ClientHelloRaw ch) (ServerHelloRaw sh) =
  THContext $ Crypto.Hash.hashUpdate (Crypto.Hash.hashInit :: Crypto.Hash.Context Crypto.Hash.Algorithms.SHA384) (ch <> sh)

makeTHUntilCertificateRequest :: THContext 'TS_SH -> EncryptedExtensionsRaw -> THContext 'TS_CR
makeTHUntilCertificateRequest (THContext ctx) (EncryptedExtensionsRaw ee) =
  THContext $ Crypto.Hash.hashUpdate ctx ee

makeTHUntilServerFinished :: THContext 'TS_CR -> ServerCertificateRaw -> ServerCertificateVerifyRaw -> ServerFinishedRaw -> THContext 'TS_SF
makeTHUntilServerFinished (THContext ctx) (ServerCertificateRaw cert) (CertificateVerifyRaw cv) (FinishedRaw fin) =
  THContext $ Crypto.Hash.hashUpdate (Crypto.Hash.hashUpdate (Crypto.Hash.hashUpdate ctx cert) cv) fin

-- The following types are the encoded form of the Handshake type.
-- TODO: Want to ensure this property via types?

newtype ClientHelloRaw = ClientHelloRaw ByteString deriving (Show, Eq)

newtype ServerHelloRaw = ServerHelloRaw ByteString deriving (Show, Eq)

newtype EncryptedExtensionsRaw = EncryptedExtensionsRaw ByteString deriving (Show, Eq)

newtype ServerCertificateRaw = ServerCertificateRaw ByteString deriving (Show, Eq)

newtype ServerCertificateVerifyRaw = CertificateVerifyRaw ByteString deriving (Show, Eq)

newtype ServerFinishedRaw = FinishedRaw ByteString deriving (Show, Eq)

-- Crypto DSL
-- TODO: Move these to a proper Crypto module

-- TODO: Very not confident about the correctness. Want tests!!

-- Unlike the RFC definition, the third argument is the hash context of the messages, not the messages themselves.
deriveSecret :: ByteString -> ByteString -> THContext p -> ByteString
deriveSecret secret label msgContext =
  hkdfExpandLabel secret label (transcriptHash msgContext) (hashDigestSize Crypto.Hash.Algorithms.SHA384)

-- transcriptHash messages =
--   hash (BS.concat messages)

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
