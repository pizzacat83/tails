-- https://datatracker.ietf.org/doc/html/rfc8446#section-4

module Tails.TLS.Handshake.Types where

import Data.ByteString (ByteString)

data Handshake = Handshake
  { msgType :: HandshakeType,
    msg :: ByteString
  }
  deriving (Show, Eq)

data HandshakeType
  = ClientHelloType
  | ServerHelloType
  deriving (Show, Eq)

-- https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
data ClientHello = ClientHello
  { -- legacyVersion
    random :: Random,
    -- legacySessionId
    cipherSuites :: [CipherSuite],
    extensions :: [Extension]
  }
  deriving (Show, Eq)

-- Random is 32 bytes
-- TODO: What's the best way to represent it?
newtype Random = Random ByteString deriving (Show, Eq)

-- https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
data Extension = Extension () -- TODO
  deriving (Show, Eq)

data CipherSuite = TLS_AES_256_GCM_SHA384 deriving (Show, Eq)

-- There are many more cipher suites, but for now we only define one
