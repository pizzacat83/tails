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
    legacySessionId :: ByteString,
    cipherSuites :: [CipherSuite],
    extensions :: [Extension]
  }
  deriving (Show, Eq)

-- Should we move ClientHello to a different module?

-- Random is 32 bytes
-- TODO: What's the best way to represent it?
newtype Random = Random ByteString deriving (Show, Eq)

-- https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
data Extension = Extension
  { extensionType :: ExtensionType,
    extensionData :: ByteString
  }
  deriving (Show, Eq)

data ExtensionType
  = SupportedVersionsType
  | KeyShareType
  -- and more...
  deriving (Show, Eq)

data CipherSuite = TLS_AES_256_GCM_SHA384 deriving (Show, Eq)

-- There are many more cipher suites, but for now we only define one

-- https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1
newtype ClientSupportedVersions = ClientSupportedVersions [ProtocolVersion]
  deriving (Show, Eq)

newtype ServerSupportedVersion = ServerSupportedVersion ProtocolVersion
  deriving (Show, Eq)

data ProtocolVersion = TLS1_2 | TLS1_3 deriving (Show, Eq)

-- https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3
data ServerHello = ServerHello
  { -- legacyVersion
    randomSH :: Random, -- How can we avoid name clash?
    legacySessionIdEcho :: ByteString,
    cipherSuiteSH :: CipherSuite,
    -- legacyCompressionMethod
    extensionsSH :: [Extension]
  }

-- https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8
data KeyShareServerHello = KeyShareServerHello
  { serverShare :: KeyShareEntry
  }

data KeyShareEntry = KeyShareEntry
  { group :: NamedGroup,
    keyExchange :: ByteString
  }

data NamedGroup = X25519 deriving (Show, Eq)

-- There are many more named groups, but for now we only define one
