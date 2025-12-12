-- https://datatracker.ietf.org/doc/html/rfc8446#section-5.1

module Tails.TLS.Record.Types where

import Data.ByteString (ByteString)

data TLSPlainText = TLSPlainText
  { contentType :: ContentType,
    -- legacyRecordVersion :: ProtocolVersion, -- Ignored for TLS 1.3
    fragment :: ByteString
  }
  deriving (Show, Eq)

-- As per the spec,
data ContentType
  = Invalid
  | ChangeCipherSpec
  | Alert
  | Handshake
  | ApplicationData
  deriving (Show, Eq)
