module Tails.TLS.Handshake.Codec (decodeHandshake, decodeClientHello, encodeServerHello, encodeServerSupportedVersionExtension, encodeKeyShareServerHelloExtension, encodeHandshake) where

import Data.ByteString (ByteString)
import Data.Word (Word8)
import Tails.Bytes (Put, getBytes, getOpaque24, getOpaqueVector, getU16, getU24, getU8, putBytes, putOpaque24, putOpaqueVector, putU16, putU8, putVector, runPut)
import Tails.TLS.Codec (DecodeError (Malformed), Decoder (runDecoder), failDecode, wrapGet)
import Tails.TLS.Handshake.Types (CipherSuite (..), ClientHello (..), Extension (..), ExtensionType (..), Handshake (..), HandshakeType (..), KeyShareEntry (..), KeyShareServerHello (..), NamedGroup (..), ProtocolVersion (..), Random (..), ServerHello (..), ServerSupportedVersion (..))

decodeHandshake :: ByteString -> Either DecodeError (Handshake, ByteString)
decodeHandshake = runDecoder $ do
  rawType <- wrapGet getU8
  body <- wrapGet getOpaque24

  ht <- decodeHandshakeType rawType

  pure $
    Handshake
      { msgType = ht,
        msg = body
      }

encodeHandshake :: Handshake -> ByteString
encodeHandshake (Handshake ht body) = runPut $ do
  encodeHandshakeType ht
  putOpaque24 body

encodeHandshakeType :: HandshakeType -> Put ()
encodeHandshakeType ht = putU8 $ case ht of
  ClientHelloType -> 1
  ServerHelloType -> 2

decodeHandshakeType :: Word8 -> Decoder HandshakeType
decodeHandshakeType b =
  case b of
    1 -> pure ClientHelloType
    2 -> pure ServerHelloType
    _ -> failDecode $ Malformed $ "Unknown HandshakeType: " ++ show b

decodeClientHello :: ByteString -> Either DecodeError (ClientHello, ByteString)
decodeClientHello = runDecoder $ do
  _ <- wrapGet getU16 -- legacy_version
  rawRandom <- wrapGet $ getBytes 32
  sid <- wrapGet $ getOpaqueVector 0 32 -- legacy_session_id
  rawCypherSuites <- wrapGet $ getOpaqueVector 2 ((2 ^ 16) - 1)
  _ <- wrapGet $ getOpaqueVector 1 ((2 ^ 8) - 1) -- legacy_compression_methods
  rawExtensions <- wrapGet $ getOpaqueVector 8 ((2 ^ 16) - 1)

  pure $
    ClientHello
      { random = Random rawRandom,
        legacySessionId = sid,
        cipherSuites = [],
        extensions = []
      }

encodeServerHello :: ServerHello -> ByteString
encodeServerHello (ServerHello randomSH legacySessionIdEcho cipherSuiteSH extensionsSH) = runPut $ do
  putProtocolVersion TLS1_2
  putRandom randomSH
  putOpaqueVector 0 32 legacySessionIdEcho
  putCypherSuite cipherSuiteSH
  putU8 0 -- legacy_compression_method
  putVector 6 ((2 ^ 16) - 1) putExtension extensionsSH

putRandom :: Random -> Put ()
putRandom (Random bs) = putBytes bs

putCypherSuite :: CipherSuite -> Put ()
putCypherSuite cs = case cs of
  TLS_AES_256_GCM_SHA384 -> putU16 0x1302

putExtension :: Extension -> Put ()
putExtension (Extension et body) = do
  putExtensionType et
  putOpaqueVector 0 ((2 ^ 16) - 1) body

putExtensionType :: ExtensionType -> Put ()
putExtensionType et = case et of
  SupportedVersionsType -> putU16 43
  KeyShareType -> putU16 51

encodeServerSupportedVersionExtension :: ServerSupportedVersion -> ByteString
encodeServerSupportedVersionExtension (ServerSupportedVersion version) = runPut $ do
  putProtocolVersion version

putProtocolVersion :: ProtocolVersion -> Put ()
putProtocolVersion et = case et of
  TLS1_2 -> putU16 0x0303
  TLS1_3 -> putU16 0x0304

encodeKeyShareServerHelloExtension :: KeyShareServerHello -> ByteString
encodeKeyShareServerHelloExtension (KeyShareServerHello entry) = runPut $ do
  putKeyShareEntry entry

putKeyShareEntry :: KeyShareEntry -> Put ()
putKeyShareEntry (KeyShareEntry group keyExchange) = do
  putNamedGroup group
  putOpaqueVector 1 ((2 ^ 16) - 1) keyExchange

putNamedGroup :: NamedGroup -> Put ()
putNamedGroup ng = putU16 $ case ng of
  X25519 -> 0x001d
