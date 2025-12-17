module Tails.App.Server (runServer, handleConnEcho) where

import Control.Monad (unless)
import qualified Crypto.Cipher.AES
import qualified Crypto.Cipher.Types
import Crypto.ConstructHash.MiyaguchiPreneel (compute)
import Crypto.ECC (SharedSecret (SharedSecret))
import qualified Crypto.ECC
import Crypto.Error (CryptoFailable (..))
import qualified Crypto.PubKey.ECIES
import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import Data.Data (Proxy (..))
import Data.Word (Word64)
import GHC.IO.Encoding (BufferCodec (encode))
import Network.Socket (Socket)
import Numeric (showHex)
import System.Posix.Internals (o_BINARY)
import Tails.Bytes (putBytes, putU64, runPut)
import Tails.TCP (acceptLoop, recvSome, sendAll, withServer)
import Tails.TLS.Codec (DecodeError (..))
import Tails.TLS.Crypto.KeySchedule (deriveSecret, deriveSecrets, hkdfExpandLabel)
import Tails.TLS.Handshake.Codec (decodeClientHello, decodeHandshake, encodeHandshake, encodeKeyShareServerHelloExtension, encodeServerHello, encodeServerSupportedVersionExtension)
import Tails.TLS.Handshake.Types (Certificate (..), CertificateEntry (CertificateEntry, certificateData, certificateExtensions), CertificateVerify (..), CipherSuite (..), ClientHello (ClientHello, legacySessionId), EncryptedExtensions (EncryptedExtensions), Extension (Extension), ExtensionType (KeyShareType, SupportedVersionsType), Finished (..), Handshake (..), HandshakeType (ClientHelloType, ServerHelloType), KeyShareEntry (..), KeyShareServerHello (..), NamedGroup (..), ProtocolVersion (..), Random (Random), ServerHandshakeContext (..), ServerHello (..), ServerSupportedVersion (..), SignatureScheme (RSS_PSS_RSAE_SHA256))
import Tails.TLS.Record.Codec (decodeTLSPlainText, encodeTLSPlainText)
import Tails.TLS.Record.Types (ContentType (Handshake), TLSCiphertext (..), TLSInnerPlaintext (..), TLSPlainText (..))

runServer :: IO ()
runServer =
  withServer "127.0.0.1" "8443" $ \sock -> do
    putStrLn "listening on 127.0.0.1:8443"
    acceptLoop sock handleConnEcho

handleConnEcho :: Socket -> IO ()
handleConnEcho sock = do
  putStrLn "client connected"
  loop BS.empty
  putStrLn "client disconnected"
  where
    loop buf = do
      bs <- recvSome sock 4096
      if BS.null bs
        then pure ()
        else do
          putStrLn $ "received " ++ show (BS.length bs) ++ " bytes"
          loop' $ BS.append buf bs

    loop' buf =
      case decodeTLSPlainText buf of
        Right (record, rest) -> do
          putStrLn $
            "decoded TLS record: type="
              ++ show (contentType record)
              ++ " length="
              ++ show (BS.length (fragment record))

          unless (contentType record == Tails.TLS.Record.Types.Handshake) $
            ioError $
              userError $
                "handshake record expected but got" ++ show (contentType record)

          (handshake, rest) <- either (ioError . userError . \err -> "failed to decode handshake" ++ show err) pure $ decodeHandshake (fragment record)
          unless (BS.null rest) $ ioError $ userError $ "handshake decoded, but has trailing data: " ++ show (BS.length rest)
          putStrLn $ "handshake decoded successfully: type=" ++ show (msgType handshake)

          unless (msgType handshake == ClientHelloType) $
            ioError $
              userError
                "not a ClientHello message"

          putStrLn "ClientHello received"
          (clientHello, rest) <- either (ioError . userError . \err -> "failed to decode ClientHello" ++ show err) pure $ decodeClientHello (msg handshake)

          putStrLn "Sending ServerHello in response"
          sendAll sock $
            encodeTLSPlainText $
              TLSPlainText
                { contentType = Tails.TLS.Record.Types.Handshake,
                  fragment =
                    encodeHandshake $
                      Tails.TLS.Handshake.Types.Handshake
                        { msgType = ServerHelloType,
                          msg =
                            encodeServerHello $
                              ServerHello
                                { randomSH = Random (BS.replicate 32 0x83), -- TODO: use real randomness
                                  legacySessionIdEcho = legacySessionId clientHello,
                                  cipherSuiteSH = TLS_AES_256_GCM_SHA384,
                                  extensionsSH =
                                    -- it would be nice if we have a type safe way so that the correct pair of type and encoder is used
                                    [ Extension SupportedVersionsType $ encodeServerSupportedVersionExtension $ ServerSupportedVersion TLS1_3,
                                      Extension KeyShareType $
                                        encodeKeyShareServerHelloExtension $
                                          KeyShareServerHello $
                                            KeyShareEntry
                                              { group = X25519,
                                                keyExchange = BS.replicate 32 0x84 -- TODO: use real key exchange data
                                              }
                                    ]
                                }
                        }
                }

          -- TODO: send EncryptedExtensions
          -- TODO: send Certificate
          -- TODO: send CertificateVerify
          -- TODO: send Finished
          -- TODO: receive ClientFinished
          -- TODO: receive ApplicationData

          -- it would be nice if we can print the sent and received data without WireShark, but how can we design that, considering that a meaningful data (e.g. Handshake) can split across multiple chunks of the envelope?

          loop' rest
        Left NeedMoreData -> loop buf
        Left (Malformed err) -> do
          ioError $ userError $ "malformed TLS record: " ++ show err

handleConn = do
  clientHello <- recvClientHello
  -- Note: we need the raw bytestring for transcript hash!

  let exchangedClientX25519PubKey = undefined -- can be extracted from clientHello!
  let (exchangedServerX25519PubKey, exchangedServerX25519PrivKey) = undefined

  let sharedSecret = computeSharedSecretX25519 exchangedClientX25519PubKey exchangedServerX25519PrivKey

  let serverHello = makeServerHello
  sendServerHello serverHello

  -- Hereafter, messages are encrypted!
  -- How should we deal with encryption keys?
  let keyScheduleResult = proceedKeySchedule state sharedSecret -- sharedSecret が手に入ったので追加のシークレットが得られるぞの気持ち
  let serverHandshakeTrafficSecret = undefined -- TODO: derive from key schedule
  let serverWriteKey = hkdfExpandLabel serverHandshakeTrafficSecret (B8.pack "key") BS.empty aes256KeySize
  let serverWriteIV = hkdfExpandLabel serverHandshakeTrafficSecret (B8.pack "iv") BS.empty aes256IVSize

  -- In our toy implementation, we just send empty extensions
  let encryptedExtensions = EncryptedExtensions []
  sendEncryptedExtensions encryptedExtensions

  let certificate =
        Certificate
          { certificateRequestContext = BS.empty,
            certificateList =
              [ CertificateEntry -- TODO: how to load real certificate?
                  { certificateData = BS.empty,
                    certificateExtensions = []
                  }
              ]
          }
  sendCertificate certificate

  certificateVerify <- makeCertificateVerify
  sendCertificateVerify certificateVerify

  -- TODO: need to be computed from previous data
  let serverFinished = Finished {verifyData = BS.empty}
  sendFinished serverFinished

  clientFinished <- recvClientFinished

  runApp
  where
    sendEncryptedExtensions encryptedExtensions = do
      let writeKey = undefined
      let iv = undefined
      let protectedRecord =
            protectRecord writeKey iv $
              TLSInnerPlaintext
                { content =
                    encodeHandshake $
                      Tails.TLS.Handshake.Types.Handshake
                        { msgType = EncryptedExtensionsType,
                          msg = encodeEncryptedExtensions encryptedExtensions
                        },
                  innerContentType = Tails.TLS.Record.Types.Handshake
                  -- padding?
                }
      sendAll sock $ encodeTLSCiphertext protectedRecord

    protectRecord :: ByteString -> ByteString -> TLSInnerPlaintext -> TLSCiphertext
    protectRecord writeKey iv plaintext = do
      -- TODO: how to manage sequence number? Since it increments per record (including non-encrypted ones), we should track the state outside the protection mechanism
      let nonce = calculatePerRecordNonce iv sequenceNumber
      -- TODO: need data for additional authenticated data
      pure $ TLSCiphertext $ aeadEncrypt writeKey nonce additionalData plaintext

    makeCertificateVerify = do
      let signedContent = transcriptHash [handshakeContext, certificate]

      let signedPayload =
            BS.concat
              [ BS.replicate 64 0x20,
                contextString,
                BS.singleton 0x00,
                signedContent
              ]
            where
              contextString = B8.pack "TLS 1.3, server CertificateVerify"

      sig <- undefined
      pure $
        CertificateVerify
          { algorithm = RSS_PSS_RSAE_SHA256,
            signature = sig
          }

-- Where should this be defined?
packServerHandshakeContext :: ServerHandshakeContext -> ByteString
packServerHandshakeContext (ServerHandshakeContext ch sh ee) =
  BS.concat [ch, sh, ee]

-- Need to move this to Crypto/
type X25519PublicKey = Crypto.ECC.Point Crypto.ECC.Curve_X25519

type X25519PrivateKey = Crypto.ECC.Scalar Crypto.ECC.Curve_X25519

computeSharedSecretX25519 :: X25519PublicKey -> X25519PrivateKey -> Either String ByteString
computeSharedSecretX25519 pub pri =
  case Crypto.PubKey.ECIES.deriveDecrypt (Proxy :: Proxy Crypto.ECC.Curve_X25519) pub pri of
    CryptoPassed (SharedSecret s) -> Right $ BA.convert s
    CryptoFailed err -> Left $ show err

aeadEncrypt key nonce plaintext associatedData = do
  aead <- Crypto.Cipher.Types.aeadInit Crypto.Cipher.Types.AEAD_GCM key nonce

  -- An authentication tag with a length of 16 octets (128 bits) is used.
  -- http://datatracker.ietf.org/doc/html/rfc5116#section-5.1
  let tagLength = 16
  let (tag, ciphertext) = Crypto.Cipher.Types.aeadSimpleEncrypt aead associatedData plaintext tagLength

  -- The AEAD_AES_{128,256}_GCM ciphertext is formed by appending the authentication tag provided as an output to the GCM encryption operation to the ciphertext that is output by that operation.
  return (ciphertext <> BA.convert tag :: ByteString)

calculatePerRecordNonce :: ByteString -> Word64 -> ByteString
calculatePerRecordNonce iv seqNum =
  --  1. The 64-bit record sequence number is encoded in network byte order and padded to the left with zeros to iv_length.
  let seqNumBytes = runPut $ do
        putU64 seqNum
        putBytes (BS.replicate (ivlength - 8) 0x00)
   in --  2. The padded sequence number is XORed with either the static client_write_iv or server_write_iv (depending on the role).
      BS.pack $
        BS.zipWith xor iv seqNumBytes
  where
    ivlength = aes256IVSize

-- a veeeeeeery simple HTTP app.
-- TODO: Tails.TLS should provide send/recv interface to the app layer. Too restrictive now!
appHandle :: ByteString -> ByteString
appHandle req =
  if B8.pack "GET / " `BS.isPrefixOf` req
    then
      B8.pack $
        "HTTP/1.1 200 OK\r\n"
          ++ "Content-Length: 13\r\n"
          ++ "Content-Type: text/plain\r\n"
          ++ "\r\n"
          ++ "Hello over TLS!"
    else
      B8.pack $
        "HTTP/1.1 404 Not Found\r\n"
          ++ "Content-Length: 9\r\n"
          ++ "Content-Type: text/plain\r\n"
          ++ "\r\n"
          ++ "Not Found"

-- TODO: move this to the Crypto module?
aes256KeySize = 32

aes256IVSize = 12
