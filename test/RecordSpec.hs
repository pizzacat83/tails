module RecordSpec (tests) where

import qualified Data.ByteString as BS
import Tails.TLS.Record.Codec (decodeTLSPlainText, encodeTLSPlainText)
import Tails.TLS.Record.Types (ContentType (..), TLSPlainText (..))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertFailure, testCase, (@?=))

tests :: TestTree
tests =
  testGroup
    "Record"
    [ testCase "roundtrip" test_record_roundtrip
    ]

test_record_roundtrip :: IO ()
test_record_roundtrip = do
  let r =
        TLSPlainText
          { contentType = Handshake,
            fragment = BS.pack [0x01, 0x02, 0x03, 0x04]
          }
  let bs = encodeTLSPlainText r

  case decodeTLSPlainText bs of
    Left err -> assertFailure $ "Decoding failed: " ++ show err
    Right (r', rest) -> do
      r' @?= r
      rest @?= BS.empty
