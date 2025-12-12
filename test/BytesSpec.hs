module BytesSpec (tests) where

import qualified Data.ByteString as BS
import Tails.Bytes (DecodeError (DecodeError), getU8, runGet)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertFailure, testCase, (@?=))

tests :: TestTree
tests =
  testGroup
    "Bytes"
    [testCase "getU8" test_getU8]

test_getU8 :: IO ()
test_getU8 = do
  let input = BS.pack [0x42, 0x43, 0x44]
  case runGet getU8 input of
    Left (DecodeError err) -> assertFailure $ "runGet failed: " ++ err
    Right (val, rest) -> do
      val @?= 0x42
      rest @?= BS.pack [0x43, 0x44]
