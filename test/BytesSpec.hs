module BytesSpec (tests) where

import qualified Data.ByteString as BS
import Tails.Bytes (DecodeError (DecodeError), getU16, getU8, putU16, putU8, runGet, runPut)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertFailure, testCase, (@?=))

tests :: TestTree
tests =
  testGroup
    "Bytes"
    [ testCase "getU8" test_getU8,
      testCase "getU16" test_getU16,
      testCase "putU8" test_putU8,
      testCase "putU16" test_putU16,
      testCase "roundtrip U8" test_roundtrip_U8,
      testCase "roundtrip U16" test_roundtrip_U16
    ]

test_getU8 :: IO ()
test_getU8 = do
  let input = BS.pack [0x42, 0x43, 0x44]
  case runGet getU8 input of
    Left (DecodeError err) -> assertFailure $ "runGet failed: " ++ err
    Right (val, rest) -> do
      val @?= 0x42
      rest @?= BS.pack [0x43, 0x44]

-- numbers are big-endian
test_getU16 :: IO ()
test_getU16 = do
  let input = BS.pack [0x01, 0x02, 0x03]
  case runGet getU16 input of
    Left (DecodeError err) -> assertFailure $ "runGet failed: " ++ err
    Right (val, rest) -> do
      val @?= 0x0102
      rest @?= BS.pack [0x03]

test_putU8 :: IO ()
test_putU8 = do
  runPut (putU8 0x42) @?= BS.pack [0x42]

test_putU16 :: IO ()
test_putU16 = do
  runPut (putU16 0x0102) @?= BS.pack [0x01, 0x02]

test_roundtrip_U8 :: IO ()
test_roundtrip_U8 = do
  let original = 0x42
  let encoded = runPut (putU8 original)
  case runGet getU8 encoded of
    Left (DecodeError err) -> assertFailure $ "runGet failed: " ++ err
    Right (decoded, _) -> decoded @?= original

test_roundtrip_U16 :: IO ()
test_roundtrip_U16 = do
  let original = 0x0102
  let encoded = runPut (putU16 original)
  case runGet getU16 encoded of
    Left (DecodeError err) -> assertFailure $ "runGet failed: " ++ err
    Right (decoded, _) -> decoded @?= original
