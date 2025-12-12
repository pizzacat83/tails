module Main (main) where

import qualified BytesSpec
import qualified RecordSpec
import Test.Tasty

main :: IO ()
main =
  defaultMain $
    testGroup
      "tails"
      [ BytesSpec.tests,
        RecordSpec.tests
      ]
