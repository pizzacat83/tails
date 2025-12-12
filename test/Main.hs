module Main (main) where

import qualified BytesSpec
import Test.Tasty

main :: IO ()
main =
  defaultMain $
    testGroup
      "tails"
      [ BytesSpec.tests
      ]
