module Main (main) where

import Test.Tasty
import Test.Tasty.HUnit

main :: IO ()
main = defaultMain $ testGroup "tails"
    [ testCase "sanity" $ 1 @?= (1 :: Int)
    ]
