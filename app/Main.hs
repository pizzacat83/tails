module Main (main) where

import Tails.App.Server (runServer)

main :: IO ()
main = do
  runServer
