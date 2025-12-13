module Tails.TCP (withServer, acceptLoop, recvSome, sendAll) where

import Control.Exception (bracket, finally)
import Data.ByteString (ByteString)
import Network.Socket (AddrInfo (addrAddress, addrFamily, addrFlags, addrProtocol, addrSocketType), AddrInfoFlag (..), HostName, ServiceName, Socket, SocketOption (..), SocketType (..), accept, bind, close, defaultHints, getAddrInfo, listen, setSocketOption, socket)
import qualified Network.Socket.ByteString as NSB

withServer :: HostName -> ServiceName -> (Socket -> IO ()) -> IO ()
withServer host port action = do
  addr <- resolve
  bracket (open addr) close action
  where
    resolve :: IO AddrInfo
    resolve = do
      let hints =
            defaultHints
              { addrFlags = [AI_PASSIVE],
                addrSocketType = Stream
              }
      head <$> getAddrInfo (Just hints) (Just host) (Just port)

    open :: AddrInfo -> IO Socket
    open addr = do
      sock <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
      setSocketOption sock ReuseAddr 1
      bind sock (addrAddress addr)
      listen sock 1024
      return sock

acceptLoop :: Socket -> (Socket -> IO ()) -> IO ()
acceptLoop serverSock handler = go
  where
    go = do
      (connSock, _peer) <- accept serverSock
      handler connSock `finally` close connSock
      go

recvSome :: Socket -> Int -> IO ByteString
recvSome = NSB.recv

sendAll :: Socket -> ByteString -> IO ()
sendAll = NSB.sendAll
