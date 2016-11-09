module Base (
  module Quote
  , Packet
  , maxOffset
) where

import Quote

import qualified Network.Pcap as Pcap
import qualified Data.ByteString.Char8 as BS
import qualified Data.Time as T

type Packet = (Pcap.PktHdr, BS.ByteString)

maxOffset = 3 :: T.NominalDiffTime
