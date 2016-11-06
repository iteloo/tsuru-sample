module MyIteratee.QuoteParsing where

import Quote

import Control.Monad
import qualified Network.Pcap as Pcap
import qualified Data.ByteString.Char8 as BS
import qualified Data.Time as T
import qualified Data.Time.Clock.POSIX as T
import qualified Data.List as L

-- [todo] statically verify bytestring lengths and formats using LiquidHaskell

type Payload = BS.ByteString

type QuotePacket = BS.ByteString

-- extracts substring of length `n` at location `i` of a bytestring
-- returns Nothing if out of bound
range :: Int -> Int -> BS.ByteString -> Maybe BS.ByteString
range i n bs =
  let bs' = BS.take n . BS.drop i $ bs in
  if n == BS.length bs' then Just bs' else Nothing

-- checks payload contains correct quote header
hasQuoteHeader :: Payload -> Bool
hasQuoteHeader = maybe False (== BS.pack "B6034") . range 42 5

-- parses quote object from pcap packet
quoteFromPacket :: Packet -> Maybe Quote
quoteFromPacket (hdr, pl) = do
  qPkt <- quotePacketFromPayload pl
  let atime = packetAcceptTimeFromHeader hdr
  quoteFromQuotePacket qPkt atime

-- parses UDP payload into quote packets
quotePacketFromPayload :: Payload -> Maybe QuotePacket
quotePacketFromPayload = range 42 215

-- constructs quote object from quote packet and packet accept time
-- does not check that quote packet begins with "B6034"
quoteFromQuotePacket :: QuotePacket -> T.UTCTime -> Maybe Quote
quoteFromQuotePacket p ptime = do
  aToD <- parseAcceptTimeOfDay =<< range 206 8 p
  -- [todo] handle exception explicitly
  acceptTime <- extrapolateAcceptTime ptime aToD
  issueCode <- range 5 12 p
  bids <- parseBids =<< range 29 60 p
  asks <- parseBids =<< range 96 60 p
  return Quote {
    acceptTime  = acceptTime,
    packetTime  = ptime,
    issueCode   = issueCode,
    bids        = reverse bids,
    asks        = asks
  }
  where
    -- assumes input is a bytestring of 8 digits
    parseAcceptTimeOfDay :: BS.ByteString -> Maybe T.TimeOfDay
    parseAcceptTimeOfDay bs = do
      hh <- safeRead =<< liftM BS.unpack (range 0 2 bs)
      mm <- safeRead =<< liftM BS.unpack (range 2 2 bs)
      ss <- safeRead =<< liftM BS.unpack (range 4 2 bs)
      uu <- safeRead =<< liftM BS.unpack (range 6 2 bs)
      let pico = fromRational $ (fromIntegral ss) + (fromIntegral uu) / 100
      return $ T.TimeOfDay hh mm pico

    -- assumes input is a bytestring of 60 (= (5+7)*5) digits
    -- [todo] check statically with LiquidHaskell
    parseBids :: BS.ByteString -> Maybe [Bid]
    parseBids bs =
      liftM fst $ foldM (\(bids, remain) _ -> do
            let (bid, remain') = BS.splitAt 12 remain
            let (pstr, qstr) = BS.splitAt 5 bid
            p <- safeRead $ BS.unpack pstr
            q <- safeRead $ BS.unpack qstr
            return (Bid p q : bids, remain')
        ) ([],bs) [1..5]

-- Helpers

safeRead :: Read a => String -> Maybe a
safeRead s = case reads s of
    [(x,"")] -> Just x
    _ -> Nothing
