module Quote where

import Helpers

import Control.Monad
import qualified Network.Pcap as Pcap
import qualified Data.ByteString.Char8 as BS
import qualified Data.Time as T
import qualified Data.Time.Clock.POSIX as T
import qualified Data.List as L

-- [todo] statically verify bytestring lengths and formats using LiquidHaskell

type Packet = (Pcap.PktHdr, BS.ByteString)

type Payload = BS.ByteString

type QuotePacket = BS.ByteString

data Quote = Quote {
    -- [note] `accepTime` must be first for ordering to work correctly!
    acceptTime  :: !T.UTCTime,
    packetTime  :: !T.UTCTime,
    issueCode   :: !String,
    bids        :: ![Bid],
    asks        :: ![Bid]
  } deriving (Eq, Ord)

instance Show Quote where
  show = showQuote

data Bid = Bid {
    price    :: !Int,
    quantity :: !Int
  } deriving (Show, Eq, Ord)

showQuote :: Quote -> String
showQuote q = unwords $ fmap ($ q) [
    show . packetTime,
    show . acceptTime,
    issueCode,
    unwords . fmap showBid . bids,
    unwords . fmap showBid . asks
  ]
  where
    showBid b = (show $ quantity b) ++ "@" ++ (show $ price b)

maxOffset :: T.NominalDiffTime
maxOffset = 3

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

-- parses packet accept time from pcap header
-- assumes in POSIX time
packetAcceptTimeFromHeader :: Pcap.PktHdr -> T.UTCTime
packetAcceptTimeFromHeader =
  T.posixSecondsToUTCTime . fromRational . toRational . Pcap.hdrDiffTime

-- constructs quote object from quote packet and packet accept time
-- does not check that quote packet begins with "B6034"
quoteFromQuotePacket :: QuotePacket -> T.UTCTime -> Maybe Quote
quoteFromQuotePacket p ptime = do
  aToD <- parseAcceptTimeOfDay =<< range 206 8 p
  -- [todo] handle exception explicitly
  acceptTime <- extrapolateAcceptTime aToD ptime
  issueCode <- liftM BS.unpack $ range 5 12 p
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

    -- uses the packet accept time and possible list of time zones
    -- to find quote accept time satisfying the 3s constraint
    -- [todo] allow users to specify list of time zones
    extrapolateAcceptTime :: T.TimeOfDay -> T.UTCTime
                                    -> Maybe T.UTCTime
    extrapolateAcceptTime aToD ptime =
      let tzones = [T.hoursToTimeZone 9]
          -- nondeterministic search for timezone
          atimes = do
            tz <- tzones
            let day = T.localDay $ T.utcToLocalTime tz ptime
            -- here we account for the possibility that
            --   the quote was accepted on the previous local day,
            --   but the packet is accepted on the next day
            -- [note] uniqueness relies on `maxOffset` being less
            --   than half a day
            d <- [day, T.addDays (-1) day]
            let t = T.LocalTime d aToD
            return $ T.localTimeToUTC tz t
      in
        -- [note] we expect exactly one result assuming that the
        --   `maxOffset` constraint is satisfied
        L.find ((< maxOffset) . T.diffUTCTime ptime) atimes

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
