{-# LANGUAGE NoMonomorphismRestriction #-}

module Quote (
    Packet
  , quoteHeader
  , packetAcceptTimeFromHeader
  , extrapolateAcceptTime
  , Quote(..)
  , Bid(..)
  , showQuote
  , maxOffset
) where

import qualified Network.Pcap as Pcap
import qualified Data.Time as T
import qualified Data.Time.Clock.POSIX as T
import qualified Data.ByteString.Char8 as BS
import qualified Data.List as L
import Debug.Trace


type Packet = (Pcap.PktHdr, BS.ByteString)

quoteHeader = BS.pack "B6034"

-- parses packet accept time from pcap header
-- assumes in POSIX time
packetAcceptTimeFromHeader =
  T.posixSecondsToUTCTime . fromRational . toRational . Pcap.hdrDiffTime

-- uses the packet accept time and possible list of time zones
-- to find quote accept time satisfying the 3s constraint
-- [todo] allow users to specify list of time zones
extrapolateAcceptTime ptime aToD =
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

data Quote = Quote {
    -- [note] `accepTime` must be first for ordering to work correctly!
    acceptTime  :: !T.UTCTime,
    packetTime  :: !T.UTCTime,
    issueCode   :: !BS.ByteString,
    bids        :: ![Bid],
    asks        :: ![Bid]
  } deriving (Eq, Ord)

instance Show Quote where
  show = showQuote

data Bid = Bid {
    price    :: !Int,
    quantity :: !Int
  } deriving (Show, Eq, Ord)

showQuote q = unwords $ fmap ($ q) [
    show . packetTime,
    show . acceptTime,
    BS.unpack . issueCode,
    unwords . fmap showBid . bids,
    unwords . fmap showBid . asks
  ]
  where
    showBid b = (show $ quantity b) ++ "@" ++ (show $ price b)

maxOffset = 3 :: T.NominalDiffTime
