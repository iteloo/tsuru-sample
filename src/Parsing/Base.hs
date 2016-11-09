module Parsing.Base (
    module Base
  , quoteHeader
  , packetAcceptTimeFromHeader
  , extrapolateAcceptTime
) where

import Base

import qualified Network.Pcap as Pcap
import qualified Data.ByteString.Char8 as BS
import qualified Data.Time as T
import qualified Data.Time.Clock.POSIX as T
import qualified Data.List as L
import Debug.Trace


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
