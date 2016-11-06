{-# LANGUAGE GADTs #-}

module MyIteratee (
    module MyIteratee.MyIteratee
  , reorderQuotes
  , enumPcapFile
  , hasQuoteHeader
  , parseQuote
) where

import MyIteratee.MyIteratee
import MyIteratee.QuoteParsing
import Quote

import qualified Network.Pcap as Pcap
import qualified Data.ByteString.Char8 as BS
import qualified Data.Time as T


-- enumerator for streaming contents of pcap files
enumPcapFile :: FilePath
                  -> Iter (Sum3 (Get (Data Packet)) Printing Exception) a
                  -> IO a
enumPcapFile fname it = do
  handle <- Pcap.openOffline fname
  let process (Finish a) = return a
      process (Effect (G Get) k) = do
          (hdr, bs) <- Pcap.nextBS handle
          process . k $ if bs == BS.pack ""
            then NoData
            else Data (hdr, bs)
      process (Effect (P (Print s)) k) = do
        putStrLn s
        process (k ())
      process (Effect (T (Throw s)) _) = do
        -- [todo] handle better
        putStrLn s
        error s
  process it
  -- [note] no need/way to close handle

-- reorders quotes based on quote accept time, assuming that
--   `pt - qt <= 3` for each quote,
--   where `pt` : packet accept time
--         `qt` : quote accept time
-- we implement this handler using a buffer that assumes quotes
-- `q` satisfying `pt_r - qt_q > 3` can be safely reordered and emitted.
-- Here `r` is the most recently inserted quote.
-- proof that `qt_q` < qt_f` for any quote `q` in the buffer, and
-- all `f`s that we might receive in the future:
--   suppose `f` is a future quote, then since `pt_f > pt_r`, we have
--   `qt_q < pt_r - 3 < pt_f - 3 <= qt_f
-- proof that we cannot do better: let `q` be a quote in the buffer
--   such that `pt_r - qt_q = 3 - e` for `e > 0`. we construct a future `f`
--   such that `qt_q > qt_f`
--   let `f` be a packet with
--     `qt_f = pt_r - 3 + e/2` and `pt_f = pt_r + e/3`
--   then `f` is indeed a valid future packet since:
--     `pt_f > pt_r`
--     `pt_f - qt_f = 3 - e/6 < 3`
--   morever, `qt_q = pt_r - 3 + e > qt_f`
-- reorderQuotes :: Iter (Sum3 (Get (Data Quote)) x y) a
--               -> Iter (Sum3 (Get (Data Quote)) x y) a
reorderQuotes = reorder $ \q q' ->
          T.diffUTCTime (packetTime q) (acceptTime q') > maxOffset
