{-# LANGUAGE GADTs #-}

module Streaming.MyIteratee (
    module Data.MyIteratee
  , enumPcapFile
  , reorderQuotes
) where

import Data.MyIteratee
import Base

import qualified Network.Pcap as Pcap
import qualified Data.ByteString.Char8 as BS
import qualified Data.Time as T


-- enumerator for streaming contents of pcap files
enumPcapFile fname it = do
  handle <- Pcap.openOffline fname
  let
    onFinish = return
    onGet = do
      (hdr, bs) <- Pcap.nextBS handle
      return $ if bs == BS.pack "" then Nothing else Just (hdr, bs)
    onPrint = putStrLn
    -- [todo] handle better
    onThrow = putStrLn
  enumFromHandlers onFinish onGet onPrint onThrow it
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
