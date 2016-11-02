{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE NoMonomorphismRestriction #-}

module Main where

import qualified Quote as Qu
import qualified Data.Iteratee as I
import Data.Iteratee ((=$), ($=))
import qualified Data.Iteratee.IO as I
import qualified Data.ListLike as LL

import Prelude hiding (take, drop, filter)
import qualified System.Environment as Env
import qualified Data.Time as T
import qualified Data.ByteString.Char8 as BS
import qualified Network.Pcap as Pcap
import Control.Exception (SomeException)
import Control.Monad.IO.Class (MonadIO(..))
import qualified Data.Set as Set
import qualified Data.List as List


main :: IO ()
main = do
  args <- Env.getArgs
  case parseArgs args of
    Nothing -> print "Usage: parse-quote [-r] <pcap filename>"
    Just appSetting -> startApp appSetting

startApp :: AppSetting -> IO ()
startApp settings =
  (enumPcapFile (filename settings)
    $= I.filter (Qu.hasQuoteHeader . snd)
    $= I.mapStream Qu.quoteFromPacket
    $= I.filter (maybe False (const True))
    $= I.mapStream (maybe (error "should be no Nothing here!") id)
    $= (if reordering settings then reorderQuotes else fmap return)
    $ I.countConsumed
    $ logIndiv
  ) >>= I.run >>= print

byteCounter :: Monad m => I.Iteratee [Packet] m Int
byteCounter = I.length

logger = I.mapChunksM_ (liftIO . print)

logIndiv :: _ => I.Iteratee [a] m ()
logIndiv = I.mapChunksM_ (liftIO . sequence_ . map print)

data AppSetting = AppSetting {
  filename :: String,
  reordering  :: Bool
}

type Packet = (Pcap.PktHdr, BS.ByteString)

enumPcapFile :: FilePath -> I.Enumerator [Packet] IO a
enumPcapFile fp it = do
  handle <- liftIO $ Pcap.openOffline fp
  let callback :: st -> IO (Either SomeException ((Bool, st), [Packet]))
      callback st = do
        (hdr, bs) <- Pcap.nextBS handle
        if bs == BS.pack ""
          then return $ Right ((False, st), I.empty) -- yield first? -- [hack]
          else return $ Right ((True, st), [(hdr, bs)])
  I.enumFromCallback callback () it

parseArgs :: [String] -> Maybe AppSetting
parseArgs [fn]        = Just $ AppSetting fn False
parseArgs ["-r", fn]  = Just $ AppSetting fn True
parseArgs _           = Nothing

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
reorderQuotes = reorder $ \q q' ->
          T.diffUTCTime (Qu.packetTime q) (Qu.acceptTime q') > Qu.maxOffset

reorder :: (Ord i, Monad m)
  => (i -> i -> Bool)
  -> I.Enumeratee [i] [i] m a
reorder cond = unfoldConvStreamFinish update fin (undefined, Set.empty)
  where
    update (i, buf) =
      case Set.minView buf of
        Just (i', buf') ->
          if cond i i'
            then return ((i, buf'), [i'])
            else request
        Nothing -> request
      where
        request = I.getChunk >>= \is ->
          return ((maximum is, Set.fromList is `Set.union` buf), [])
    fin (_, buf) = Set.toList buf

unfoldConvStreamFinish ::
  (Monad m, I.Nullable s)
    => (acc -> I.Iteratee s m (acc, s'))
    -> (acc -> s')
    -> acc
    -> I.Enumeratee s s' m a
unfoldConvStreamFinish f fin acc0 = I.eneeCheckIfDonePass (check acc0)
 where
   check acc k (Just e) = I.throwRecoverableErr e (const I.identity) >> check acc k Nothing
   check acc k _ = I.isStreamFinished >>=
                   maybe (step acc k) (I.idone (k . I.Chunk $ fin acc) . I.EOF . Just)
   step acc k = f acc >>= \(acc', s') ->
                   I.eneeCheckIfDonePass (check acc') . k . I.Chunk $ s'
