{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}

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
import qualified Data.ByteString.Unsafe as BU
import Foreign.Ptr as FPtr
import qualified Network.Pcap as Pcap
import Control.Exception (SomeException)
import Control.Monad.IO.Class (MonadIO(..))
import qualified Data.Set as Set
import qualified Data.IORef as Rf
import Debug.Trace
import Control.Monad


main :: IO ()
main = do
  args <- Env.getArgs
  case parseArgs args of
    Nothing -> print "Usage: parse-quote [-r] <pcap filename>"
    Just appSetting -> startApp appSetting

mapPair f (a,b) = (f a, f b)

startApp :: AppSetting -> IO ()
startApp settings =
  (enumPcapFileSingle (filename settings)
    $= I.filter (Qu.hasQuoteHeader . snd)
    -- $= I.take 100
    $= I.mapStream Qu.quoteFromPacket
    $= I.filter (maybe False (const True))
    $= I.mapStream (maybe (error "should be no Nothing here!") id)
    -- $= (if reordering settings then reorderQuotes else fmap return)
    $ I.countConsumed
    $ I.skipToEof
  ) >>= I.run >>= print

logger = I.mapChunksM_ (liftIO . print)

logIndiv = I.mapChunksM_ (liftIO . LL.mapM_ print)

data AppSetting = AppSetting {
  filename :: String,
  reordering  :: Bool
}

type Packet = (Pcap.PktHdr, BS.ByteString)

enumPcapFileSingle :: FilePath -> I.Enumerator _ IO a
enumPcapFileSingle fp it = do
  handle <- liftIO $ Pcap.openOffline fp
  let --callback :: st -> IO (Either SomeException ((Bool, st), _))
      callback st = do
        (hdr, ptr) <- Pcap.next handle
        -- [note] no finalizer: memory will not be freed
        bs <- BU.unsafePackCStringFinalizer
                ptr
                (fromIntegral $ Pcap.hdrCaptureLength hdr)
                (return ())
        -- alternatively, and equivalently:
        -- bs <- BU.unsafePackCStringLen
        --         (FPtr.wordPtrToPtr . FPtr.ptrToWordPtr $ ptr,
        --         fromIntegral $ Pcap.hdrCaptureLength hdr)
        return . Right $ ((bs /= BS.pack "", st), [(hdr, bs)])

  I.enumFromCallback callback () it

-- [problem] doesn't work since ptr is re-used in `dispatch`
enumPcapFileMany :: Int -> FilePath -> I.Enumerator _ IO a
enumPcapFileMany cs fp it = do
  handle <- liftIO $ Pcap.openOffline fp
  packetsRef <- Rf.newIORef $ ([] :: [Packet])
  let --callback :: st -> IO (Either SomeException ((Bool, st), _))
      callback st = do
        -- [note] for some reason `n` is 0 even if some packets were read
        n <- Pcap.dispatch handle cs handlePacketRead
        packets <- Rf.readIORef packetsRef
        Rf.writeIORef packetsRef []
        return . Right $ ((not $ n==0, st), reverse packets)

      handlePacketRead hdr ptr = do
        -- [note] no finalizer: memory will not be freed
        bs <- BU.unsafePackCStringFinalizer
                ptr
                (fromIntegral $ Pcap.hdrCaptureLength hdr)
                (return ())
        Rf.modifyIORef' packetsRef ((hdr, bs):)

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
