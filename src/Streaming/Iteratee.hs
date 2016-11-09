{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE NoMonomorphismRestriction #-}

module Streaming.Iteratee (
    logger
  , logIndiv
  , logIndivBuilder
  , logIndivQuote
  , resizeChunks
  , enumPcapFileSingle
  , enumPcapFileMany
  , enumPcapFileMany'
  , unsafeEnumPcapFileSingle
  , unsafeEnumPcapFileMany
  , reorderQuotes
) where

import Base
import Streaming.Builder.Quote (quoteBuilder)

import qualified Data.Iteratee as I
import Data.Iteratee ((=$), ($=))
import qualified Data.Iteratee.IO as I
import qualified Data.ListLike as LL
import Control.Monad.IO.Class (MonadIO(..))

import Control.Monad
import Control.Applicative
import System.IO (stdout)
import qualified Data.Time as T
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Builder as BS
import qualified Data.ByteString.Unsafe as BU
import qualified Network.Pcap as Pcap
-- import qualified Foreign.Ptr as FPtr
import qualified Data.Set as Set
import qualified Data.IORef as Rf
import Debug.Trace


logger = I.mapChunksM_ (liftIO . print)

logIndivBuilder =
  I.mapChunksM_ (liftIO . LL.mapM_ (BS.hPutBuilder stdout))

logIndivQuote =
  I.mapChunksM_ (liftIO . LL.mapM_ (BS.hPutBuilder stdout . quoteBuilder))

logIndiv = I.mapChunksM_ (liftIO . LL.mapM_ print)

resizeChunks n it =
    I.Iteratee $ \od oc -> let
        od' x _        = I.runIter (return (return x)) od oc
        oc' k Nothing  = I.runIter (do
            isEOF <- I.isStreamFinished
            case isEOF of
              Nothing ->
                (I.take n =$ I.stream2stream) >>= resizeChunks n . k . I.Chunk
              e -> resizeChunks n . k . I.EOF $ e
          ) od oc
        oc' _ (Just e) = I.runIter (I.throwErr e) od oc
      in I.runIter it od' oc'

enumPcapFileSingle :: FilePath -> I.Enumerator _ IO a
enumPcapFileSingle fp it = do
  handle <- liftIO $ Pcap.openOffline fp
  let --callback :: st -> IO (Either SomeException ((Bool, st), _))
      callback st = do
        (hdr, bs) <- Pcap.nextBS handle
        return . Right $ ((bs /= BS.pack "", st), [(hdr, bs)])

  I.enumFromCallback callback () it

enumPcapFileMany :: Int -> FilePath -> I.Enumerator _ IO a
enumPcapFileMany cs fp = enumPcapFileSingle fp $= resizeChunks cs

-- [note] for some reason this version is much much slower for large `cs`
enumPcapFileMany' :: Int -> FilePath -> I.Enumerator [Packet] IO a
enumPcapFileMany' cs fp it = do
  handle <- liftIO $ Pcap.openOffline fp
  let --callback :: st -> IO (Either SomeException ((Bool, st), _))
      callback st = do
        chunk <- getMany cs
        return . Right $ ((not (null chunk), st), chunk)
        where
          getMany 0 = return []
          getMany n = do
            (hdr, bs) <- Pcap.nextBS handle
            if bs /= BS.pack ""
              then liftM ((hdr, bs):) $ getMany (n-1)
              else return []

  I.enumFromCallback callback () it

unsafeEnumPcapFileSingle :: FilePath -> I.Enumerator _ IO a
unsafeEnumPcapFileSingle fp it = do
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
unsafeEnumPcapFileMany :: Int -> FilePath -> I.Enumerator _ IO a
unsafeEnumPcapFileMany cs fp it = do
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
reorderQuotes = reorder $ \q ->
  -- [hack] this dummy quote is made purely for reordering to work
  q { acceptTime = T.addUTCTime (-maxOffset) (packetTime q) }

reorder :: (Ord i, Monad m)
  => (i -> i) -- [hack] make dummy to get the O(log n) time of Set.split
  -> I.Enumeratee [i] [i] m a
reorder dummy = unfoldConvStreamFinish update fin (undefined, Set.empty)
  where
    update (i, buf) =
      let (is, buf') = Set.split (dummy i) buf in
      if Set.null is
        then do
          chunk <- I.getChunk
          return ((maximum chunk, Set.fromList chunk `Set.union` buf), [])
        else return ((i, buf'), Set.toAscList is)
    fin (_, buf) = Set.toAscList buf
{-# INLINE reorder #-}

-- small modification of `I.unfoldConvStream` to accept a specialized
--   finishing routine
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
{-# INLINE unfoldConvStreamFinish #-}
