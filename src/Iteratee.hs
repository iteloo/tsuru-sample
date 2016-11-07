{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NoMonomorphismRestriction #-}

module Iteratee (
    parseQuote
  , logger
  , logIndiv
  , resizeChunks
  , enumPcapFileSingle
  , enumPcapFileMany
  , enumPcapFileMany'
  , unsafeEnumPcapFileSingle
  , unsafeEnumPcapFileMany
  , reorderQuotes
) where

import Quote hiding (bids, asks)

import qualified Data.Iteratee as I
import Data.Iteratee ((=$), ($=))
import qualified Data.Iteratee.IO as I
import qualified Data.ListLike as LL
import Control.Monad.IO.Class (MonadIO(..))

import Control.Monad
import Control.Applicative
import qualified Data.Time as T
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Unsafe as BU
import qualified Network.Pcap as Pcap
-- import qualified Foreign.Ptr as FPtr
import qualified Data.Set as Set
import qualified Data.IORef as Rf
import Debug.Trace


parseQuote :: _ => Packet -> m (Either I.IFException Quote)
parseQuote (hdr, bs) =
  (I.enumPure1Chunk bs $ quote (packetAcceptTimeFromHeader hdr)) >>= I.tryRun

quote ptime = do
  I.drop 42
  exact quoteHeader
  issueCode <- I.take 12 =$ I.stream2stream
  I.drop 12
  bs <- bids
  I.drop 7
  as <- asks
  I.drop 50
  aToD <- acceptTimeOfDay
  case extrapolateAcceptTime ptime aToD of
    Nothing ->
      I.throwErr $ I.iterStrExc "cannot parse time"
    Just t ->
      return $ Quote t ptime issueCode bs as

-- [problem] for some reason errors are swallowed
bids = sequence . replicate 5 $ Bid <$> nDigitNumber 5 <*> nDigitNumber 7

asks = reverse <$> bids

acceptTimeOfDay = do
  hh <- nDigitNumber 2
  mm <- nDigitNumber 2
  ss <- nDigitNumber 2
  uu <- nDigitNumber 2
  let pico = fromRational $ fromIntegral ss + fromIntegral uu / 100
  return $ T.TimeOfDay hh mm pico

nDigitNumber n = do
  ds <- I.take n =$ I.stream2stream
  maybe
    (I.throwErr . I.iterStrExc $ "not a " ++ show n ++ "-digit number")
    (return . foldr (\(i,d) a -> a + d*10^i) 0 . zip [n-1,n-2..0])
    (mapM digitToInt $ LL.toString ds)

digitToInt :: Char -> Maybe Int
digitToInt c
  | (fromIntegral i::Word) <= 9 = Just i
  | otherwise = Nothing
  where
    i = fromEnum c - fromEnum '0'
{-# INLINE digitToInt #-}

exact s = do
  n <- I.heads s
  if n == LL.length s
    then return ()
    else I.throwErr . I.iterStrExc $ "exact: no match"

logger = I.mapChunksM_ (liftIO . print)

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
