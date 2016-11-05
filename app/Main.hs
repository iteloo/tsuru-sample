{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NoMonomorphismRestriction #-}

module Main where

import qualified Data.Iteratee as I
import Data.Iteratee ((=$), ($=))
import qualified Data.Iteratee.IO as I
import qualified Data.ListLike as LL
import Control.Monad.IO.Class (MonadIO(..))

import Options.Applicative hiding (header)
import qualified Options.Applicative as Opt
import Control.Monad
import Control.Applicative
import qualified System.Environment as Env
import qualified Data.Time as T
import qualified Data.Time.Clock.POSIX as T
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Unsafe as BU
import qualified Network.Pcap as Pcap
import qualified Foreign.Ptr as FPtr
import qualified Data.Set as Set
import qualified Data.List as L
import qualified Data.IORef as Rf
import qualified Data.Attoparsec.ByteString.Char8 as AP
import Debug.Trace


main :: IO ()
main = do
  execParser opts >>= startApp
  where
    opts = info (helper <*> appSetting)
      ( fullDesc
     <> progDesc "Parses quote data from pcap dump files"
     <> Opt.header
          "tsuru-sample - a streaming application for parsing quote data" )

startApp :: AppSetting -> IO ()
startApp stg =
  (enumPcapFileSingle (filename stg) $
    -- $= I.filter (Qu.hasQuoteHeader . snd)
    (I.drop (start stg) >>) $
    (if number stg == (-1) then fmap return else I.take (number stg)) =$
    I.countConsumed $
    I.mapStream parseQuote =$
    I.filter (either (const False) (const True)) =$
    I.mapStream (either (error "should be no Nothing here!") id) =$
    (if reordering stg then reorderQuotes else fmap return) =$
    I.countConsumed $
    (if silent stg then I.skipToEof else logIndiv)
  ) >>= I.run >>= \((_,n),m) -> putStrLn
      $ show m ++ " packets processed. " ++ show n ++ " quotes parsed."

data AppSetting = AppSetting {
  reordering  :: Bool,
  start       :: Int,
  number      :: Int,
  silent      :: Bool,
  filename    :: String
}

appSetting :: Parser AppSetting
appSetting = AppSetting
  <$> switch
     ( long "reorder"
    <> short 'r'
    <> help "Reorder packets based on quote accept time" )
  <*> option auto
     ( long "start"
    <> short 's'
    <> help "Starting index for packet"
    <> showDefault
    <> value 0
    <> metavar "INT" )
  <*> option auto
     ( long "number"
    <> short 'n'
    <> help "Maximum number of packets to accept"
    <> showDefault
    <> value (-1)  -- [hack]
    <> metavar "INT" )
  <*> switch
     ( long "silent"
    <> help "Do not log packets" )
  <*> argument str (metavar "FILE")


-- packet parsing (attoparsec)

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

showQuote :: Quote -> String
showQuote q = unwords $ fmap ($ q) [
    show . packetTime,
    show . acceptTime,
    BS.unpack . issueCode,
    unwords . fmap showBid . bids,
    unwords . fmap showBid . asks
  ]
  where
    showBid b = (show $ quantity b) ++ "@" ++ (show $ price b)

maxOffset :: T.NominalDiffTime
maxOffset = 3

parseQuote (hdr, bs) = AP.parseOnly (quote (packetAcceptTimeFromHeader hdr)) bs

packetAcceptTimeFromHeader =
  T.posixSecondsToUTCTime . fromRational . toRational . Pcap.hdrDiffTime

header = AP.string $ BS.pack "B6034"

upTil p = many (let one = p <|> (AP.anyChar >> one) in one)

parser = upTil header

-- nDigitNumber :: Int -> AP.Parser Int
-- will throw exceptions if parses doubles instead
nDigitNumber n = liftM (\(AP.I i) -> fromInteger i)
    $ AP.take n >>= either fail return . AP.parseOnly AP.number

-- quote ptime =
--   (,,)
--   <$ AP.take 42
--   <* AP.string (BS.pack "B6034")
--   <*> AP.take 12
--   <* AP.take 3
--   <*> bids
--   <* AP.take 7
--   <*> asks
--   <* AP.take 50
--   <*> (extrapolateAcceptTime ptime <$> acceptTimeOfDay)

quote ptime = do
  AP.take 42
  AP.string $ BS.pack "B6034"
  issueCode <- AP.take 12
  AP.take 12
  bs <- bids'
  AP.take 7
  as <- asks'
  AP.take 50
  aTime <- liftM (extrapolateAcceptTime ptime) acceptTimeOfDay
  case aTime of
    Nothing -> fail "cannot parse time"
    Just t ->
      return $ Quote t ptime issueCode bs as

bids' = AP.count 5 (Bid <$> nDigitNumber 5 <*> nDigitNumber 7)

-- [todo] verify order
asks' = reverse <$> bids'

acceptTimeOfDay = do
  hh <- nDigitNumber 2
  mm <- nDigitNumber 2
  ss <- nDigitNumber 2
  uu <- nDigitNumber 2
  let pico = fromRational $ ss + uu / 100
  return $ T.TimeOfDay hh mm pico

extrapolateAcceptTime :: T.UTCTime -> T.TimeOfDay -> Maybe T.UTCTime
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

-- iteratees

type Packet = (Pcap.PktHdr, BS.ByteString)

logger = I.mapChunksM_ (liftIO . print)

logIndiv = I.mapChunksM_ (liftIO . LL.mapM_ print)

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
          T.diffUTCTime (packetTime q) (acceptTime q') > maxOffset

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
