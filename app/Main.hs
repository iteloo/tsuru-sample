{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE BangPatterns #-}

module Main where

import Lib

import Prelude hiding (take, drop, filter)
import Control.Monad
import qualified Prelude as Pre
import qualified System.Environment as Env
import qualified Network.Pcap as Pcap
import qualified Data.ByteString.Char8 as BS
import qualified Data.Time as T
import qualified Data.Time.Clock.POSIX as T
import qualified Data.List as L
import qualified Data.Set as Set
import System.IO.Unsafe (unsafePerformIO)


main :: IO ()
main = do
  args <- Env.getArgs
  -- "mdf-kospi200.20110216-0.pcap"
  case parseArgs args of
    Nothing -> print "Invalid arguments"
    Just appSetting -> startApp appSetting

startApp :: AppSetting -> IO ()
startApp settings =
  streamPackets (filename settings)
    $ filter (hasQuoteHeader . snd)
    -- $ drop 12000
    -- $ take 4000
    $ transformData quoteFromPacket
    $ filterMaybe
    $ (if reorder settings then reorderQuotes else id)
    $ getForever

data AppSetting = AppSetting {
  filename :: String,
  reorder  :: Bool
}

parseArgs :: [String] -> Maybe AppSetting
parseArgs [fn]        = Just $ AppSetting fn False
parseArgs ["-r", fn]  = Just $ AppSetting fn True
parseArgs _           = Nothing

-- quote parsing
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

-- iteratees

data Iter e a where
  Finish :: a -> Iter e a
  Effect :: e x -> (x -> Iter e a) -> Iter e a

instance Monad (Iter e) where
  return = Finish
  Finish a >>= f = f a
  Effect e k >>= f = Effect e (\a -> k a >>= f)

instance Applicative (Iter e) where
  pure = return
  (<*>) = ap

instance Functor (Iter e) where
  fmap = liftM

data Get i x where
  Get :: Get i i

data Printing x where
  Print :: String -> Printing ()

data Exception x where
  Throw :: String -> Exception x

-- [todo] implement using open unions instead
data Sum3 (f :: * -> *) (g :: * -> *) (h :: * -> *) x
    = G (f x) | P (g x) | T (h x)

printEff :: String -> Iter (Sum3 x Printing z) ()
printEff s = Effect (P $ Print s) return

data Data a = NoData | Data a

instance Monad Data where
  return = Data
  NoData >>= f = NoData
  Data a >>= f = f a

instance Applicative Data where
  pure = return
  (<*>) = ap

instance Functor Data where
  fmap = liftM

type FileName = String

streamPackets :: FileName
                  -> Iter (Sum3 (Get (Data Packet)) Printing Exception) a
                  -> IO a
streamPackets fname it = do
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

get :: Iter _ (Data a)
get = Effect (G Get) Finish

getForever :: Iter _ ()
getForever = do
  a <- get
  case a of
    NoData -> do
      printEff "End of stream"
      return ()
    Data x -> do
      printEff $ show x
      getForever

drop :: Int -> Iter (Sum3 (Get (Data i)) x y) a
            -> Iter (Sum3 (Get (Data i)) x y) a
drop n (Finish a)         = Finish a
drop 0 e@(Effect (G Get) k) = e
drop n e@(Effect (G Get) k) = Effect (G Get) $ drop (n-1) . \case
                              NoData -> k NoData
                              Data _ -> e
drop n (Effect e k)       = Effect e (drop n . k)

take :: Int -> Iter (Sum3 (Get (Data i)) x y) a
            -> Iter (Sum3 (Get (Data i)) x y) a
take n (Finish a)         = Finish a
take 0 (Effect (G Get) k) = take 0 (k NoData)
take n (Effect (G Get) k) = Effect (G Get) (take (n-1) . k)
take n (Effect e k)       = Effect e (take n . k)

filter :: (i -> Bool) -> Iter (Sum3 (Get (Data i)) x y) a
                      -> Iter (Sum3 (Get (Data i)) x y) a
filter c (Finish a) = Finish a
filter c e@(Effect (G Get) k) = Effect (G Get) (filter c . loop)
    where loop NoData  = k NoData
          loop (Data i) = if c i then k (Data i) else e
filter c (Effect e k) = Effect e (filter c . k)

-- a filter that blocks `Nothing` and output `a` for `Just a`
filterMaybe :: Iter (Sum3 (Get (Data i)) x y) a
              -> Iter (Sum3 (Get (Data (Maybe i))) x y) a
filterMaybe (Finish a)           = Finish a
filterMaybe e@(Effect (G Get) k) = Effect (G Get) (filterMaybe . loop)
    where loop NoData                  = k NoData
          loop (Data i) | Just x <- i  = k $ Data x
          loop (Data i) | Nothing <- i = e
filterMaybe (Effect (P e) k) = Effect (P e) (filterMaybe . k)
filterMaybe (Effect (T e) k) = Effect (T e) (filterMaybe . k)

transform :: (a -> b) -> Iter (Sum3 (Get b) x y) c
                      -> Iter (Sum3 (Get a) x y) c
transform f (Finish a)          = Finish a
transform f (Effect (G Get) k)  = Effect (G Get) (transform f . k . f)
transform f (Effect (P e) k)    = Effect (P e) (transform f . k)
transform f (Effect (T e) k)    = Effect (T e) (transform f . k)

transformData :: (a -> b) -> Iter (Sum3 (Get (Data b)) x y) c
                      -> Iter (Sum3 (Get (Data a)) x y) c
transformData f = transform $ liftM f

-- reorders quotes based on quote accept time
-- assumes that `pt - qt <= 3` for each quote,
  -- where `pt` : packet accept time
  --       `qt` : quote accept time
-- we implement this using a set buffer, ordered by `qt`
--   and a variable `pt_max`
-- when a new quote arrives, we
  -- add it to the buffer,
  -- update `pt_max` to using its `pt`
-- when a quote is requested, we
  -- take the min `m` from the buffer
    -- i.e. the quote with least `qt`
  -- if no such `m` exists,
    -- we send a request
  -- if `pt_max - qt_m > 3`, we answer to the request using `m`
    -- proof that `qt_m` <= qt_q` for any `q` in the buffer, and
    -- for all `q`s that we might receive in the future:
      -- suppose `q` is a quote in the buffer, then
        -- `qt_m <= qt_q` by defn as the min
      -- suppose `f` is a future quote, then since `pt_f > pt_max`,
        -- `qt_m < pt_max - 3 < pt_f - 3 <= qt_f
    -- proof that we cannot do better: if pt_max - qt_m = 3 - e, then
    -- there could be a future `q` such that `qt_m > qt_q`
      -- let `q` be a packet with
        -- `qt_q = pt_max - 3 + e/2` and `pt_q = pt_max + e/3`
      -- `qt_m = pt_max - 3 + e > qt_q`
      -- `pt_q > pt_max`
      -- `pt_q - qt_q = 3 - e/6 < 3`
  -- otherwise, we send a request
-- when EOF, flush everything in the buffer
-- [think] is Set really the right choice? no duplicate would be stored
reorderQuotes :: Iter (Sum3 (Get (Data Quote)) x y) a
              -> Iter (Sum3 (Get (Data Quote)) x y) a
reorderQuotes = reord (T.posixSecondsToUTCTime 0) Set.empty  -- bogus initial pmax
  where
    reord :: T.UTCTime -> Set.Set Quote
            -> Iter (Sum3 (Get (Data Quote)) x y) a
            -> Iter (Sum3 (Get (Data Quote)) x y) a
    reord pmax buf (Finish a) = Finish a
    reord pmax buf (Effect (G Get) k) =
      case Set.minView buf of
        Just (q, buf') ->
          if T.diffUTCTime pmax (acceptTime q) > maxOffset
            then reord pmax buf' (k (Data q))
            else request
        Nothing -> request
      where
        request = Effect (G Get) $ \case
          -- [todo] [fix] handle this case
          NoData -> flush buf (Effect (G Get) k)
          Data q ->
            let pmax' = packetTime q
                -- [todo] [fix] multiple quotes for same accept time
                buf' = Set.insert q buf
            in reord pmax' buf' (Effect (G Get) k)

        flush :: Set.Set Quote
                -> Iter (Sum3 (Get (Data Quote)) x y) a
                -> Iter (Sum3 (Get (Data Quote)) x y) a
        flush buf (Finish a)          = Finish a
        flush buf (Effect (G Get) k)  =
          case Set.minView buf of
            Just (q, buf') -> flush buf' (k (Data q))
            Nothing -> flush buf (k NoData)
        flush buf (Effect e k)        = Effect e (flush buf . k)
    reord pmax buf (Effect e k) = Effect e (reord pmax buf . k)


-- helpers

safeRead :: Read a => String -> Maybe a
safeRead s = case reads s of
    [(x,"")] -> Just x
    _ -> Nothing

logVal :: Show a => a -> a
logVal a = unsafePerformIO $ do
  print a
  return a
