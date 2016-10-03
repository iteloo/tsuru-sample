{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE PartialTypeSignatures #-}

module Main where

import Lib

import Prelude hiding (take, filter)
import qualified Network.Pcap as Pcap
import qualified Data.ByteString.Char8 as BS
import qualified Data.Time.LocalTime as LTime
import qualified Data.Time.Clock as Clock
import Control.Monad


main :: IO ()
main = do
    streamPackets "mdf-kospi200.20110216-0.pcap"
      $ filter (maybe False (== BS.pack "B6034") . header . snd)
      $ take 20  -- [todo] remove on final version
      $ transform (liftM quoteFromPacket)
      $ getForever
  where header = range 42 5

-- quote parsing
-- [todo] statically verify bytestring lengths and formats using LiquidHaskell

type Packet = (Pcap.PktHdr, BS.ByteString)

type Payload = BS.ByteString

type QuotePacket = BS.ByteString

data Quote = Quote {
    packetTime  :: Clock.DiffTime,
    acceptTime  :: Clock.DiffTime,
    issueCode   :: String,
    bids        :: [Bid],
    asks        :: [Bid]
  } deriving (Show)

data Bid = Bid {
    price :: Int,
    quantity :: Int
  } deriving (Show)

-- extracts substring of length `n` at location `i` of a bytestring
-- returns Nothing if out of bound
range :: Int -> Int -> BS.ByteString -> Maybe BS.ByteString
range i n bs =
  let bs' = BS.take n . BS.drop i $ bs in
  if n == BS.length bs' then Just bs' else Nothing

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
packetAcceptTimeFromHeader :: Pcap.PktHdr -> Clock.DiffTime
packetAcceptTimeFromHeader hdr =
  let s     = fromIntegral $ Pcap.hdrSeconds hdr
      ms    = fromIntegral $ Pcap.hdrUseconds hdr
  in Clock.picosecondsToDiffTime $ 10^12 * s + 10^6 * ms

-- constructs quote object from quote packet and packet accept time
-- does not check that quote packet begins with "B6034"
quoteFromQuotePacket :: QuotePacket -> Clock.DiffTime -> Maybe Quote
quoteFromQuotePacket p ptime = do
  acceptTime <- parseAcceptTime =<< range 206 8 p
  issueCode <- liftM BS.unpack $ range 5 12 p
  bids <- parseBids =<< range 29 60 p
  asks <- parseBids =<< range 96 60 p
  return Quote {
    packetTime  = ptime,
    acceptTime  = acceptTime,
    issueCode   = issueCode,
    bids        = reverse bids,
    asks        = asks
  }
  where
    -- assumes input is a bytestring of 8 digits
    parseAcceptTime :: BS.ByteString -> Maybe Clock.DiffTime
    parseAcceptTime bs = do
      hh <- safeRead =<< liftM BS.unpack (range 0 2 bs)
      mm <- safeRead =<< liftM BS.unpack (range 2 2 bs)
      ss <- safeRead =<< liftM BS.unpack (range 4 2 bs)
      uu <- safeRead =<< liftM BS.unpack (range 6 2 bs)
      let pico = fromRational $ (fromIntegral ss) + (fromIntegral uu) / 100
      return $ LTime.timeOfDayToTime $ LTime.TimeOfDay hh mm pico

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
          p <- Pcap.toBS =<< Pcap.next handle
          process (k $ Data p)
      process (Effect (P (Print s)) k) = do
        putStrLn s
        process (k ())
      process (Effect (T (Throw s)) _) = do
        -- [todo] handle better
        putStrLn s
        error s
  process it
  -- [todo] close handle?
  -- [todo] handle EOF?

get :: Iter _ (Data a)
get = Effect (G Get) Finish

getForever :: Iter _ ()
getForever = do
  a <- get
  let msg = case a of
        NoData -> "End of stream"
        Data x -> show x
  printEff msg
  getForever

take :: Int -> Iter (Sum3 (Get (Data i)) x y) a
            -> Iter (Sum3 (Get (Data i)) x y) a
take n (Finish a)    = Finish a
take 0 (Effect (G Get) k) = Effect (G Get) (\_ -> take 0 (k NoData))
take n (Effect (G Get) k) = Effect (G Get) (take (n-1) . k)
take n (Effect e k) = Effect e (take n . k)

filter :: (i -> Bool) -> Iter (Sum3 (Get (Data i)) x y) a
                      -> Iter (Sum3 (Get (Data i)) x y) a
filter c (Finish a) = Finish a
filter c e@(Effect (G Get) k) = Effect (G Get) (filter c . loop)
    where loop NoData  = k NoData
          loop (Data i) = if c i then k (Data i) else e
filter c (Effect e k) = Effect e (filter c . k)

transform :: (a -> b) -> Iter (Sum3 (Get b) x y) c
                      -> Iter (Sum3 (Get a) x y) c
transform f (Finish a)          = Finish a
transform f (Effect (G Get) k)  = Effect (G Get) (transform f . k . f)
transform f (Effect (P e) k)    = Effect (P e) (transform f . k)
transform f (Effect (T e) k)    = Effect (T e) (transform f . k)


-- helpers

safeRead :: Read a => String -> Maybe a
safeRead s = case reads s of
    [(x,"")] -> Just x
    _ -> Nothing
