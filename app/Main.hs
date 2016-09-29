{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE PartialTypeSignatures #-}

module Main where

import Lib

import qualified Data.ByteString.Char8 as BS
import qualified Data.Word
import qualified Data.Time.LocalTime as LTime
import qualified Data.Time.Clock as Clock
import Control.Monad
import qualified Network.Pcap as Pcap
import System.IO
import System.IO.Unsafe (unsafePerformIO)

main :: IO ()
main = do
  let header = BS.take 5 . BS.drop 42
  streamPackets "mdf-kospi200.20110216-0.pcap"
    $ filterPackets ((== BS.pack "B6034") . header)
    $ take' 20
    $ getPackets

-- quote ac
-- Your program should print the packet and quote accept times,
-- the issue code,
-- followed by the bids from 5th to 1st,
-- then the asks from 1st to 5th
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

-- extracts a range from a bytestring
range :: Int -> Int -> BS.ByteString -> BS.ByteString
range i n = BS.take n . BS.drop i

-- [todo] actually parse packet time
-- [problem] UTC or local?
parseUDPPacket :: Packet -> (QuotePacket, Clock.DiffTime)
parseUDPPacket p = (range 42 215 p, Clock.picosecondsToDiffTime 0)

-- assumes packet begins with "B6034"
-- and contains the right number of bytes
-- packet time is passed in as an arg
-- [todo] statically verify bytestring lengths, etc, using LiquidHaskell
parseQuotePacket :: QuotePacket -> Clock.DiffTime -> Quote
parseQuotePacket p ptime =
    let parseBids bs = fst $ foldr (\_ (bids, remain) ->
                      let (bid, remain') = BS.splitAt 12 remain
                          (p,q) = BS.splitAt 5 bid
                      in (Bid
                            (read $ BS.unpack p)
                            (read $ BS.unpack q)
                          : bids
                          , remain')  -- [todo] convert to safeRead
                    ) ([],bs) [1..5]
  in Quote {
    packetTime  = ptime,
    acceptTime  = parseTime $ range 206 8 p,
    issueCode   = BS.unpack $ range 5 12 p,  -- [todo] safeRead
    bids        = reverse $ parseBids $ range 29 60 p,
    asks        = parseBids $ range 96 60 p
  }

logVal :: Show a => a -> a
logVal a = unsafePerformIO $ do
    print a
    return a

parseTime :: BS.ByteString -> Clock.DiffTime
parseTime bs =
  let hh = read $ BS.unpack $ range 0 2 bs :: Int
      mm = read $ BS.unpack $ range 2 2 bs :: Int
      ss = read $ BS.unpack $ range 4 2 bs :: Int
      uu = read $ BS.unpack $ range 6 2 bs :: Int
      pico = fromRational $ (fromIntegral ss) + (fromIntegral uu) / 100
  in LTime.timeOfDayToTime $ LTime.TimeOfDay hh mm pico

safeRead :: Read a => String -> Maybe a
safeRead s = case reads s of
    [(x,"")] -> Just x
    _ -> Nothing

-- toAscii :: Data.Word.Word8 -> Char
-- toAscii = toEnum . fromIntegral

-- packet processing


type Packet = BS.ByteString

data PacketIter e a where
  Finish :: a -> PacketIter e a
  GetPacket :: (Maybe Packet -> PacketIter e a) -> PacketIter e a
  OtherEffects :: e x -> (x -> PacketIter e a) -> PacketIter e a

data Printing x where
  Print :: String -> Printing ()

data Exception x where
  Throw :: String -> Exception x

data Sum (f :: * -> *) (g :: * -> *) x = L (f x) | R (g x)

printEff :: String -> PacketIter (Sum Printing e) ()
printEff s = OtherEffects (L $ Print s) return

instance Monad (PacketIter e) where
  return = Finish
  Finish a >>= f = f a
  GetPacket k >>= f = GetPacket (\a -> k a >>= f)
  OtherEffects e k >>= f = OtherEffects e (\a -> k a >>= f)

  -- OtherEffect replaces
  -- Print s k >>= f = Print s (\a -> k a >>= f)
  -- Throw s >>= f = Throw s

instance Applicative (PacketIter e) where
  pure = return
  (<*>) = ap

instance Functor (PacketIter e) where
  fmap = liftM

streamPackets :: FileName -> PacketIter (Sum Printing Exception) a -> IO a
streamPackets fname it = do
  handle <- Pcap.openOffline fname
  let process (Finish a) = return a
      process (GetPacket k) = do
          (hdr, bs) <- Pcap.toBS =<< Pcap.next handle
          process (k $ Just bs)
      process (OtherEffects (L (Print s)) k) = do
        putStrLn s
        process (k ())
      process (OtherEffects (R (Throw s)) _) = do
        -- [todo] handle better
        putStrLn s
        error s
  process it
  -- [todo] close handle?
  -- [todo] handle EOF?

getPacket :: PacketIter e (Maybe Packet)
getPacket = GetPacket (Finish . maybe Nothing Just)

getPackets :: PacketIter _ ()
getPackets = getPacket >>= \case
    Nothing -> getPackets
    Just p -> do
        printEff $ show $ uncurry parseQuotePacket $ parseUDPPacket p
        getPackets

take' :: Int -> PacketIter e a -> PacketIter e a
take' n (Finish a)    = Finish a
take' 0 (GetPacket k) = GetPacket (\_ -> take' 0 (k Nothing))
take' n (GetPacket k) = GetPacket (take' (n-1) . k)
take' n (OtherEffects e k) = OtherEffects e (take' n . k)

filterPackets :: (Packet -> Bool) -> PacketIter e a -> PacketIter e a
filterPackets c (Finish a) = Finish a
filterPackets c (GetPacket k) = GetPacket (filterPackets c . k .
      (>>= \p -> if c p then Just p else Nothing))
filterPackets c (OtherEffects e k) = OtherEffects e (filterPackets c . k)
