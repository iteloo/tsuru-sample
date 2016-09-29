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
  Effect :: e x -> (x -> PacketIter e a) -> PacketIter e a

data Get i x where
  Get :: Get i i

type GetPacket = Get (Maybe Packet)

data Printing x where
  Print :: String -> Printing ()

data Exception x where
  Throw :: String -> Exception x

-- [todo] implement using open unions instead
data Sum (f :: * -> *) (g :: * -> *) (h :: * -> *) x
    = G (f x) | P (g x) | T (h x)

printEff :: String -> PacketIter (Sum _ Printing _) ()
printEff s = Effect (P $ Print s) return

instance Monad (PacketIter e) where
  return = Finish
  Finish a >>= f = f a
  Effect e k >>= f = Effect e (\a -> k a >>= f)

instance Applicative (PacketIter e) where
  pure = return
  (<*>) = ap

instance Functor (PacketIter e) where
  fmap = liftM

type FileName = String

streamPackets :: FileName
                  -> PacketIter (Sum GetPacket Printing Exception) a
                  -> IO a
streamPackets fname it = do
  handle <- Pcap.openOffline fname
  let process (Finish a) = return a
      process (Effect (G Get) k) = do
          (hdr, bs) <- Pcap.toBS =<< Pcap.next handle
          process (k $ Just bs)
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

getPacket :: PacketIter (Sum GetPacket _ _) (Maybe Packet)
getPacket = Effect (G Get) Finish

getPackets :: PacketIter _ ()
getPackets = getPacket >>= \case
    Nothing -> getPackets
    Just p -> do
        printEff $ show $ uncurry parseQuotePacket $ parseUDPPacket p
        getPackets

take' :: Int -> PacketIter (Sum (Get (Maybe i)) x y) a
              -> PacketIter (Sum (Get (Maybe i)) x y) a
take' n (Finish a)    = Finish a
take' 0 (Effect (G Get) k) = Effect (G Get) (\_ -> take' 0 (k Nothing))
take' n (Effect (G Get) k) = Effect (G Get) (take' (n-1) . k)
take' n (Effect e k) = Effect e (take' n . k)

filterPackets :: (i -> Bool)
                      -> PacketIter (Sum (Get (Maybe i)) x y) a
                      -> PacketIter (Sum (Get (Maybe i)) x y) a
filterPackets c (Finish a) = Finish a
filterPackets c (Effect (G Get) k) = Effect (G Get) (filterPackets c . k .
      (>>= \p -> if c p then Just p else Nothing))
filterPackets c (Effect e k) = Effect e (filterPackets c . k)
