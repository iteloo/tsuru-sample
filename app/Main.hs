{-# LANGUAGE LambdaCase #-}

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
  -- spec <- readFile "packet_spec"  -- not closed
  -- r <- streamFromFile "packet_spec" getlines
  let header = BS.take 5 . BS.drop 42
  r <- streamPackets "mdf-kospi200.20110216-0.pcap"
          $ filterPackets ((== BS.pack "B6034") . header)
          $ take' 8
          $ getPackets
  print r



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
data PacketIter a = Finish a | GetPacket (Maybe Packet -> PacketIter a)

instance Monad PacketIter where
  return = Finish
  Finish a >>= f = f a
  GetPacket k >>= f = GetPacket (\a -> k a >>= f)

instance Applicative PacketIter where
  pure = return
  (<*>) = ap

instance Functor PacketIter where
  fmap = liftM

streamPackets :: FileName -> PacketIter a -> IO a
streamPackets fname it = do
  handle <- Pcap.openOffline fname
  let process (Finish a) = return a
      process (GetPacket k) = do
          (hdr, bs) <- Pcap.toBS =<< Pcap.next handle
          process (k $ Just bs)
  process it
  -- [todo] close handle?
  -- [todo] handle EOF?

getPacket :: PacketIter (Maybe Packet)
getPacket = GetPacket (Finish . maybe Nothing Just)

-- [hack] using unsafePerformIO, never returns
-- [todo] add IO effect to print as packets are processed
getPackets :: PacketIter ()
getPackets = getPacket >>= \case
    Nothing -> getPackets
    Just p  -> unsafePerformIO $ do
          print $ uncurry parseQuotePacket $ parseUDPPacket p
          return getPackets

take' :: Int -> PacketIter a -> PacketIter a
take' n (Finish a)    = Finish a
take' 0 (GetPacket k) = GetPacket (\_ -> take' 0 (k Nothing))
take' n (GetPacket k) = GetPacket (\p -> take' (n-1) (k p))

filterPackets :: (Packet -> Bool) -> PacketIter a -> PacketIter a
filterPackets c (Finish a) = Finish a
filterPackets c (GetPacket k) = GetPacket (filterPackets c . k .
      (>>= \p -> if c p then Just p else Nothing))

-- file processing

data I a = Done a | GetChar (LChar -> I a)
type LChar = Maybe Char
type FileName = String

instance Monad I where
  return = Done
  Done a >>= f = f a
  GetChar k >>= f = GetChar (\a -> k a >>= f)

instance Applicative I where
  pure = return
  (<*>) = ap

instance Functor I where
  fmap = liftM

streamFromFile :: FileName -> I a -> IO a
streamFromFile fname it = do
    content <- readFile fname  -- [todo] change to stream
    let process _ (Done a) = return a
        process [] (GetChar k) = process [] (k Nothing)
        process (c:cs) (GetChar k) = process cs (k $ Just c)
    process content it

getchar :: I LChar
getchar = GetChar (Done . maybe Nothing Just)

count :: I Int
count = getchar >>= \case
          Nothing -> return 0
          _       -> liftM (+1) count

-- count_old :: I Int
-- count_old = getchar >>= count' 0
--   where count' n (Just _) = getchar >>= count' (n+1)
--         count' n Nothing = return n
--
-- count_oleg :: I Int
-- count_oleg = count' 0
--   where count' n = getchar >>= count'' n
--         count'' n Nothing = return n
--         count'' n _ = count' (n+1)
--
-- count_oleg' :: I Int
-- count_oleg' = go 0
--   where go n = getchar >>= \case
--         Nothing -> return n
--         _       -> go (n+1)

getline :: I (Maybe String)
getline = getchar >>= \case
        Nothing -> return Nothing
        Just c -> liftM Just $ liftM (c:) getline'
  where getline' = getchar >>= \case
          Just '\n' -> return ""
          Nothing   -> return ""
          Just c    -> liftM (c:) getline'

getlines :: I [String]
getlines = getline >>= \case
        Nothing -> return []
        Just l -> liftM (l:) getlines
