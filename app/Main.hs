{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE AllowAmbiguousTypes #-}

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
  let header = BS.take 5 . BS.drop 42
  streamPackets "mdf-kospi200.20110216-0.pcap"
    $ filter ((== BS.pack "B6034") . header . snd)
    $ take 20
    $ transform (liftM parsePacket)
    $ transform (liftM $ uncurry parseQuotePacket)
    $ getForever

-- quote ac

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
-- returns approximate result (but no exception) if out of bound
range :: Int -> Int -> BS.ByteString -> BS.ByteString
range i n = BS.take n . BS.drop i

-- parses header and UDP packet into
parsePacket :: Packet -> (QuotePacket, Clock.DiffTime)
parsePacket (hdr, p) =
  let s = fromIntegral $ Pcap.hdrSeconds hdr
      ms = fromIntegral $ Pcap.hdrUseconds hdr
      atime = Clock.picosecondsToDiffTime $ 10^12 * s + 10^6 * ms
  in (range 42 215 p, atime)

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
    acceptTime  = parsePacketTime $ range 206 8 p,
    issueCode   = BS.unpack $ range 5 12 p,  -- [todo] safeRead
    bids        = reverse $ parseBids $ range 29 60 p,
    asks        = parseBids $ range 96 60 p
  }

-- assumes input is a bytestring of 8 digits
parsePacketTime :: BS.ByteString -> Clock.DiffTime
parsePacketTime bs =
  let hh = read $ BS.unpack $ range 0 2 bs :: Int
      mm = read $ BS.unpack $ range 2 2 bs :: Int
      ss = read $ BS.unpack $ range 4 2 bs :: Int
      uu = read $ BS.unpack $ range 6 2 bs :: Int
      pico = fromRational $ (fromIntegral ss) + (fromIntegral uu) / 100
  in LTime.timeOfDayToTime $ LTime.TimeOfDay hh mm pico


-- iteratees

type Packet = (Pcap.PktHdr, BS.ByteString)

data Iter e a where
  Finish :: a -> Iter e a
  Effect :: e x -> (x -> Iter e a) -> Iter e a

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

class Member e es where
  inj :: e x -> es x
  prj :: es x -> Maybe (e x)

instance (i ~ i') => Member (Get i) (Sum (Get i') y z) where
  inj = G
  prj = \case
    G x -> Just x
    _ -> Nothing

printEff :: String -> Iter (Sum _ Printing _) ()
printEff s = Effect (P $ Print s) return

instance Monad (Iter e) where
  return = Finish
  Finish a >>= f = f a
  Effect e k >>= f = Effect e (\a -> k a >>= f)

instance Applicative (Iter e) where
  pure = return
  (<*>) = ap

instance Functor (Iter e) where
  fmap = liftM

type FileName = String

streamPackets :: FileName
                  -> Iter (Sum GetPacket Printing Exception) a
                  -> IO a
streamPackets fname it = do
  handle <- Pcap.openOffline fname
  let process (Finish a) = return a
      process (Effect (G Get) k) = do
          p <- Pcap.toBS =<< Pcap.next handle
          process (k $ Just p)
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

get :: Iter _ (Maybe a)
get = Effect (G Get) Finish

getForever :: Iter _ ()
getForever = get >>= \case
    Nothing -> getForever
    Just p -> do
        printEff $ show p
        getForever

take :: forall i e a . Member (Get (Maybe i)) e
            => Int -> Iter e a -> Iter e a
take n (Finish a)   = Finish a
take 0 (Effect e k) | Just Get <- prj e :: Maybe (Get (Maybe i) _)
                    = Effect e (\_ -> take 0 (k Nothing))
take n (Effect e k) | Just Get <- prj e :: Maybe (Get (Maybe i) _)
                    = Effect e (take (n-1) . k)
take n (Effect e k) = Effect e (take n . k)

filter :: forall i e a . Member (Get (Maybe i)) e
            => (i -> Bool) -> Iter e a -> Iter e a
filter c (Finish a)   = Finish a
filter c (Effect e k) | Just Get <- prj e :: Maybe (Get (Maybe i) _)
                      = Effect e (filter c . k .
                          (>>= \p -> if c p then Just p else Nothing))
filter c (Effect e k) = Effect e (filter c . k)

transform :: (a -> b) -> Iter (Sum (Get b) x y) c
                      -> Iter (Sum (Get a) x y) c
transform f (Finish a)          = Finish a
transform f (Effect (G Get) k)  = Effect (G Get) (transform f . k . f)
transform f (Effect (P e) k)    = Effect (P e) (transform f . k)
transform f (Effect (T e) k)    = Effect (T e) (transform f . k)


-- helpers

safeRead :: Read a => String -> Maybe a
safeRead s = case reads s of
    [(x,"")] -> Just x
    _ -> Nothing
