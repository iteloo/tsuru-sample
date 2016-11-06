{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE NoMonomorphismRestriction #-}

module Attoparsec where

import Quote hiding (asks, bids)

import Control.Monad
import Control.Applicative
import qualified Data.Time as T
import qualified Data.ByteString.Char8 as BS
import qualified Data.Attoparsec.ByteString.Char8 as AP
import Debug.Trace


parseQuote (hdr, bs) = AP.parseOnly (quote (packetAcceptTimeFromHeader hdr)) bs

-- upTil p = many (let one = p <|> (AP.anyChar >> one) in one)

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
  AP.string quoteHeader
  issueCode <- AP.take 12
  AP.take 12
  bs <- bids
  AP.take 7
  as <- asks
  AP.take 50
  aToD <- acceptTimeOfDay
  case extrapolateAcceptTime ptime aToD of
    Nothing -> fail "cannot parse time"
    Just t ->
      return $ Quote t ptime issueCode bs as

bids = AP.count 5 (Bid <$> nDigitNumber 5 <*> nDigitNumber 7)

-- [todo] verify order
asks = reverse <$> bids

acceptTimeOfDay = do
  hh <- nDigitNumber 2
  mm <- nDigitNumber 2
  ss <- nDigitNumber 2
  uu <- nDigitNumber 2
  let pico = fromRational $ ss + uu / 100
  return $ T.TimeOfDay hh mm pico
