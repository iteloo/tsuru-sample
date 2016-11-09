{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE NoMonomorphismRestriction #-}

module Parsing.Attoparsec (
    parseQuote
) where

import Parsing.Base hiding (asks, bids)

import Control.Monad
import Control.Applicative
import qualified Data.Time as T
import qualified Data.ByteString.Char8 as BS
import qualified Data.Attoparsec.ByteString.Char8 as AP
import Debug.Trace


parseQuote (hdr, bs) = AP.parseOnly (quote (packetAcceptTimeFromHeader hdr)) bs

nDigitNumber n = AP.take n
  >>= either fail return . AP.parseOnly (AP.decimal <* AP.endOfInput)

quote ptime = do
  AP.take 42
  AP.string quoteHeader
  -- [note] the following can be used instead if the header had variable
  --   locations, which is not the case for the sample input, though better
  --   solution without backtracking is preferred: 
  -- AP.manyTill AP.anyChar (AP.string quoteHeader)
  issueCode <- AP.take 12
  AP.take 12
  bs <- bids
  AP.take 7
  as <- asks
  AP.take 50
  aToD <- acceptTimeOfDay
  case extrapolateAcceptTime ptime aToD of
    Nothing -> fail "cannot parse time"
    Just t -> return $ Quote t ptime issueCode bs as

-- partly applicative version of `quote`
-- [question] why is this slightly slower than the
--   fully monadic version? is it due to tuple packing?
-- quote ptime = do
--   (issueCode, bs, as) <- (,,)
--     <$ AP.take 42
--     <* AP.string quoteHeader
--     <*> AP.take 12
--     <* AP.take 12
--     <*> bids
--     <* AP.take 7
--     <*> asks
--     <* AP.take 50
--   aToD <- acceptTimeOfDay
--   case extrapolateAcceptTime ptime aToD of
--     Nothing -> fail "cannot parse time"
--     Just t ->
--       return $ Quote t ptime issueCode bs as

bids = AP.count 5 (Bid <$> nDigitNumber 5 <*> nDigitNumber 7)

-- [todo] verify order
asks = reverse <$> bids

acceptTimeOfDay = do
  hh <- nDigitNumber 2
  mm <- nDigitNumber 2
  ss <- nDigitNumber 2
  uu <- nDigitNumber 2
  let pico = fromRational $ fromIntegral ss + fromIntegral uu / 100
  return $ T.TimeOfDay hh mm pico
