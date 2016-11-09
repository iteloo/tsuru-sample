{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE NoMonomorphismRestriction #-}

module Parsing.Iteratee (
    parseQuote
) where

import Parsing.Base hiding (asks, bids)

import qualified Data.Iteratee as I
import Data.Iteratee ((=$), ($=))
import qualified Data.ListLike as LL

import Control.Applicative
import qualified Data.Time as T
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Builder as BS
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
