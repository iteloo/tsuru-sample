module Streaming.Builder.Quote (
    quoteBuilder
) where

import Quote
import Streaming.Builder.UTCTime (utcTime)

import qualified Data.ByteString.Builder as BS
import Data.Monoid ((<>))


-- faster bytestring builder version
-- can fold inline twice given a list literal?
quoteBuilder q = unwordsBuilder (fmap ($ q) [
    utcTime . packetTime,
    utcTime . acceptTime,
    BS.byteString . issueCode,
    unwordsBuilder . fmap quoteBuilder . bids,
    unwordsBuilder . fmap quoteBuilder . asks
  ]) <> BS.char7 '\n'
  where
    quoteBuilder b = BS.intDec (quantity b) <> BS.char7 '@' <> BS.intDec (price b)

-- [question] can fold inline twice given a list literal?
-- i.e. will `quoteBuilder` get expanded to:
-- (answer seems to be "yes" from profiling)
-- quoteBuilder q =
--     (A.utcTime . packetTime $ q) <> BS.char7 ' '
--     <> (A.utcTime . acceptTime $ q) <> BS.char7 ' '
--     <> (BS.byteString . issueCode $ q) <> BS.char7 ' '
--     <> BS.intDec (quantity (bids q !! 0)) <> BS.char7 '@'
--     <> BS.intDec (price (bids q !! 0)) <> BS.char7 ' '
--     <> BS.intDec (quantity (bids q !! 1)) <> BS.char7 '@'
--     <> BS.intDec (price (bids q !! 1)) <> BS.char7 ' '
--     <> BS.intDec (quantity (bids q !! 2)) <> BS.char7 '@'
--     <> BS.intDec (price (bids q !! 2)) <> BS.char7 ' '
--     <> BS.intDec (quantity (bids q !! 3)) <> BS.char7 '@'
--     <> BS.intDec (price (bids q !! 3)) <> BS.char7 ' '
--     <> BS.intDec (quantity (bids q !! 4)) <> BS.char7 '@'
--     <> BS.intDec (price (bids q !! 4)) <> BS.char7 ' '
--     <> BS.intDec (quantity (asks q !! 0)) <> BS.char7 '@'
--     <> BS.intDec (price (asks q !! 0)) <> BS.char7 ' '
--     <> BS.intDec (quantity (asks q !! 1)) <> BS.char7 '@'
--     <> BS.intDec (price (asks q !! 1)) <> BS.char7 ' '
--     <> BS.intDec (quantity (asks q !! 2)) <> BS.char7 '@'
--     <> BS.intDec (price (asks q !! 2)) <> BS.char7 ' '
--     <> BS.intDec (quantity (asks q !! 3)) <> BS.char7 '@'
--     <> BS.intDec (price (asks q !! 3)) <> BS.char7 ' '
--     <> BS.intDec (quantity (asks q !! 4)) <> BS.char7 '@'
--     <> BS.intDec (price (asks q !! 4)) <> BS.char7 '\n'

unwordsBuilder :: [BS.Builder] -> BS.Builder
unwordsBuilder = foldr1 (\w s -> w <> BS.char7 ' ' <> s)
{-# INLINE unwordsBuilder #-}
