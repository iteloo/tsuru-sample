{-# LANGUAGE NoMonomorphismRestriction #-}

module Quote (
    Quote(..)
  , Bid(..)
  , showQuote
) where

import qualified Data.Time as T
import qualified Data.ByteString.Char8 as BS
import Debug.Trace


data Quote = Quote {
    -- [note] `accepTime` must be first for ordering to work correctly!
    acceptTime  :: !T.UTCTime,
    packetTime  :: !T.UTCTime,
    issueCode   :: !BS.ByteString,
    bids        :: ![Bid],
    asks        :: ![Bid]
  } deriving (Eq, Ord)

instance Show Quote where
  show = showQuote

data Bid = Bid {
    price    :: !Int,
    quantity :: !Int
  } deriving (Show, Eq, Ord)

showQuote q = unwords $ fmap ($ q) [
    show . packetTime,
    show . acceptTime,
    BS.unpack . issueCode,
    unwords . fmap showBid . bids,
    unwords . fmap showBid . asks
  ]
  where
    showBid b = (show $ quantity b) ++ "@" ++ (show $ price b)
