{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Ported from Data.Aeson.Encoding.Builder and Data.Aeson.Internal.Time
-- Copyright:   (c) 2011 MailRank, Inc.
--              (c) 2013 Simon Meier <iridcode@gmail.com>

module Builder (
    utcTime
) where

import Data.Fixed (Pico, Fixed(MkFixed))
import Data.Int (Int64)
import Data.Time
import Unsafe.Coerce (unsafeCoerce)

import Data.ByteString.Builder as B
import Data.ByteString.Builder.Prim as BP
import Data.Char (chr)
import Data.Monoid ((<>))
import Data.Time (UTCTime(..))
import Data.Time.Calendar (Day(..), toGregorian)
import Data.Time.LocalTime
import qualified Data.ByteString.Builder.Internal as B
import qualified Data.ByteString.Builder.Prim.Internal as BP


ascii2 :: (Char, Char) -> BP.BoundedPrim a
ascii2 cs = BP.liftFixedToBounded $ const cs BP.>$< BP.char7 >*< BP.char7
{-# INLINE ascii2 #-}

ascii4 :: (Char, (Char, (Char, Char))) -> BP.BoundedPrim a
ascii4 cs = BP.liftFixedToBounded $ const cs >$<
    BP.char7 >*< BP.char7 >*< BP.char7 >*< BP.char7
{-# INLINE ascii4 #-}

ascii5 :: (Char, (Char, (Char, (Char, Char)))) -> BP.BoundedPrim a
ascii5 cs = BP.liftFixedToBounded $ const cs >$<
    BP.char7 >*< BP.char7 >*< BP.char7 >*< BP.char7 >*< BP.char7
{-# INLINE ascii5 #-}
--
ascii6 :: (Char, (Char, (Char, (Char, (Char, Char))))) -> BP.BoundedPrim a
ascii6 cs = BP.liftFixedToBounded $ const cs >$<
    BP.char7 >*< BP.char7 >*< BP.char7 >*< BP.char7 >*< BP.char7 >*< BP.char7
{-# INLINE ascii6 #-}
--
ascii8 :: (Char, (Char, (Char, (Char, (Char, (Char, (Char, Char)))))))
       -> BP.BoundedPrim a
ascii8 cs = BP.liftFixedToBounded $ const cs >$<
    BP.char7 >*< BP.char7 >*< BP.char7 >*< BP.char7 >*<
    BP.char7 >*< BP.char7 >*< BP.char7 >*< BP.char7
{-# INLINE ascii8 #-}

day :: Day -> Builder
day dd = encodeYear yr <>
         BP.primBounded (ascii6 ('-',(mh,(ml,('-',(dh,dl)))))) ()
  where (yr,m,d)    = toGregorian dd
        !(T mh ml)  = twoDigits m
        !(T dh dl)  = twoDigits d
        encodeYear y
            | y >= 1000 = B.integerDec y
            | y > 0 =
                let (ab,c) = fromIntegral y `quotRem` 10
                    (a,b)  = ab `quotRem` 10
                in BP.primBounded (ascii4 ('0',(digit a,(digit b,digit c)))) ()
            | otherwise =
                error "Builder.day:  years BCE not supported"
{-# INLINE day #-}

timeOfDay :: TimeOfDay -> Builder
timeOfDay t = timeOfDay64 (toTimeOfDay64 t)
{-# INLINE timeOfDay #-}

timeOfDay64 :: TimeOfDay64 -> Builder
timeOfDay64 (TOD h m s)
  | frac == 0 = hhmmss -- omit subseconds if 0
  | otherwise = hhmmss <> BP.primBounded showFrac frac
  where
    hhmmss  = BP.primBounded (ascii8 (hh,(hl,(':',(mh,(ml,(':',(sh,sl)))))))) ()
    !(T hh hl)  = twoDigits h
    !(T mh ml)  = twoDigits m
    !(T sh sl)  = twoDigits (fromIntegral real)
    (real,frac) = s `quotRem` pico
    showFrac = (\x -> ('.', x)) >$< (BP.liftFixedToBounded BP.char7 >*< trunc12)
    trunc12 = (`quotRem` micro) >$<
              BP.condB (\(_,y) -> y == 0) (fst >$< trunc6) (digits6 >*< trunc6)
    digits6 = ((`quotRem` milli) . fromIntegral) >$< (digits3 >*< digits3)
    trunc6  = ((`quotRem` milli) . fromIntegral) >$<
              BP.condB (\(_,y) -> y == 0) (fst >$< trunc3) (digits3 >*< trunc3)
    digits3 = (`quotRem` 10) >$< (digits2 >*< digits1)
    digits2 = (`quotRem` 10) >$< (digits1 >*< digits1)
    digits1 = BP.liftFixedToBounded (digit >$< BP.char7)
    trunc3  = BP.condB (== 0) BP.emptyB $
              (`quotRem` 100) >$< (digits1 >*< trunc2)
    trunc2  = BP.condB (== 0) BP.emptyB $
              (`quotRem` 10)  >$< (digits1 >*< trunc1)
    trunc1  = BP.condB (== 0) BP.emptyB digits1

    pico       = 1000000000000 -- number of picoseconds  in 1 second
    micro      =       1000000 -- number of microseconds in 1 second
    milli      =          1000 -- number of milliseconds in 1 second
{-# INLINE timeOfDay64 #-}

dayTime :: Day -> TimeOfDay64 -> Builder
dayTime d t = day d <> B.char7 'T' <> timeOfDay64 t
{-# INLINE dayTime #-}

utcTime :: UTCTime -> B.Builder
utcTime (UTCTime d s) = dayTime d (diffTimeOfDay64 s) <> B.char7 'Z'
{-# INLINE utcTime #-}

data T = T {-# UNPACK #-} !Char {-# UNPACK #-} !Char

twoDigits :: Int -> T
twoDigits a     = T (digit hi) (digit lo)
  where (hi,lo) = a `quotRem` 10

digit :: Int -> Char
digit x = chr (x + 48)


-- helpers

toPico :: Integer -> Pico
toPico = MkFixed

fromPico :: Pico -> Integer
fromPico (MkFixed i) = i

-- | Like TimeOfDay, but using a fixed-width integer for seconds.
data TimeOfDay64 = TOD {-# UNPACK #-} !Int
                       {-# UNPACK #-} !Int
                       {-# UNPACK #-} !Int64

diffTimeOfDay64 :: DiffTime -> TimeOfDay64
diffTimeOfDay64 t = TOD (fromIntegral h) (fromIntegral m) s
  where (h,mp) = fromIntegral pico `quotRem` 3600000000000000
        (m,s)  = mp `quotRem` 60000000000000
        pico   = unsafeCoerce t :: Integer

toTimeOfDay64 :: TimeOfDay -> TimeOfDay64
toTimeOfDay64 (TimeOfDay h m s) = TOD h m (fromIntegral (fromPico s))
