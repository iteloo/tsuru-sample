{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE NoMonomorphismRestriction #-}

module Main where

import qualified Iteratee as I
import qualified Data.Iteratee as I
import qualified Data.Iteratee.IO as I
import Data.Iteratee ((=$), ($=))
import qualified Attoparsec as AP
import qualified MyIteratee as MyI

import Options.Applicative
import Control.Applicative
import Control.Monad.Identity (runIdentity)
import Data.Bifunctor (first)
import Debug.Trace


main = execParser opts >>= startApp

startApp stg =
  case library stg of
    MyIteratee -> let
      begin it =
        MyI.enumPcapFile (filename stg)
          $ MyI.filter (MyI.hasQuoteHeader . snd)
          $ MyI.drop (start stg)
          $ (if number stg == (-1) then id else MyI.take (number stg))
          $ it
      end = (if silent stg then MyI.getForever else MyI.logForever) in
      if noparse stg
        then
          begin
            $ end
        else
          begin
            $ MyI.transform MyI.parseQuote
            $ MyI.filterMaybe
            $ (if reordering stg then MyI.reorderQuotes else id)
            $ end
    lib -> let
      begin it = I.enumPcapFileMany (chunksize stg) (filename stg) $
        (I.drop (start stg) >>) $
        (if number stg == (-1) then idEnumeratee else I.take (number stg)) =$
        I.countConsumed $
        it
      end = (if silent stg then I.skipToEof else I.logIndiv) in
      if noparse stg
        then
          (begin $
            end
          ) >>= I.run
            >>= \(_,m) -> putStrLn
              $ show m ++ " packets processed. 0 quotes parsed."
        else
          (begin $
            I.mapStream (case lib of
              Iteratee   -> first I.toException . runIdentity . I.parseQuote
              Attoparsec -> first I.iterStrExc . AP.parseQuote
              _          -> error "no more choice of libs") =$
            I.filter (either (const False) (const True)) =$
            I.mapStream (either (error "should be no Nothing here!") id) =$
            (if reordering stg then I.reorderQuotes else idEnumeratee) =$
            I.countConsumed $
            end
          ) >>= I.run
            >>= \((_,n),m) -> putStrLn
              $ show m ++ " packets processed. " ++ show n ++ " quotes parsed."
  where
    idEnumeratee = fmap return

data AppSetting = AppSetting {
  reordering  :: Bool,
  start       :: Int,
  number      :: Int,
  silent      :: Bool,
  library     :: Library,
  chunksize   :: Int,
  noparse     :: Bool,
  filename    :: String
}

data Library = Iteratee | Attoparsec | MyIteratee
  deriving (Read, Show)

opts = info (helper <*> appSetting)
  ( fullDesc
 <> progDesc "Parses quote data from pcap dump files"
 <> header
      "tsuru-sample - a streaming application for parsing quote data" )

appSetting = AppSetting
  <$> switch
     ( long "reorder"
    <> short 'r'
    <> help "Reorder packets based on quote accept time" )
  <*> option auto
     ( long "start"
    <> short 's'
    <> help "Starting index for packet"
    <> showDefault
    <> value 0
    <> metavar "INT" )
  <*> option auto
     ( long "number"
    <> short 'n'
    <> help "Maximum number of packets to accept"
    -- do not show default
    <> value (-1)  -- [hack]
    <> metavar "INT" )
  <*> switch
     ( long "silent"
    <> help "Do not log packets" )
  <*> option auto
     ( long "library"
    <> short 'l'
    <> help "Streaming library to use."
    <> showDefault
    <> value Iteratee
    <> metavar "LIBRARY" )
  <*> option auto
     ( long "chunksize"
    <> short 'c'
    <> help "Chunk size when using the Iteratee and Attoparsec libraries"
    <> showDefault
    <> value 4096
    <> metavar "INT" )
  <*> switch
     ( long "noparse"
    <> help "Directly print out packets without parsing" )
  <*> argument str (metavar "FILE")
