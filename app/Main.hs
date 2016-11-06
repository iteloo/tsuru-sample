{-# LANGUAGE NoMonomorphismRestriction #-}

module Main where

import qualified Iteratee as I
import qualified Data.Iteratee as I
import qualified Data.Iteratee.IO as I
import Data.Iteratee ((=$), ($=))
import qualified Attoparsec as AP


import Options.Applicative
import Control.Applicative
import Control.Monad.Identity (runIdentity)
import Data.Bifunctor (first)
import Debug.Trace


main :: IO ()
main = execParser opts >>= startApp

startApp :: AppSetting -> IO ()
startApp stg =
  (I.enumPcapFileSingle (filename stg) $
    (I.drop (start stg) >>) $
    (if number stg == (-1) then fmap return else I.take (number stg)) =$
    I.countConsumed $
    I.mapStream (case library stg of
      Iteratee   -> first I.toException . runIdentity . I.parseQuote
      Attoparsec -> first I.iterStrExc . AP.parseQuote) =$
    I.filter (either (const False) (const True)) =$
    I.mapStream (either (error "should be no Nothing here!") id) =$
    (if reordering stg then I.reorderQuotes else fmap return) =$
    I.countConsumed $
    (if silent stg then I.skipToEof else I.logIndiv)
  ) >>= I.run
    >>= \((_,n),m) -> putStrLn
      $ show m ++ " packets processed. " ++ show n ++ " quotes parsed."

data AppSetting = AppSetting {
  reordering  :: Bool,
  start       :: Int,
  number      :: Int,
  silent      :: Bool,
  library     :: Library,
  filename    :: String
}

data Library = Iteratee | Attoparsec
  deriving (Read, Show)

opts = info (helper <*> appSetting)
  ( fullDesc
 <> progDesc "Parses quote data from pcap dump files"
 <> header
      "tsuru-sample - a streaming application for parsing quote data" )

appSetting :: Parser AppSetting
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
  <*> argument str (metavar "FILE")
