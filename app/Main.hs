{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE LambdaCase #-}

module Main where

import qualified Iteratee as I
import qualified Data.Iteratee as I
import qualified Data.Iteratee.IO as I
import Data.Iteratee ((=$), ($=))
import qualified Attoparsec as A
import qualified MyIteratee as MyI

import System.IO
import Options.Applicative
import Control.Monad.Identity (runIdentity)
import Data.Bifunctor (first)
import Debug.Trace


main = execParser opts >>= startApp

startApp stg = do
  hSetBuffering stdout (BlockBuffering (buffersize stg))
  hSetBinaryMode stdout True
  case streaminglib stg of
    SMyIteratee -> let
      begin it =
        MyI.enumPcapFile (filename stg)
          $ MyI.drop (start stg)
          $ maybe id MyI.take (number stg)
          $ it
      end = if silent stg then MyI.getForever else MyI.logForever in
      if noparse stg
        then
          begin
            $ end
        else
          begin
            $ MyI.transform (case parsinglib stg of
                PIteratee  -> eitherToMaybe . runIdentity . I.parseQuote
                PAttoparsec -> eitherToMaybe . A.parseQuote
                PByteString -> MyI.parseQuote )
            $ MyI.filterMaybe
            $ (if reordering stg then MyI.reorderQuotes else id)
            $ end
    SIteratee -> let
      begin it = I.enumPcapFileMany (chunksize stg) (filename stg) $
        (I.drop (start stg) >>) $
        maybe idEnumeratee I.take (number stg) =$
        I.countConsumed $
        it in
      if noparse stg
        then
          (begin $
            (if silent stg then I.skipToEof else I.logIndiv)
          ) >>= I.run
            >>= \(_,m) -> putStrLn
              $ show m ++ " packets processed. 0 quotes parsed."
        else
          (begin $
            I.mapStream (case parsinglib stg of
              PIteratee  -> first I.toException . runIdentity . I.parseQuote
              PAttoparsec -> first I.iterStrExc . A.parseQuote
              PByteString -> maybeToEither (I.iterStrExc "quote parse error")
                . MyI.parseQuote ) =$
            I.filter (either (const False) (const True)) =$
            I.mapStream (either (error "should be no Nothing here!") id) =$
            (if reordering stg then I.reorderQuotes else idEnumeratee) =$
            I.countConsumed $
            (if silent stg then I.skipToEof else I.logIndivQuote)
          ) >>= I.run
            >>= \((_,n),m) -> putStrLn
              $ show m ++ " packets processed. " ++ show n ++ " quotes parsed."
  where
    idEnumeratee = fmap return

data AppSetting = AppSetting {
  reordering   :: Bool,
  start        :: Int,
  number       :: Maybe Int,
  silent       :: Bool,
  streaminglib :: StreamLib,
  parsinglib   :: ParseLib,
  chunksize    :: Int,
  noparse      :: Bool,
  buffersize   :: Maybe Int,
  filename     :: String
}

data ParseLib = PIteratee | PAttoparsec | PByteString
  deriving (Read, Show)

data StreamLib = SIteratee | SMyIteratee
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
  <*> (optional $ option auto
     ( long "number"
    <> short 'n'
    <> help "Maximum number of packets to accept"
    <> metavar "INT" ))
  <*> switch
     ( long "silent"
    <> help "Do not log packets" )
  <*> option streaminglibReader
     ( long "streaminglib"
    <> short 'S'
    <> help "Streaming library to use. \
        \Available options: iteratee (default), myiteratee."
    <> value SIteratee
    <> metavar "SLIB" )
  <*> option parsinglibReader
     ( long "parsinglib"
    <> short 'P'
    <> help "Parsing library to use. \
        \Available options: attoparsec (default), iteratee, bytestring."
    <> value PAttoparsec
    <> metavar "PLIB" )
  <*> option auto
     ( long "chunksize"
    <> short 'c'
    <> help "Chunk size when using the iteratee streaming library"
    <> showDefault
    <> value 4096
    <> metavar "INT" )
  <*> switch
     ( long "noparse"
    <> help "Directly print out packets without parsing" )
  <*> (optional $ option auto
     ( long "buffersize"
    <> help "size of output buffer. System dependent if unspecified."
    <> metavar "INT" ))
  <*> argument str (metavar "FILE")

streaminglibReader = eitherReader $ \case
    "iteratee"    -> Right SIteratee
    "myiteratee"  -> Right SMyIteratee
    _             -> Left "not a supported streaming library option"

parsinglibReader = eitherReader $ \case
    "iteratee"    -> Right PIteratee
    "attoparsec"  -> Right PAttoparsec
    "bytestring"  -> Right PByteString
    _             -> Left "not a supported parsing library option"

-- helper

maybeToEither = flip maybe Right . Left

eitherToMaybe = either (const Nothing) Just
