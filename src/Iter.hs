{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE BangPatterns #-}

module Iter where

import Prelude hiding (take, drop, filter)
import Control.Monad
import qualified Network.Pcap as Pcap
import qualified Data.ByteString.Char8 as BS
import qualified Data.Set as Set


data Iter e a where
  Finish :: a -> Iter e a
  Effect :: e x -> (x -> Iter e a) -> Iter e a

instance Monad (Iter e) where
  return = Finish
  Finish a >>= f = f a
  Effect e k >>= f = Effect e ((>>= f) . k)

instance Applicative (Iter e) where
  pure = return
  (<*>) = ap

instance Functor (Iter e) where
  fmap = liftM

data Get i x where
  Get :: Get i i

data Printing x where
  Print :: String -> Printing ()

data Exception x where
  Throw :: String -> Exception x

-- [todo] implement using open unions instead
data Sum3 (f :: * -> *) (g :: * -> *) (h :: * -> *) x
    = G (f x) | P (g x) | T (h x)

data Data a = NoData | Data a

type Packet = (Pcap.PktHdr, BS.ByteString)

type FileName = String

-- enumerator for streaming contents of pcap files
streamPackets :: FileName
                  -> Iter (Sum3 (Get (Data Packet)) Printing Exception) a
                  -> IO a
streamPackets fname it = do
  handle <- Pcap.openOffline fname
  let process (Finish a) = return a
      process (Effect (G Get) k) = do
          (hdr, bs) <- Pcap.nextBS handle
          process . k $ if bs == BS.pack ""
            then NoData
            else Data (hdr, bs)
      process (Effect (P (Print s)) k) = do
        putStrLn s
        process (k ())
      process (Effect (T (Throw s)) _) = do
        -- [todo] handle better
        putStrLn s
        error s
  process it
  -- [note] no need/way to close handle


-- get effect

-- get :: Iter (Sum3 (Get a) g h) a
get = Effect (G Get) return

getForever :: Show i => Iter (Sum3 (Get (Data i)) Printing z) ()
getForever = get >>= \case
    NoData -> do
      printS "End of stream"
    Data x -> do
      printS $ show x
      getForever

-- a generator for creating stateful handlers of `Get` requests
handleGetS :: ((s -> Iter (Sum3 (Get i) x y) a -> Iter (Sum3 z x y) a)
              -> s
              -> (i -> Iter (Sum3 (Get i) x y) a)
              -> Iter (Sum3 z x y) a)
            -> s
            -> Iter (Sum3 (Get i) x y) a
            -> Iter (Sum3 z x y) a
handleGetS f s (Finish a) = Finish a
handleGetS f s (Effect (G Get) k) = f (handleGetS f) s k
handleGetS f s (Effect (P e) k) = Effect (P e) (handleGetS f s . k)
handleGetS f s (Effect (T e) k) = Effect (T e) (handleGetS f s . k)

-- stateless version of `handleGetS`
-- handleGet :: ((Iter (Sum3 (Get i) x y) a -> Iter (Sum3 z x y) a)
--               -> (i -> Iter (Sum3 (Get i) x y) a) -> Iter (Sum3 z x y) a)
--         -> Iter (Sum3 (Get i) x y) a -> Iter (Sum3 z x y) a
handleGet f = handleGetS g ()
  where g h _ k = f (h ()) k

-- handleData :: Monad m => (t -> m (Data a)) -> Data t -> m (Data a)
handleData f = \case
  NoData -> return NoData
  Data i -> f i

-- drop :: Int -> Iter (Sum3 (Get (Data i)) x y) a
--               -> Iter (Sum3 (Get (Data i)) x y) a
drop = handleGetS f
  where f h 0 k = get >>= k
        f h n k = get >>= handleData (const get) >>> k .> h (n-1)

-- take :: Int -> Iter (Sum3 (Get (Data i)) x y) a
--             -> Iter (Sum3 (Get (Data i)) x y) a
take = handleGetS f
  where f h 0 k = h 0 (k NoData)
        f h n k = get >>= k .> h (n-1)

-- filter :: (i -> Bool) -> Iter (Sum3 (Get (Data i)) x y) a
--                       -> Iter (Sum3 (Get (Data i)) x y) a
filter c = handleGet f
  where f h k = get >>= handleData (\i -> if c i then return (Data i) else get)
                    >>> k .> h

-- a filter that blocks `Nothing` and output `a` for `Just a`
-- filterMaybe :: Iter (Sum3 (Get (Data i)) x y) a
--               -> Iter (Sum3 (Get (Data (Maybe i))) x y) a
filterMaybe = handleGet f
  where f h k = get >>= handleData (maybe get (return . Data)) >>> k .> h

-- transform :: (a -> b) -> Iter (Sum3 (Get b) x y) c
--                       -> Iter (Sum3 (Get a) x y) c
transform f = handleGet g
  where g h k = get >>= handleData (return . Data . f) >>> k .> h

-- a stateful handler that stores data into a buffer as they
--   are received. The user supplies a conditional that can depend on
--   the most recently inserted item. The subset of data satisfying this
--   condition will be emitted in the correct order.
-- reord'
--   :: Ord a =>
--      (i -> i -> Bool)
--      -> Iter (Sum3 (Get (Data i)) x y) a
--      -> Iter (Sum3 (Get (Data i)) x y) a
-- [think] is Set really the right choice? no duplicate would be stored
reorder cond = handleGetS f (undefined, Set.empty)
  -- [note] no branch where `undefined` is evaluated
  where
    f h (i, buf) k =
      case Set.minView buf of
        Just (i', buf') ->
          if cond i i'
            then h (i, buf') (k (Data i'))
            else request
        Nothing -> request
      where
        request = get >>= \case
          NoData -> handleGetS flush buf (get >>= k)
          Data i ->
            let buf' = Set.insert i buf
            in h (i, buf') (get >>= k)

        flush h buf k =
          case Set.minView buf of
            Just (i, buf') -> h buf' (k (Data i))
            Nothing -> h buf (k NoData)


-- print effect

printS :: String -> Iter (Sum3 x Printing z) ()
printS s = Effect (P $ Print s) return


-- helpers

-- Kleisli composition
(>>>) :: Monad m => (a -> m b) -> (b -> m c) -> a -> m c
(f >>> g) a = f a >>= g
infixl 9 >>>

-- reverse function composition
(.>) :: (a -> b) -> (b -> c) -> a -> c
(.>) = flip (.)
infixl 9 .>
