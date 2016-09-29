-- file processing
module FileProcessing where

data I a = Done a | GetChar (LChar -> I a)
type LChar = Maybe Char
type FileName = String

instance Monad I where
  return = Done
  Done a >>= f = f a
  GetChar k >>= f = GetChar (\a -> k a >>= f)

instance Applicative I where
  pure = return
  (<*>) = ap

instance Functor I where
  fmap = liftM

streamFromFile :: FileName -> I a -> IO a
streamFromFile fname it = do
    content <- readFile fname  -- [todo] change to stream
    let process _ (Done a) = return a
        process [] (GetChar k) = process [] (k Nothing)
        process (c:cs) (GetChar k) = process cs (k $ Just c)
    process content it

getchar :: I LChar
getchar = GetChar (Done . maybe Nothing Just)

count :: I Int
count = getchar >>= \case
          Nothing -> return 0
          _       -> liftM (+1) count

-- count_old :: I Int
-- count_old = getchar >>= count' 0
--   where count' n (Just _) = getchar >>= count' (n+1)
--         count' n Nothing = return n
--
-- count_oleg :: I Int
-- count_oleg = count' 0
--   where count' n = getchar >>= count'' n
--         count'' n Nothing = return n
--         count'' n _ = count' (n+1)
--
-- count_oleg' :: I Int
-- count_oleg' = go 0
--   where go n = getchar >>= \case
--         Nothing -> return n
--         _       -> go (n+1)

getline :: I (Maybe String)
getline = getchar >>= \case
        Nothing -> return Nothing
        Just c -> liftM Just $ liftM (c:) getline'
  where getline' = getchar >>= \case
          Just '\n' -> return ""
          Nothing   -> return ""
          Just c    -> liftM (c:) getline'

getlines :: I [String]
getlines = getline >>= \case
        Nothing -> return []
        Just l -> liftM (l:) getlines
