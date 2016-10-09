module Helpers where

import System.IO.Unsafe (unsafePerformIO)


safeRead :: Read a => String -> Maybe a
safeRead s = case reads s of
    [(x,"")] -> Just x
    _ -> Nothing

logVal :: Show a => a -> a
logVal a = unsafePerformIO $ do
  print a
  return a
