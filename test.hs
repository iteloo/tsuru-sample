import Network.Pcap
import System.IO

main = do
  handle <- openOffline "sample_input.pcap"
  (hdr, payload) <- next handle
  print hdr
