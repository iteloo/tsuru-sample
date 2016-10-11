# tsuru-sample
A solution to the problem posed here: http://www.tsurucapital.com/en/code-sample.html

This solution processes data based on the ideas described in [this paper](http://okmij.org/ftp/Haskell/Iteratee/describe.pdf). 

## Running this program
Make sure you have `stack` on your system, and run

    stack build

which will install the necessary dependencies and create the executables. 
The program can then be run with

    stack exec tsuru-sample-exe -- -r data.pcap

where `-r` is the optional flag for reordering based on quote accept time, 
and `data.pcap` is the `pcap` dump of market data. 
