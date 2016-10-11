# tsuru-sample
A solution to the problem posed here: http://www.tsurucapital.com/en/code-sample.html

This solution processes data based on the ideas described in [this paper](http://okmij.org/ftp/Haskell/Iteratee/describe.pdf).

## A word about timezones

Currently, the program works with a hard-coded list (in `src/Quote.hs`) of `Data.Time.LocalTime.TimeZone` objects representing the possible timezones of the sources of the quote data. The program ships with only Tokyo Time (UTC+9) in the list, but the user is free to add more, and the processor will automatically decide which timezone each individual packet comes from.

## Organization of project
Four main source files are used in this project

    app/Main.hs
    src/Iter.hs
    src/Quote.hs
    src/Helper.hs

Currently, the timezone

## Running this program
Make sure you have `stack` on your system, and run

    stack build

which will install the necessary dependencies and create the executables.
The program can then be run with

    stack exec tsuru-sample-exe -- -r data.pcap

where `-r` is the optional flag for reordering based on quote accept time,
and `data.pcap` is the `pcap` dump of market data.
