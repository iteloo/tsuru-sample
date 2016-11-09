# tsuru-sample
A solution to the problem posed here: http://www.tsurucapital.com/en/code-sample.html

This application processes packet data stored in a pcap dump file using iteratees. The ideas are described in [this paper](http://okmij.org/ftp/Haskell/Iteratee/describe.pdf). Several choices are available for the parsing of the packets themselves: using the `iteratee` library, the `attoparsec` library, or just using the naive `bytestring` operations and the built-in `read`.

## Organization of project
The source files are structured as follows:

|  filepath              | description                                                                              |
|  --------------------- | ----------------------------------                                                       |
| `app/Main.hs`          | CL executable                                                                            |
| `src/Parsing/`         | `attoparsec`, `iteratee`, and vanilla `ByteString` implementation of the quote parser    |
| `src/Streaming/`       | `iteratee` and `myiteratee` implementations of the pcap streaming and quote reordering   |
| `iteratee-0.8.9.6/`    | clone of the `iteratee` library, but with minor modification to satisfy stack's solver   |
| `myiteratee/`          | my own implementation of iteratees                                                       |

## Running this program
Make sure you have `stack` on your system, and run

    stack build

which will install the necessary dependencies and create the executables.
The program can then be run with

    stack exec tsuru-sample-exe -- PROGRAM_OPTS PCAP_FILE

## List of options
The following can also be viewed by running `stack exec tsuru-sample-exe -- --help`.

| option                    | description                                                                   |
| -------------             | --------------------------                                                    |
| `-h`,`--help`             | Show this help text                                                           |
| `-r`,`--reorder`          | Reorder packets based on quote accept time                                    |
| `-s`,`--start INT`        | Starting index for packet (default: 0)                                        |
| `-n`,`--number INT`       | Maximum number of packets to accept                                           |
| `--silent`                | Do not log packets                                                            |
| `-S`,`--streaminglib SLIB`| Streaming library to use. Available options: `iteratee` (default), `myiteratee`. |
| `-P`,`--parsinglib PLIB`  | Parsing library to use. Available options: `attoparsec` (default), `iteratee`, `bytestring`. |
| `-c`,`--chunksize INT`    | Chunk size when using the `iteratee` streaming library (default: 4096)   |
| `--noparse`               | Directly print out packets without parsing                                    |
| `--buffersize INT`        | Size of output buffer. System dependent if unspecified.                       |

## A word about performance

The default settings should give optimal performance. The `iteratee` library supports chunk processing, which allows faster quote reordering. The fastest packet parser out of the three options is `attoparsec`, as it is specialized to parsing bytestrings, and we do not use backtracking. Further speed boost can be achieved by fine-tuning the `--chunksize` and the `--buffersize` option for your particular system.

## A word about timezones

Currently, the program works with a hard-coded list (in `Parsing.Base`) of `Data.Time.LocalTime.TimeZone` objects representing the possible timezones of the sources of the quote data. The program ships with only Tokyo Time (UTC+9) in the list, but the user is free to add more, and the processor will automatically decide for each individual packet which timezone it comes from.
