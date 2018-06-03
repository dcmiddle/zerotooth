# Zerotooth
### _A zkSnark experiment with Hyperledger Sawtooth_

## Intro
This repo is work in progress.
It is inspired by and makes use of the tutorials in the [libsnark](https://github.com/scipr-lab/libsnark) project and 
in Howard Wu's separate [libsnark-tutorial](https://github.com/howardwu/libsnark-tutorial)
 project.


The end goal is to demonstrate a Hyperledger Sawtooth Transaction Family
using zkSNARKs to hide information in transactions and in global state. I plan
to riff on the intkey transaction family.

My initial approach was to use gadgetlib2. Encountering a segfault in libsnark
there I switchted to gadgetlib1.
TODO: finish prover method
TODO: finish verifier method
TODO: split out main into a test file. make zk source file a callable lib.
TODO: wrap prover outputs with a generic sawtooth txn client. maybe rust.
TODO: create a Sawtooth Transaction Processor that reads proof & verif. key

## WARNING:
I intend to regularly rebase this until I get things working to my satisfaction.
Fork at your own peril.

## Build
To build & run make sure you have Docker installed and then enter ...

```
# Fetch the dependency source
git submodule update --init --recursive

# Make yourself a dev environment
./build-docker  # builds the docker image for development and running
./run-docker  # drops you into a shell inside the running container

# ----------------------------------------------------------------------------
# From within the dev environment
mkdir build 
cd build
cmake ..
make main
./src/main
```

