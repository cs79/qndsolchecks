## What is this?

Quick and dirty regular-expression based Solidity developer hints. The example Solidity programs in this repository are taken from Trail of Bits' [(Not So) Smart Contracts](https://github.com/crytic/not-so-smart-contracts). This is not intended to be a replacement for any of their excellent open-source code analysis tools; rather an exploration of the effectiveness of heuristic suggestions "further to the left" during Solidity development, with minimal up-front tool development effort required. While this is a command line tool for expediency, it is intended as a proof of concept for "live" suggestions to developers in their editors.

## Usage

To run the checks on a Solidity source file:

`python qndsol.py <path_to_source_file>`

## Checks implemented

This tool currently runs (non-comprehensive, heuristic) checks for the following:

* Potential use of random functions in smart contracts
* Loops containing transfers that may be potentially DOS'd by an attacker
* Required transfers that facilitate DOS attacks on subsequent code
* Requirements on contracts' ether balances that may be susceptible to forced ether send attacks
* Potentially unsafe integer arithmetic
* Reentrancy vulnerability due to use of `call.value()`
* Potential silent failures on external calls
* Unprotected public functions
* Missing contract constructors

The framework is easily extensible to other checks as can be seen in the source.
