# Bulletproofs in Python

We use pyo3 to wrap the [bulletproof implementation by dalek-cryptography][https://github.com/dalek-cryptography/bulletproofs/blob/main/README.md] in python.

## Dependency

- Python 3.8 and up
- Rust 1.62.0-nightly (60e50fc1c 2022-04-04) and up

## Building

We first create a python virtual environment, activate it, and install [`maturin`](https://github.com/PyO3/maturin) into the virtual environment.

```bash
$ python -m venv .env
$ source .env/bin/activate
$ pip install maturin
```

To compile the Rust implementation into a python library, run the following code snippet.

```bash
$ maturin init
$ maturin develop
```

To test the python library, run the following proof and verification.

```bash
from zkrp_pyo3 import zkrp_prove, zkrp_verify

comm1, proof1 = zkrp_prove(2022)
comm2, proof2 = zkrp_prove(2023)

assert zkrp_verify(comm1, proof1)
assert !zkrp_verify(comm1, proof2)
```
