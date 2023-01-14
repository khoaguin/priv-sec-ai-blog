# What is Hybrid Homomorphic Encryption
Some demonstration code for HHE in C++ based on [Microsoft's SEAL](https://github.com/microsoft/SEAL) and [PASTA library](https://github.com/IAIK/hybrid-HE-framework)

## Requirements
`cpp==9.4.0`   
`CMAKE>=3.13`  
`SEAL==4.0.0`  

## Running
- `cmake -S . -B build -DCMAKE_PREFIX_PATH=libs/seal`  
Here, `-DCMAKE_PREFIX_PATH` specifies the path to the installed SEAL library.
- `cmake --build build`
- Run the compiled binary, for example `./build/WhatIsHHE`