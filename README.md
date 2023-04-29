# BombPuppy
A miniature packet sniffer

## Compiling
For a regular compilation:
```
make BombPuppy
``` 
For debugging:
```
make debug
```
And to clean:
```
make clean
```
## Running 
BombPuppy requires sudo permissions and can optionally take two options, namely:
### [-n __n_packets__] 
the number of packets to capture 
### [-w __filename__]
redirect standard output to a file
## Known Issues 
* ARP and IPv6 not supported (yet)
