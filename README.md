## Simple BPF hello world in pure C
The code in this repository loads a simple BPF program into the kernel and enable it. It is written with pure C and use no external libraries or frameworks. The purpose of it is educational only, the code is pretty simple and straightforward without extra modularization or flexibility.

Most of the existing examples and BPF program uses external frameworks to utilize the compilation, loading and initialization of the program. While it is good for real use cases, for learning BPF it is help to see a pure C program that does the whole cycle.

### Usage

 - Clone this repo
 - Run the `run.sh` script

### Notes
The example is heavily based on the `kernel_src/sample/bpf/bpf_load.c` example
### Tested
- Arch Linux (5.9.14-arch1-1)

