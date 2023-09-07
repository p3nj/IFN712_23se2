# IFN712_23se2

## Table of Contents

- [Introduction](#introduction)
- [Requirements](#requirements)
- [Directory Structure](#directory-structure)
- [Build Process](#build-process)
  - [Compiler and Flags](#compiler-and-flags)
  - [Creating Directories](#creating-directories)
  - [Submodules](#submodules)
  - [Building bad-bpf](#building-bad-bpf)
- [Clean Up](#clean-up)

## Introduction
An example of how a harmless script could be leveraged to attack or harm the system using eBPF vulnerabilities.
This project uses a Makefile to automate the build process. The Makefile includes various targets to compile source files, create necessary directories, and manage Git submodules.

## Requirements
- clang-11
- llvm-11
- GCC Compiler
- Libraries: `curl`, `jansson`
### Ubuntu / Debian
`sudo apt install libcurl4-openssl-dev libjansson-dev`
### Fedora/RHEL/CentOS
`sudo dnf install libcurl-devel jansson-devel`

## Directory Structure

- `src`: Source files
- `obj`: Object files
- `bin`: Executable files
- `btrfs`: BTRFS related source files
- `cc`: Custom C files

## Build Process

### Compiler and Flags

The project uses the GCC compiler with the following flags:

```bash
CC = gcc
CFLAGS = -Wall -std=c11
```
### Creating Directories
The Makefile will create the necessary directories for object and executable files:

```bash
make directories
```

### Submodules
The project uses Git submodules. To initialize and update them, use:

```bash
make init-submodules
make update-submodules
```

### Building bad-bpf
The bad-bpf submodule is a collection of malicious eBPF programs that demonstrate eBPF's ability to read and write user data between the user-mode program and the kernel. This submodule was presented at DEF CON 29. For more details, you can visit the GitHub repository.
[https://github.com/pathtofile/bad-bpf](https://github.com/pathtofile/bad-bpf)

To build bad-bpf, use:

```bash
make build-bad-bpf
```

## Clean Up
To clean up object and executable files, use:

```bash
make clean
```

