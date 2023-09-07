# Compiler and Flags
CC = gcc
CFLAGS = -Wall -std=c11

# Directories
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
BTRFS_DIR = $(SRC_DIR)/btrfs
CC_DIR = $(SRC_DIR)/cc

# Libraries for linking
LIBS = -lcurl -ljansson

# Source and Object Files
BTRFS_SRC = $(wildcard $(BTRFS_DIR)/*.c)
CC_SRC = $(wildcard $(CC_DIR)/*.c)
ALL_SRC = $(BTRFS_SRC) $(CC_SRC)

OBJ = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(ALL_SRC))
EXECS = $(patsubst $(SRC_DIR)/%.c, $(BIN_DIR)/%, $(ALL_SRC))

# Phony targets
.PHONY: all clean directories update-submodules init-submodules build-bad-bpf

# Default target
all: directories $(EXECS)

# Create necessary directories
directories:
	@mkdir -p $(OBJ_DIR)/btrfs
	@mkdir -p $(OBJ_DIR)/cc
	@mkdir -p $(BIN_DIR)/btrfs
	@mkdir -p $(BIN_DIR)/cc
	@mkdir -p $(BIN_DIR)

# Initialize and update all submodules and nested submodules
update-submodules:
	git submodule update --remote --recursive

# Initialize all submodules and nested submodules
init-submodules:
	git submodule update --init --recursive

# Update the main project and all submodules
update-all: update-submodules
	git pull origin master
	git commit -m "Updated all submodules"
	git push origin master

build-bad-bpf:
	$(MAKE) -C bad-bpf/src # Replace with the actual path to bad-bpf
	mkdir -p bin/bad-bpf
	mv bad-bpf/src/bin/* bin/bad-bpf/ # Replace with the actual path to bad-bpf binaries


# Compile each source file into its own executable
$(BIN_DIR)/%: $(OBJ_DIR)/%.o
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

# Compile each source file into its own object file
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up
clean:
	@rm -rf $(OBJ_DIR)
	@rm -rf $(BIN_DIR)

