# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/Cellar/cmake/3.22.3/bin/cmake

# The command to remove a file.
RM = /usr/local/Cellar/cmake/3.22.3/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/christinapeterson/Documents/Walletkit/walletkit/build

# Include any dependencies generated for this target.
include CMakeFiles/yajl.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/yajl.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/yajl.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/yajl.dir/flags.make

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_alloc.c.o: CMakeFiles/yajl.dir/flags.make
CMakeFiles/yajl.dir/vendor/yajl/src/yajl_alloc.c.o: /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_alloc.c
CMakeFiles/yajl.dir/vendor/yajl/src/yajl_alloc.c.o: CMakeFiles/yajl.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/christinapeterson/Documents/Walletkit/walletkit/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/yajl.dir/vendor/yajl/src/yajl_alloc.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/yajl.dir/vendor/yajl/src/yajl_alloc.c.o -MF CMakeFiles/yajl.dir/vendor/yajl/src/yajl_alloc.c.o.d -o CMakeFiles/yajl.dir/vendor/yajl/src/yajl_alloc.c.o -c /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_alloc.c

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_alloc.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/yajl.dir/vendor/yajl/src/yajl_alloc.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_alloc.c > CMakeFiles/yajl.dir/vendor/yajl/src/yajl_alloc.c.i

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_alloc.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/yajl.dir/vendor/yajl/src/yajl_alloc.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_alloc.c -o CMakeFiles/yajl.dir/vendor/yajl/src/yajl_alloc.c.s

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_buf.c.o: CMakeFiles/yajl.dir/flags.make
CMakeFiles/yajl.dir/vendor/yajl/src/yajl_buf.c.o: /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_buf.c
CMakeFiles/yajl.dir/vendor/yajl/src/yajl_buf.c.o: CMakeFiles/yajl.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/christinapeterson/Documents/Walletkit/walletkit/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/yajl.dir/vendor/yajl/src/yajl_buf.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/yajl.dir/vendor/yajl/src/yajl_buf.c.o -MF CMakeFiles/yajl.dir/vendor/yajl/src/yajl_buf.c.o.d -o CMakeFiles/yajl.dir/vendor/yajl/src/yajl_buf.c.o -c /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_buf.c

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_buf.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/yajl.dir/vendor/yajl/src/yajl_buf.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_buf.c > CMakeFiles/yajl.dir/vendor/yajl/src/yajl_buf.c.i

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_buf.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/yajl.dir/vendor/yajl/src/yajl_buf.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_buf.c -o CMakeFiles/yajl.dir/vendor/yajl/src/yajl_buf.c.s

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_encode.c.o: CMakeFiles/yajl.dir/flags.make
CMakeFiles/yajl.dir/vendor/yajl/src/yajl_encode.c.o: /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_encode.c
CMakeFiles/yajl.dir/vendor/yajl/src/yajl_encode.c.o: CMakeFiles/yajl.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/christinapeterson/Documents/Walletkit/walletkit/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/yajl.dir/vendor/yajl/src/yajl_encode.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/yajl.dir/vendor/yajl/src/yajl_encode.c.o -MF CMakeFiles/yajl.dir/vendor/yajl/src/yajl_encode.c.o.d -o CMakeFiles/yajl.dir/vendor/yajl/src/yajl_encode.c.o -c /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_encode.c

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_encode.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/yajl.dir/vendor/yajl/src/yajl_encode.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_encode.c > CMakeFiles/yajl.dir/vendor/yajl/src/yajl_encode.c.i

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_encode.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/yajl.dir/vendor/yajl/src/yajl_encode.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_encode.c -o CMakeFiles/yajl.dir/vendor/yajl/src/yajl_encode.c.s

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_gen.c.o: CMakeFiles/yajl.dir/flags.make
CMakeFiles/yajl.dir/vendor/yajl/src/yajl_gen.c.o: /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_gen.c
CMakeFiles/yajl.dir/vendor/yajl/src/yajl_gen.c.o: CMakeFiles/yajl.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/christinapeterson/Documents/Walletkit/walletkit/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/yajl.dir/vendor/yajl/src/yajl_gen.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/yajl.dir/vendor/yajl/src/yajl_gen.c.o -MF CMakeFiles/yajl.dir/vendor/yajl/src/yajl_gen.c.o.d -o CMakeFiles/yajl.dir/vendor/yajl/src/yajl_gen.c.o -c /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_gen.c

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_gen.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/yajl.dir/vendor/yajl/src/yajl_gen.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_gen.c > CMakeFiles/yajl.dir/vendor/yajl/src/yajl_gen.c.i

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_gen.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/yajl.dir/vendor/yajl/src/yajl_gen.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_gen.c -o CMakeFiles/yajl.dir/vendor/yajl/src/yajl_gen.c.s

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_lex.c.o: CMakeFiles/yajl.dir/flags.make
CMakeFiles/yajl.dir/vendor/yajl/src/yajl_lex.c.o: /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_lex.c
CMakeFiles/yajl.dir/vendor/yajl/src/yajl_lex.c.o: CMakeFiles/yajl.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/christinapeterson/Documents/Walletkit/walletkit/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/yajl.dir/vendor/yajl/src/yajl_lex.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/yajl.dir/vendor/yajl/src/yajl_lex.c.o -MF CMakeFiles/yajl.dir/vendor/yajl/src/yajl_lex.c.o.d -o CMakeFiles/yajl.dir/vendor/yajl/src/yajl_lex.c.o -c /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_lex.c

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_lex.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/yajl.dir/vendor/yajl/src/yajl_lex.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_lex.c > CMakeFiles/yajl.dir/vendor/yajl/src/yajl_lex.c.i

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_lex.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/yajl.dir/vendor/yajl/src/yajl_lex.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_lex.c -o CMakeFiles/yajl.dir/vendor/yajl/src/yajl_lex.c.s

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_parser.c.o: CMakeFiles/yajl.dir/flags.make
CMakeFiles/yajl.dir/vendor/yajl/src/yajl_parser.c.o: /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_parser.c
CMakeFiles/yajl.dir/vendor/yajl/src/yajl_parser.c.o: CMakeFiles/yajl.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/christinapeterson/Documents/Walletkit/walletkit/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object CMakeFiles/yajl.dir/vendor/yajl/src/yajl_parser.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/yajl.dir/vendor/yajl/src/yajl_parser.c.o -MF CMakeFiles/yajl.dir/vendor/yajl/src/yajl_parser.c.o.d -o CMakeFiles/yajl.dir/vendor/yajl/src/yajl_parser.c.o -c /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_parser.c

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_parser.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/yajl.dir/vendor/yajl/src/yajl_parser.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_parser.c > CMakeFiles/yajl.dir/vendor/yajl/src/yajl_parser.c.i

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_parser.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/yajl.dir/vendor/yajl/src/yajl_parser.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_parser.c -o CMakeFiles/yajl.dir/vendor/yajl/src/yajl_parser.c.s

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_tree.c.o: CMakeFiles/yajl.dir/flags.make
CMakeFiles/yajl.dir/vendor/yajl/src/yajl_tree.c.o: /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_tree.c
CMakeFiles/yajl.dir/vendor/yajl/src/yajl_tree.c.o: CMakeFiles/yajl.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/christinapeterson/Documents/Walletkit/walletkit/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building C object CMakeFiles/yajl.dir/vendor/yajl/src/yajl_tree.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/yajl.dir/vendor/yajl/src/yajl_tree.c.o -MF CMakeFiles/yajl.dir/vendor/yajl/src/yajl_tree.c.o.d -o CMakeFiles/yajl.dir/vendor/yajl/src/yajl_tree.c.o -c /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_tree.c

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_tree.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/yajl.dir/vendor/yajl/src/yajl_tree.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_tree.c > CMakeFiles/yajl.dir/vendor/yajl/src/yajl_tree.c.i

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_tree.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/yajl.dir/vendor/yajl/src/yajl_tree.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_tree.c -o CMakeFiles/yajl.dir/vendor/yajl/src/yajl_tree.c.s

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_version.c.o: CMakeFiles/yajl.dir/flags.make
CMakeFiles/yajl.dir/vendor/yajl/src/yajl_version.c.o: /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_version.c
CMakeFiles/yajl.dir/vendor/yajl/src/yajl_version.c.o: CMakeFiles/yajl.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/christinapeterson/Documents/Walletkit/walletkit/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building C object CMakeFiles/yajl.dir/vendor/yajl/src/yajl_version.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/yajl.dir/vendor/yajl/src/yajl_version.c.o -MF CMakeFiles/yajl.dir/vendor/yajl/src/yajl_version.c.o.d -o CMakeFiles/yajl.dir/vendor/yajl/src/yajl_version.c.o -c /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_version.c

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_version.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/yajl.dir/vendor/yajl/src/yajl_version.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_version.c > CMakeFiles/yajl.dir/vendor/yajl/src/yajl_version.c.i

CMakeFiles/yajl.dir/vendor/yajl/src/yajl_version.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/yajl.dir/vendor/yajl/src/yajl_version.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl_version.c -o CMakeFiles/yajl.dir/vendor/yajl/src/yajl_version.c.s

CMakeFiles/yajl.dir/vendor/yajl/src/yajl.c.o: CMakeFiles/yajl.dir/flags.make
CMakeFiles/yajl.dir/vendor/yajl/src/yajl.c.o: /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl.c
CMakeFiles/yajl.dir/vendor/yajl/src/yajl.c.o: CMakeFiles/yajl.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/christinapeterson/Documents/Walletkit/walletkit/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building C object CMakeFiles/yajl.dir/vendor/yajl/src/yajl.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/yajl.dir/vendor/yajl/src/yajl.c.o -MF CMakeFiles/yajl.dir/vendor/yajl/src/yajl.c.o.d -o CMakeFiles/yajl.dir/vendor/yajl/src/yajl.c.o -c /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl.c

CMakeFiles/yajl.dir/vendor/yajl/src/yajl.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/yajl.dir/vendor/yajl/src/yajl.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl.c > CMakeFiles/yajl.dir/vendor/yajl/src/yajl.c.i

CMakeFiles/yajl.dir/vendor/yajl/src/yajl.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/yajl.dir/vendor/yajl/src/yajl.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore/vendor/yajl/src/yajl.c -o CMakeFiles/yajl.dir/vendor/yajl/src/yajl.c.s

# Object files for target yajl
yajl_OBJECTS = \
"CMakeFiles/yajl.dir/vendor/yajl/src/yajl_alloc.c.o" \
"CMakeFiles/yajl.dir/vendor/yajl/src/yajl_buf.c.o" \
"CMakeFiles/yajl.dir/vendor/yajl/src/yajl_encode.c.o" \
"CMakeFiles/yajl.dir/vendor/yajl/src/yajl_gen.c.o" \
"CMakeFiles/yajl.dir/vendor/yajl/src/yajl_lex.c.o" \
"CMakeFiles/yajl.dir/vendor/yajl/src/yajl_parser.c.o" \
"CMakeFiles/yajl.dir/vendor/yajl/src/yajl_tree.c.o" \
"CMakeFiles/yajl.dir/vendor/yajl/src/yajl_version.c.o" \
"CMakeFiles/yajl.dir/vendor/yajl/src/yajl.c.o"

# External object files for target yajl
yajl_EXTERNAL_OBJECTS =

libyajl.a: CMakeFiles/yajl.dir/vendor/yajl/src/yajl_alloc.c.o
libyajl.a: CMakeFiles/yajl.dir/vendor/yajl/src/yajl_buf.c.o
libyajl.a: CMakeFiles/yajl.dir/vendor/yajl/src/yajl_encode.c.o
libyajl.a: CMakeFiles/yajl.dir/vendor/yajl/src/yajl_gen.c.o
libyajl.a: CMakeFiles/yajl.dir/vendor/yajl/src/yajl_lex.c.o
libyajl.a: CMakeFiles/yajl.dir/vendor/yajl/src/yajl_parser.c.o
libyajl.a: CMakeFiles/yajl.dir/vendor/yajl/src/yajl_tree.c.o
libyajl.a: CMakeFiles/yajl.dir/vendor/yajl/src/yajl_version.c.o
libyajl.a: CMakeFiles/yajl.dir/vendor/yajl/src/yajl.c.o
libyajl.a: CMakeFiles/yajl.dir/build.make
libyajl.a: CMakeFiles/yajl.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/christinapeterson/Documents/Walletkit/walletkit/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Linking C static library libyajl.a"
	$(CMAKE_COMMAND) -P CMakeFiles/yajl.dir/cmake_clean_target.cmake
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/yajl.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/yajl.dir/build: libyajl.a
.PHONY : CMakeFiles/yajl.dir/build

CMakeFiles/yajl.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/yajl.dir/cmake_clean.cmake
.PHONY : CMakeFiles/yajl.dir/clean

CMakeFiles/yajl.dir/depend:
	cd /Users/christinapeterson/Documents/Walletkit/walletkit/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore /Users/christinapeterson/Documents/Walletkit/walletkit/WalletKitCore /Users/christinapeterson/Documents/Walletkit/walletkit/build /Users/christinapeterson/Documents/Walletkit/walletkit/build /Users/christinapeterson/Documents/Walletkit/walletkit/build/CMakeFiles/yajl.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/yajl.dir/depend

