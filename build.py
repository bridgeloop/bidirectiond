#!/usr/bin/env python3
import os, subprocess, sys
file_dirname = os.path.dirname(__file__)
gcc = [
	"/usr/bin/gcc",

	"-lpthread", "-lssl", "-lcrypto",

	"-o", os.path.join(file_dirname, "output", "bidirectiond"),

	"-I" + os.path.join(file_dirname, "inc")
]
for directory, _, files in os.walk(os.path.join(file_dirname, "bidirectiond")):
	for file_name in files:
		if file_name[-2:] != ".c":
			continue
		gcc.append(os.path.join(directory, file_name))
for directory, _, files in os.walk(os.path.join(file_dirname, "core")):
	for file_name in files:
		if file_name[-2:] != ".c":
			continue
		gcc.append(os.path.join(directory, file_name))
for directory, _, files in os.walk(os.path.join(file_dirname, "output")):
	for file_name in files:
		if file_name[-2:] != ".o":
			continue
		gcc.append(os.path.join(directory, file_name))
gcc.extend(sys.argv[1:])
subprocess.run(gcc)
