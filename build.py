#!/usr/bin/env python3
import os, subprocess, sys
file_dirname = os.path.dirname(__file__)
build_path = os.path.join(
	file_dirname,
	"build",
	""
)
gcc = ["/usr/bin/gcc", "-lpthread", "-lssl", "-lcrypto", "-o", os.path.join(build_path, "bidirectiond"), "-I" + os.path.join(file_dirname, "build")]
for directory, _, files in os.walk(build_path):
	for file_name in files:
		if file_name[-2:] != ".o":
			continue
		gcc.append(os.path.join(directory, file_name))
gcc.extend(sys.argv[1:])
subprocess.run(gcc)
