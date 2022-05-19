#!/usr/bin/env python3
import os, subprocess, sys
file_dirname = os.path.dirname(__file__)
build_path = os.path.join(
	file_dirname,
	"..",
	"build",
	""
)
os.chdir(build_path)
gcc = ["/usr/bin/gcc", "-I" + os.path.join(file_dirname, "..", "inc"), "-c"]
for directory, _, files in os.walk(file_dirname):
	for file_name in files:
		if file_name[-2:] != ".c":
			continue
		gcc.append(os.path.join(directory, file_name))
gcc.extend(sys.argv[1:])
subprocess.run(gcc)
