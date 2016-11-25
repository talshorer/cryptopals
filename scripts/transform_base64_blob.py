#! /usr/bin/python3

import sys

MAXLINELEN = 80
TABLEN = 8

# 2 for two quotes
FIRSTLINELEN = MAXLINELEN - TABLEN - 2

def main():
	with open(sys.argv[1], "rb") as f:
		data = f.read().strip().splitlines()
	with sys.stdout as f:
		f.write("static const char inputbuf[] = {\n")
		for line in data:
			f.write("\t\"{}\"\n".format(line.decode()))
		f.write("};\n")

if __name__ == "__main__":
	main();
