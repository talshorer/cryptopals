#! /usr/bin/python3

import sys

MAXLINELEN = 80
TABLEN = 8

# 3 for two quotes and a comma
FIRSTLINELEN = MAXLINELEN - TABLEN - 3
OTHERLINELEN = FIRSTLINELEN - 2 * TABLEN

FIRSTLINEBYTES = FIRSTLINELEN // 2
OTHERLINEBYTES = OTHERLINELEN // 2

def fix_line(line):
	return "".join("\\x{}".format(line[i:i + 2].decode()) for i in range(0, len(line), 2))

def main():
	with open(sys.argv[1], "rb") as f:
		data = f.read().strip().splitlines()
	with sys.stdout as f:
		f.write("#define INPUTLEN {}\n".format(len(data[0]) // 2))
		f.write("\n")
		f.write("static const unsigned char input[][INPUTLEN + 1] = {\n")
		for line in data:
			f.write("\t\"{}\"".format(fix_line(line[:FIRSTLINEBYTES])))
			if len(line) > FIRSTLINEBYTES:
				line = line[FIRSTLINEBYTES:]
				while line:
					f.write("\n\t\t\t\"{}\"".format(
							fix_line(line[:OTHERLINEBYTES])))
					line = line[OTHERLINEBYTES:]
			f.write(",\n")
		f.write("};\n")

if __name__ == "__main__":
	main();
