from argparse import ArgumentParser, FileType

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("file", type = FileType("r"), help = "File which to load and parse data from.")
    args = parser.parse_args()
    name, city = 0, 1
    if "client" not in args.file.name:
        city = 4
    content = args.file.readlines()
    args.file.close()
    output = content[0]
    for line in sorted(filter(None,
                              set(map(lambda line: tuple(map(str.strip,
                                                             line.split("\t"))),
                                  content[1:]))),
                       key = lambda line: (line[city], line[name])):
        output += "\t".join(line) + "\n"
        print(line)
    basename, ext = args.file.name.rsplit(".")
    open(f"{basename}-new.{ext}", "w").write(output)
