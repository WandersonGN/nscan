from argparse import ArgumentParser, FileType
import netaddr

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("file", type = FileType("r"), help = "File to load and parse")
    args = parser.parse_args()

    output = set()
    sl = ("SAFE", "VULNERABLE")
    for line in map(lambda line: tuple(map(str.strip, line.split("-", 2))), args.file.readlines()):
        ok = [False, False, True]
        if len(line) is 3:
            ip, status, reason = line
            if netaddr.valid_ipv4(ip):
                ok[1] = True
                ip = str(netaddr.IPAddress(ip))
            if status in sl:
                ok[0] = True
            elif status not in sl:
                for s in sl:
                    if status in s:
                        status = s
                        ok[0] = True
                        break
        if all(ok):
            output.add((status.upper(), ip, reason))
        else:
            print(line)
    args.file.close()
    open(args.file.name.rsplit(".", 1)[0] + ".csv", "w").write("Status\tIP Address\tReason\n" +
                                                               "\n".join(map("\t".join,
                                                                             sorted(output,
                                                                                    key = lambda x: (x[0], x[2])))))
