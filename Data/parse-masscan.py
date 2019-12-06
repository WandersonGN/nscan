from argparse import ArgumentParser, FileType
from socket import getservbyport

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("file", type = FileType("r"), help = "File which to load and parse data from.")
    parser.add_argument("-p", "--port", type = int, nargs="+", help = "Port(s) which to filter.")
    parser.add_argument("-o", "--output", type = FileType("w"))
    args = parser.parse_args()
    ports = {}
    with (args.output or open(args.file.name.rsplit(".", 1)[0] + ".csv", "w")) as file:
        file.write("IP\tProtocol\tPort\tService\n")
        for status, protocol, port, ip, _ in sorted(map(lambda line: tuple(map(str.strip,
                                                                               line.split(" ")[:5])),
                                                        filter(lambda line: line.startswith("open"),
                                                               args.file.readlines())),
                                                    key = lambda line: (line[3], line[1], line[2])):
            service = ""
            try:
                service = getservbyport(int(port), protocol)
            except OSError:
                pass
            k = (int(port), service)
            if k in ports:
                ports[k] += 1
            else:
                ports[k] = 1
            file.write("\t".join((ip, protocol, port, service)) + "\n")
    args.file.close()
    for port, n in sorted(ports.items(), key = lambda x: (x[1], x[0][0])):
        port, service = port
        print(f"{str(port).ljust(8)}{service.ljust(32)}{n}")
