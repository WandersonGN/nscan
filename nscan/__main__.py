from os import system, makedirs, path
from dns.resolver import get_default_resolver
from argparse import ArgumentParser, FileType

__all__ = ["main"]

def main():
    parser = ArgumentParser()
    parser.add_argument("name", type = str, help = "Scan name.")
    group = parser.add_mutually_exclusive_group(required = True)
    group.add_argument("-t", "--target", type = str, nargs = "+",
                       help = "Target hostnames, IP addresses, networks, etc.")
    group.add_argument("-iL", "--target-list", type = FileType("r"),
                       help = "Input from list of hosts/networks.")
    parser.add_argument("-ns", "--nameservers", type = str, nargs = "+",
                        help = "Specify custom DNS servers.",
                        default = get_default_resolver().nameservers)
    parser.add_argument("-d", "--datadir", type = str,
                        help = "Specify custom Nmap data file location and output directory.",
                        default = "./nmap/")
    parser.add_argument("-r", "--resume", action = "store_true", help = "Resume previous scan.")
    args = parser.parse_args()
    if args.target_list:
        args.target_list.close()
    targets = " ".join(args.target) if args.target else f"-iL {args.target_list.name}"
    output = args.name

    datadir = path.abspath(args.datadir).replace("\\", "/")
    if datadir[-1] != "/":
        datadir += "/"
    outdir = path.join(datadir, f"{output}/")
    try:
        makedirs(outdir)
    except FileExistsError:
        pass

    try:
        with open(path.join(datadir, "nse-args.lst")) as base:
            with open(path.join(outdir, "nse-args.lst"), "w") as new:
                new.write(base.read().format(datadir = datadir, outdir = outdir))
    except FileNotFoundError:
        with open(path.join(outdir, "nse-args.lst"), "w") as new:
            new.write("newtargets\n")

    blacklist = filter(None, map(str.strip, """
broadcast
brute
dos
fuzzer
asn-query
ip-geolocation-*
http-google-malware
http-virustotal
http-comments-displayer
http-fetch
http-xssed
targets-*
whois-ip
http-icloud-*
""".split()))
    scripts = f"all and not {' and not '.join(blacklist)}"
    # stylesheet https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl
    command = (f"nmap --resume {path.join(outdir, 'sCSUV-OT.xml')}" if args.resume else
               " ".join(filter(None, map(str.strip, f"""
nmap {targets}
     --datadir "{datadir}"
     --dns-servers "{','.join(args.nameservers)}"
     --traceroute --reason
     -sS -sU -p1-65535 -sV --version-all -O --osscan-guess
     --script "{scripts}" --script-args-file "{path.join(outdir, 'nse-args.lst')}"
     --min-rate 65535 --min-hostgroup 256 --max-hostgroup 2048
     --min-parallelism 256 --stats-every 1m
     -oA "{path.join(outdir, 'sCSUV-OT')}"
     --webxml
""".split("\n")))))
    #--script-timeout 8m
    #--datadir "~/nmap/" --system-dns --traceroute --reason -sS -sU -p1-65535 -sV --version-all --osscan-guess --min-rate 65536 --max-rate 67108864 --min-parallelism 256 -oA "~/nmap/179.189.95.128" --webxml --script "external and not broadcast and not brute and not dos and not fuzzer and not intrusive and not asn-query and not clamav-exec and not ip-geolocation-* and not ipidseq and not hostmap-* and not http-google-malware and not http-virustotal and not http-comments-displayer and not http-fetch and not http-vuln-cve2014-212* and not targets-* and not whois-ip" --script-args-file "~/nmap/nse-args.lst" --script-timeout 16m
    #print(command)
    #exit()
    system(command)
    #system(f"sudo -u wanderson firefox file://{path.join(outdir, 'sCSUV-OT.xml')}")

if __name__ == "__main__":
    main()
