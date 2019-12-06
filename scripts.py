import os, colorama, termcolor

colorama.init()

system, custom = ("C:\\Program Files (x86)\\Nmap\\scripts\\",
                  "C:\\Users\\Wanderson\\Sentinella\\Security\\nmap\\")
sfl, cfl = map(lambda d: tuple(filter(lambda f: f.lower().endswith(".nse"), os.listdir(d))), (system, custom))
print("FILENAME".ljust(40, "-") + "\t" + "SYSTEM".ljust(12, "-") + "\t" + "CUSTOM".ljust(12, "-"))
for filename in sorted(set(cfl + sfl)):
    s1 = s2 = 0
    if filename in cfl:
        s2 = os.stat(os.path.join(custom, filename)).st_size
    if filename in sfl:
        s1 = os.stat(os.path.join(system, filename)).st_size
    if s1 and s2:
        if s1 == s2:
            os.remove(os.path.join(custom, filename))
    print(termcolor.colored(filename.ljust(48) + f"{s1/1024:.03f}".ljust(10) + "KB\t" + f"{s2/1024:.03f}".ljust(10) + "KB",
                            "red" if ((s1 and s2) or (s2 and not s1)) and (s1 != s2) else "white"))
os.system(f"nmap --datadir '{custom}' --script-updatedb")
