"""Prints the creation bytecode of a forge artifact (oprf/contracts/*.json),
linking its one library to the address given as the second argument, as
oprf/src/anvil.rs does."""
import json
import sys

art = json.load(open(sys.argv[1]))
code = art["bytecode"]["object"]
code = code[2:] if code.startswith("0x") else code
libs = {(f, n): refs
        for f, by_name in (art["bytecode"].get("linkReferences") or {}).items()
        for n, refs in by_name.items()}
if len(libs) > 1:
    sys.exit("more than one library to link: %s" % sorted(libs))
for refs in libs.values():
    addr = sys.argv[2].lower()
    addr = addr[2:] if addr.startswith("0x") else addr
    if len(addr) != 40:
        sys.exit("library address must be 20 bytes")
    for r in refs:
        s = r["start"] * 2
        code = code[:s] + addr + code[s + 40:]
if "__$" in code:
    sys.exit("unlinked placeholder left in bytecode")
print("0x" + code)
