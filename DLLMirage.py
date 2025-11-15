#!/usr/bin/env python3
"""
DLL Reverse Proxy Generator (LIEF) - safe pragmas & stubs generator

Generates:
  1) Pragmas header:
        #pragma comment(linker,"/export:Func=Func,@Ordinal")

  2) Stub .cpp:
        extern "C" {
            __declspec(dllexport) void Func() { ProxyFunction(); }
        }

Usage:
    python DLLMirage.py --dll some.dll --pragmas
    python DLLMirage.py --dll some.dll --stubs
    python DLLMirage.py --dll some.dll --both
"""

import argparse
import logging
import os
import re
import sys

try:
    import lief
except Exception:
    print("Install LIEF using: pip install lief", file=sys.stderr)
    raise

# ---------------- Logging ----------------
def configure_logging():
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%d-%b-%y %H:%M:%S'
    )

# ---------------- Args ----------------
def build_parser():
    p = argparse.ArgumentParser(description="DLL Reverse Proxy Generator (LIEF)")

    p.add_argument(
        "--dll",
        required=True,
        help="Path to DLL to extract exports from."
    )

    p.add_argument(
        "-o", "--output-dir",
        default=".",
        help="Directory to write output files."
    )

    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--pragmas", action="store_true", help="Generate pragma header.")
    mode.add_argument("--stubs", action="store_true", help="Generate C++ stub file.")
    mode.add_argument("--both", action="store_true", help="Generate both pragma and stub files.")

    return p

# ---------------- LIEF helpers ----------------
def get_exports(pe):
    if hasattr(pe, "get_export"):
        exp = pe.get_export()
        if exp and hasattr(exp, "entries"):
            return exp.entries

    if hasattr(pe, "export") and pe.export and hasattr(pe.export, "entries"):
        return pe.export.entries

    raise RuntimeError("Could not retrieve export table via LIEF.")

def is_forwarded(entry):
    if hasattr(entry, "forwarder") and entry.forwarder:
        return True
    if hasattr(entry, "is_forwarded") and entry.is_forwarded:
        return True
    if hasattr(entry, "forwarder_name") and entry.forwarder_name:
        return True
    return False

def get_name(entry):
    if hasattr(entry, "name") and entry.name:
        return entry.name
    if hasattr(entry, "get_name"):
        try:
            n = entry.get_name()
            if n:
                return n
        except Exception:
            pass
    return None

def get_ordinal(entry):
    if hasattr(entry, "ordinal"):
        return entry.ordinal
    if hasattr(entry, "value"):
        return entry.value
    return None

def sanitize_identifier(name):
    s = re.sub(r'[^A-Za-z0-9_]', '_', name)
    if not s:
        s = "_export"
    if s[0].isdigit():
        s = "_" + s
    return s

# ---------------- Generators ----------------
def generate_pragmas(dll_path, outdir):
    base = os.path.splitext(os.path.basename(dll_path))[0]
    outpath = os.path.join(outdir, f"{base}_pragmas.h")

    pe = lief.parse(dll_path)
    exports = get_exports(pe)

    # Use EXACT path user typed
    dll_full = dll_path  # <--- no normalization
    dll_escaped = dll_full.replace("\\", "\\\\")

    with open(outpath, "w") as f:
        f.write(f"// Pragmas for {dll_full}\n\n")

        for e in exports:
            if is_forwarded(e):
                continue

            name = get_name(e)
            ordinal = get_ordinal(e)

            if not name or ordinal is None:
                continue

            # EXACT format you want:
            f.write(
                f'#pragma comment(linker,"/export:{name}={dll_escaped}.{name},@{ordinal}")\n'
            )
    logging.info(f"Generated pragma header → {outpath}")

def generate_stubs(dll_path, outdir):
    base = os.path.splitext(os.path.basename(dll_path))[0]
    outpath = os.path.join(outdir, f"{base}_stubs.cpp")

    pe = lief.parse(dll_path)
    exports = get_exports(pe)

    with open(outpath, "w") as f:
        f.write("// Stub source — exports call ProxyFunction()\n\n")
        f.write('#include <windows.h>\n')
        f.write("extern void ProxyFunction();\n\n")
        f.write('extern "C" {\n\n')

        count = 0
        for e in exports:
            if is_forwarded(e):
                continue

            name = get_name(e)
            ordinal = get_ordinal(e)
            if not name or ordinal is None:
                continue

            func = sanitize_identifier(name)

            # Only add pragma if sanitized name differs
            if func != name:
                f.write(f'#pragma comment(linker,"/export:{name}={func},@{ordinal}")\n')

            f.write(f"__declspec(dllexport) void {func}() {{\n")
            f.write("    ProxyFunction();\n")
            f.write("}\n\n")

            count += 1

        f.write("} // extern \"C\"\n")

    logging.info(f"Generated {count} stub functions → {outpath}")

# ---------------- Main ----------------
def main():
    configure_logging()
    parser = build_parser()
    args = parser.parse_args()

    dll_path = args.dll
    outdir = args.output_dir

    os.makedirs(outdir, exist_ok=True)

    if args.pragmas or args.both:
        generate_pragmas(dll_path, outdir)

    if args.stubs or args.both:
        generate_stubs(dll_path, outdir)

    logging.info("Completed.")

if __name__ == "__main__":
    main()
