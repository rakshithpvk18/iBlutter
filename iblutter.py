#!/usr/bin/env python3
"""
iBlutter - iOS Flutter App Reverse Engineering Tool
====================================================
Combines Mach-O -> ELF conversion with Blutter analysis for iOS Flutter apps.

Supports:
  - iOS IPA files (extracts the app binary automatically)
  - Raw Mach-O / Fat Binary app files
  - Arm64 only (no-compressed-ptrs, Dart 3.x)

Usage:
  python iblutter.py -i <path/to/App.ipa or Runner.app/Runner> -o <output_dir> [--dart-version 3.12.2]
"""

import argparse
import os
import sys
import shutil
import subprocess
import zipfile
import tempfile
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BIN_DIR = os.path.join(SCRIPT_DIR, "bin")
SCRIPTS_DIR = os.path.join(SCRIPT_DIR, "scripts")

# Additional lookup locations for compiled blutter binaries
ALT_BIN_DIRS = [
    os.path.join(os.path.dirname(SCRIPT_DIR), "Blutter", "blutter", "bin"),
]

DEFAULT_DART_VERSION = "3.12.2"


def banner():
    print(r"""
  _  ____  _       _   _              
 (_)| __ )| |_   _| |_| |_ ___ _ __  
 | ||  _ \| | | | | __| __/ _ \ '__| 
 | || |_) | | |_| | |_| ||  __/ |    
 |_||____/ |_|\__,_|\__|\__\___|_|   
                                      
  iBlutter - iOS Flutter RE Tool       
  ------------------------------------
""")


DART_SYMBOLS_REQUIRED = [
    '_kDartVmSnapshotData', '_kDartVmSnapshotInstructions',
    '_kDartIsolateSnapshotData', '_kDartIsolateSnapshotInstructions',
    'kDartVmSnapshotData', 'kDartVmSnapshotInstructions',
    'kDartIsolateSnapshotData', 'kDartIsolateSnapshotInstructions',
]


def binary_has_dart_symbols(path):
    """Quick check: does this Mach-O binary have any Dart snapshot symbols?"""
    try:
        import lief as _lief
        m = _lief.parse(path)
        if isinstance(m, _lief.MachO.FatBinary):
            m = m.take(_lief.MachO.CPU_TYPES.ARM64)
        if m is None:
            return False
        found = {sym.name for sym in m.symbols}
        return any(s in found for s in DART_SYMBOLS_REQUIRED)
    except Exception:
        return False


def find_app_binary_in_ipa(ipa_path, tmpdir):
    """Extract IPA and find the Mach-O binary that contains Dart snapshot symbols
    as well as the Flutter engine binary if present.
    """
    print(f"[*] Extracting IPA: {ipa_path}")
    with zipfile.ZipFile(ipa_path, 'r') as z:
        z.extractall(tmpdir)

    payload_dir = os.path.join(tmpdir, "Payload")
    if not os.path.exists(payload_dir):
        raise FileNotFoundError("No 'Payload' folder found inside IPA. Is this a valid IPA?")

    app_binary = None
    flutter_binary = None

    for root, dirs, files in os.walk(payload_dir):
        for f in files:
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, payload_dir)
            if rel_path.endswith(os.path.join("Frameworks", "App.framework", "App")):
                app_binary = full_path
            elif rel_path.endswith(os.path.join("Frameworks", "Flutter.framework", "Flutter")):
                flutter_binary = full_path

    if app_binary and binary_has_dart_symbols(app_binary):
        print(f"[+] Dart symbols found in: Frameworks/App.framework/App")
        return app_binary, flutter_binary, payload_dir

    # Fallback search
    candidates = []
    for app_bundle in os.listdir(payload_dir):
        if not app_bundle.endswith(".app"):
            continue
        app_path = os.path.join(payload_dir, app_bundle)
        binary_name = app_bundle[:-4]
        main_bin = os.path.join(app_path, binary_name)
        if os.path.isfile(main_bin):
            candidates.append((main_bin, f"{binary_name} (main binary)"))

    for path, label in candidates:
        print(f"[*] Checking {label} for Dart symbols...")
        if binary_has_dart_symbols(path):
            print(f"[+] Dart symbols found in: {label}")
            return path, flutter_binary, payload_dir

    if app_binary:
        return app_binary, flutter_binary, payload_dir

    raise FileNotFoundError("Could not find any Mach-O binary inside the IPA.")


def detect_dart_version(binary_path, flutter_binary=None, search_dir=None):
    """Try to extract the Dart version string from Flutter engine, app binary, or search dir."""
    targets = []
    if flutter_binary and os.path.isfile(flutter_binary):
        targets.append((flutter_binary, "Frameworks/Flutter.framework/Flutter"))
    if binary_path and os.path.isfile(binary_path):
        targets.append((binary_path, os.path.basename(binary_path)))

    if search_dir and os.path.exists(search_dir):
        for root, dirs, files in os.walk(search_dir):
            for f in files:
                p = os.path.join(root, f)
                if p not in [t[0] for t in targets] and ("Flutter" in f or "Runner" in f):
                    targets.append((p, f))

    for target_path, label in targets:
        try:
            with open(target_path, 'rb') as f:
                data = f.read()
            m = re.search(rb'(\d+\.\d+\.\d+)\s+\((?:stable|beta|dev)\)', data)
            if m:
                version = m.group(1).decode()
                print(f"[+] Auto-detected Dart version: {version} (from {label})")
                return version
        except Exception:
            pass
    return None


def extract_snapshot_hash(elf_path):
    """Extract Dart snapshot version hash from the converted ELF binary."""
    try:
        from elftools.elf.elffile import ELFFile
        with open(elf_path, 'rb') as f:
            elf = ELFFile(f)
            dynsym = elf.get_section_by_name('.dynsym')
            if dynsym:
                syms = dynsym.get_symbol_by_name('_kDartVmSnapshotData')
                if syms:
                    f.seek(syms[0]['st_value'] + 20)
                    h = f.read(32).decode('ascii', errors='ignore')
                    if len(h) == 32 and re.match(r'^[a-f0-9]{32}$', h):
                        print(f"[+] Dart Snapshot Hash: {h}")
                        return h
    except Exception:
        pass
    return None


def convert_macho_to_elf(binary_path, output_elf_path):
    """Invoke macho_to_elf.py converter."""
    converter = os.path.join(SCRIPT_DIR, "macho_to_elf.py")
    if not os.path.exists(converter):
        raise FileNotFoundError(f"macho_to_elf.py not found at {converter}")

    import lief as _lief
    if not _lief.is_macho(binary_path):
        fmt = "ELF" if _lief.is_elf(binary_path) else "unknown"
        print(f"[-] Input binary is {fmt} format, not Mach-O.")
        print(f"    iBlutter only processes iOS Mach-O app binaries or .ipa files.")
        print(f"    For Android ELF libapp.so, use the original Blutter tool instead.")
        sys.exit(1)

    sys.path.insert(0, SCRIPT_DIR)
    from macho_to_elf import convert_macho_to_elf as _convert
    print(f"[*] Converting Mach-O to ELF...")
    _convert(binary_path, None, output_elf_path)
    print(f"[+] ELF written to: {output_elf_path}")


def get_blutter_executable(dart_version):
    """Locate the appropriate Blutter executable for the given Dart version."""
    expected_name = f"blutter_dartvm{dart_version}_ios_arm64_no-compressed-ptrs.exe"
    
    # 1. Check local BIN_DIR
    local_path = os.path.join(BIN_DIR, expected_name)
    if os.path.exists(local_path):
        return local_path

    # 2. Check alternative bin dirs (e.g. Blutter workspace)
    for alt_dir in ALT_BIN_DIRS:
        alt_path = os.path.join(alt_dir, expected_name)
        if os.path.exists(alt_path):
            os.makedirs(BIN_DIR, exist_ok=True)
            print(f"[*] Copying {expected_name} from Blutter workspace...")
            shutil.copy(alt_path, local_path)
            for dll in ["capstone.dll", "icudt73.dll", "icuuc73.dll"]:
                src_dll = os.path.join(alt_dir, dll)
                dst_dll = os.path.join(BIN_DIR, dll)
                if os.path.exists(src_dll) and not os.path.exists(dst_dll):
                    shutil.copy(src_dll, dst_dll)
            return local_path

    # 3. List all available binaries for user feedback
    available = []
    if os.path.exists(BIN_DIR):
        for f in os.listdir(BIN_DIR):
            if f.startswith("blutter_dartvm") and f.endswith(".exe"):
                available.append(f)
    for alt_dir in ALT_BIN_DIRS:
        if os.path.exists(alt_dir):
            for f in os.listdir(alt_dir):
                if f.startswith("blutter_dartvm") and f.endswith(".exe") and f not in available:
                    available.append(f)

    raise ValueError(
        f"No Blutter binary found for Dart version '{dart_version}' ({expected_name}).\n"
        f"Available binaries in workspace: {', '.join(available) if available else 'none'}\n"
        f"Use --dart-version to specify an available version or compile blutter for Dart {dart_version}."
    )


def run_blutter(elf_path, output_dir, dart_version, verbose=False):
    """Run the Blutter binary on the converted ELF with clean filtered output."""
    exe_path = get_blutter_executable(dart_version)

    print(f"[*] Running Blutter ({dart_version})...")
    print(f"    Binary : {exe_path}")
    print(f"    Input  : {elf_path}")
    print(f"    Output : {output_dir}")
    print()

    IMPORTANT_PREFIXES = (
        "Dumping Object Pool",
        "Dumping Objects",
        "Generating application",
        "Dumping 4Ida",
        "Generating Frida",
        "AnalyzeAll: iteration",
        "AnalyzeAll: lib",
        "main:",
    )
    SUPPRESS_PREFIXES = (
        "  Analyzing function:",
        "Analysis error at line",
        "    0x",
        "  * 0x",
        "  DumpStructHeaderFile",
        "  Dump4Ida",
        "  Written ELF",
        "  .text:",
        "  .rodata:",
        "  _kDart",
    )

    fn_count = 0
    err_count = 0
    cur_lib = ""
    lib_fn_count = 0
    exception_lines = []

    proc = subprocess.Popen(
        [exe_path, "-i", elf_path, "-o", output_dir],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env={**os.environ, "PATH": BIN_DIR + os.pathsep + os.environ.get("PATH", "")},
        text=True, encoding="utf-8", errors="replace",
        bufsize=1,
    )

    for line in proc.stdout:
        line_stripped = line.rstrip()

        if verbose:
            print(line_stripped)
            continue

        if line_stripped.startswith("Analysis error at line"):
            err_count += 1
            continue

        if line_stripped.startswith("  Analyzing function:"):
            fn_count += 1
            lib_fn_count += 1
            continue

        if any(line_stripped.startswith(p) for p in SUPPRESS_PREFIXES):
            continue

        if line_stripped.startswith("AnalyzeAll: lib"):
            lib_name = line_stripped.replace("AnalyzeAll: lib", "").strip()
            if cur_lib and lib_fn_count > 0:
                print(f"    [{lib_fn_count:>5} functions]  {cur_lib}")
            cur_lib = lib_name if lib_name else "(core)"
            lib_fn_count = 0
            continue

        # Capture Blutter internal exceptions (these indicate a fatal internal failure
        # even when the process exits with code 0)
        if line_stripped.lower().startswith("exception:"):
            exception_lines.append(line_stripped)
            print(f"  [!] {line_stripped}")
            continue

        print(line_stripped)

    if cur_lib and lib_fn_count > 0:
        print(f"    [{lib_fn_count:>5} functions]  {cur_lib}")

    proc.wait()

    print()
    print(f"[*] Analysis summary: {fn_count} functions processed, {err_count} non-critical analysis warnings")

    if proc.returncode != 0:
        print(f"\n[-] Blutter exited with code {proc.returncode}")
        sys.exit(proc.returncode)

    # Validate that Blutter actually wrote output — it can exit 0 but produce nothing
    # when an internal exception occurs (e.g. "exception: getting native function pool
    # object from Dart code").
    output_sentinels = ["asm", "pp.txt", "blutter_frida.js", "objs.txt", "ida_script"]
    produced = [s for s in output_sentinels if os.path.exists(os.path.join(output_dir, s))]

    if not produced:
        print(f"\n[-] Blutter produced no output files in: {output_dir}")
        if exception_lines:
            print(f"    Blutter threw internal exception(s):")
            for exc in exception_lines:
                print(f"      {exc}")
        print()
        print(f"  Possible causes & fixes:")
        print(f"  1. Wrong Dart version  -- retry with --dart-version <ver>")
        print(f"     Available: check bin/ for compiled blutter binaries")
        print(f"  2. Corrupt / unsupported snapshot -- try --verbose to see full Blutter output")
        print(f"  3. Dart 3.x native pool exception -- this app may need a patched Blutter build")
        print(f"     See: https://github.com/worawit/blutter/issues")
        sys.exit(1)

    print(f"[+] Blutter completed successfully!")


def print_results(output_dir):
    print("\n" + "="*55)
    print("  iBlutter - Analysis Complete!")
    print("="*55)
    artifacts = {
        "asm/":              "Dart class/method structure (human-readable)",
        "blutter_frida.js":  "Frida instrumentation script",
        "ida_script/":       "IDA Pro auto-labeling scripts",
        "pp.txt":            "Dart Object Pool map",
        "objs.txt":          "Known Dart objects dump",
    }
    for name, desc in artifacts.items():
        full = os.path.join(output_dir, name)
        exists = os.path.exists(full)
        mark = "[OK]" if exists else "[--]"
        print(f"  {mark} {name:<25} {desc}")
    print("="*55)
    print(f"\n  Output directory: {output_dir}\n")


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="iBlutter - iOS Flutter App Reverse Engineering Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python iblutter.py -i MyApp.ipa -o ./output
  python iblutter.py -i Runner -o ./output --dart-version 3.12.2
  python iblutter.py -i MyApp.ipa -o ./output --keep-elf
  python iblutter.py -i MyApp.ipa -o ./output --verbose
        """
    )
    parser.add_argument("-i", "--input", required=True,
                        help="Path to IPA file or raw Mach-O app binary")
    parser.add_argument("-o", "--output", required=True,
                        help="Output directory for all generated artifacts")
    parser.add_argument("--dart-version", default=None,
                        help=f"Dart version to use. Default: auto-detect, fallback {DEFAULT_DART_VERSION}")
    parser.add_argument("--keep-elf", action="store_true",
                        help="Keep the intermediate libapp.so ELF file after analysis")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show all Blutter output including per-function analysis (very noisy)")
    args = parser.parse_args()

    input_path = os.path.abspath(args.input)
    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)

    tmpdir = None
    elf_path = None
    keep_elf = args.keep_elf

    try:
        flutter_binary = None
        payload_dir = None

        # Step 1: Find the binary
        if input_path.endswith(".ipa"):
            tmpdir = tempfile.mkdtemp(prefix="iblutter_")
            binary_path, flutter_binary, payload_dir = find_app_binary_in_ipa(input_path, tmpdir)
        else:
            binary_path = input_path
            if not os.path.isfile(binary_path):
                print(f"[-] Input file not found: {binary_path}")
                sys.exit(1)

        # Step 2: Auto-detect Dart version
        dart_version = args.dart_version
        if dart_version is None:
            dart_version = detect_dart_version(binary_path, flutter_binary, payload_dir)
        if dart_version is None:
            dart_version = DEFAULT_DART_VERSION
            print(f"[!] Could not auto-detect Dart version. Using default: {dart_version}")

        # Step 3: Convert Mach-O -> ELF
        elf_path = os.path.join(output_dir, "libapp.so")
        convert_macho_to_elf(binary_path, elf_path)

        # Step 4: Extract and display snapshot hash
        extract_snapshot_hash(elf_path)

        # Step 5: Run Blutter (exits via sys.exit on failure, finally block still runs)
        run_blutter(elf_path, output_dir, dart_version, verbose=args.verbose)

        print_results(output_dir)

    finally:
        # Clean up intermediate ELF unless --keep-elf was requested.
        # Runs even when run_blutter calls sys.exit() on failure so we never
        # leave a stale libapp.so behind in the output folder.
        if elf_path and os.path.exists(elf_path) and not keep_elf:
            os.remove(elf_path)
            print(f"[*] Removed intermediate ELF (use --keep-elf to keep it)")
        if tmpdir and os.path.exists(tmpdir):
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
