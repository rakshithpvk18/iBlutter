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

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

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
                                      
  iBlutter - iOS Flutter Reverse Engineering Tool
  -----------------------------------------------
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


def find_vs_dev_cmd():
    """Find VsDevCmd.bat path using vswhere or standard locations."""
    vswhere = os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe")
    if os.path.exists(vswhere):
        try:
            out = subprocess.run([vswhere, "-latest", "-property", "installationPath"],
                                 capture_output=True, text=True, check=True).stdout.strip()
            if out:
                cmd_path = os.path.join(out, "Common7", "Tools", "VsDevCmd.bat")
                if os.path.exists(cmd_path):
                    return cmd_path
        except Exception:
            pass
    fallback = r"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
    if os.path.exists(fallback):
        return fallback
    return None


def auto_build_blutter(dart_version, snapshot_hash=None):
    """Automatically fetch Dart SDK, apply patches, and compile the missing Blutter binary."""
    blutter_dir = os.path.join(os.path.dirname(SCRIPT_DIR), "Blutter", "blutter")
    if not os.path.exists(blutter_dir):
        return None

    vs_dev_cmd = find_vs_dev_cmd()
    if not vs_dev_cmd:
        print("[-] Visual Studio developer tools not found. Cannot auto-build Blutter binary.")
        return None

    print(f"\n[*] [Auto-Build] No binary found for Dart {dart_version}.")
    print(f"[*] [Auto-Build] Fetching Dart SDK {dart_version} and compiling Blutter binary...")
    print(f"    Workspace : {blutter_dir}")
    print(f"    Target    : ios arm64 (no-compressed-ptrs)")
    if snapshot_hash:
        print(f"    Snapshot  : {snapshot_hash}")
    print(f"    Please wait (this one-time compilation takes ~1-2 minutes)...")

    # Command 1: Fetch & build Dart SDK runtime library
    cmd_sdk = f'"{vs_dev_cmd}" -arch=x64 -host_arch=x64 && python dartvm_fetch_build.py {dart_version} ios arm64'
    if snapshot_hash:
        cmd_sdk += f' {snapshot_hash}'

    try:
        res = subprocess.run(f'cmd /c "{cmd_sdk}"', cwd=blutter_dir, shell=True, capture_output=True, text=True)
        if res.returncode != 0:
            print(f"[-] [Auto-Build] Dart SDK build failed:")
            print(res.stderr[-1000:] if res.stderr else res.stdout[-1000:])
            return None
    except Exception as e:
        print(f"[-] [Auto-Build] Error building Dart SDK: {e}")
        return None

    # Command 2: Build Blutter binary
    py_code = (
        f"from blutter import BlutterInput, cmake_blutter; "
        f"from dartvm_fetch_build import DartLibInfo; "
        f"dart_info = DartLibInfo('{dart_version}', 'ios', 'arm64', has_compressed_ptrs=False, snapshot_hash='{snapshot_hash or ''}'); "
        f"input_obj = BlutterInput('', dart_info, '', False, False, False); "
        f"cmake_blutter(input_obj)"
    )
    cmd_blutter = f'"{vs_dev_cmd}" -arch=x64 -host_arch=x64 && python -c "{py_code}"'

    try:
        res = subprocess.run(f'cmd /c "{cmd_blutter}"', cwd=blutter_dir, shell=True, capture_output=True, text=True)
        if res.returncode != 0:
            print(f"[-] [Auto-Build] Blutter executable compilation failed:")
            print(res.stderr[-1000:] if res.stderr else res.stdout[-1000:])
            return None
    except Exception as e:
        print(f"[-] [Auto-Build] Error compiling Blutter executable: {e}")
        return None

    expected_name = f"blutter_dartvm{dart_version}_ios_arm64_no-compressed-ptrs.exe"
    built_path = os.path.join(blutter_dir, "bin", expected_name)
    if os.path.exists(built_path):
        os.makedirs(BIN_DIR, exist_ok=True)
        local_path = os.path.join(BIN_DIR, expected_name)
        shutil.copy(built_path, local_path)
        for dll in ["capstone.dll", "icudt73.dll", "icuuc73.dll"]:
            src_dll = os.path.join(blutter_dir, "bin", dll)
            dst_dll = os.path.join(BIN_DIR, dll)
            if os.path.exists(src_dll) and not os.path.exists(dst_dll):
                shutil.copy(src_dll, dst_dll)
        print(f"[+] [Auto-Build] Successfully built and cached: {expected_name}\n")
        return local_path

    return None


def get_blutter_executable(dart_version, snapshot_hash=None):
    """Locate or auto-build the appropriate Blutter executable for the given Dart version."""
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

    # 3. Attempt automated on-demand build
    auto_path = auto_build_blutter(dart_version, snapshot_hash)
    if auto_path and os.path.exists(auto_path):
        return auto_path

    # 4. List all available binaries for user feedback
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


def run_blutter(elf_path, output_dir, dart_version, snapshot_hash=None, verbose=False):
    """Run the Blutter binary on the converted ELF with clean filtered output."""
    exe_path = get_blutter_executable(dart_version, snapshot_hash=snapshot_hash)

    print(f"[*] Initializing Dart {dart_version} decompiler...")
    print(f"    Binary : {exe_path}")
    print(f"    Output : {output_dir}")
    print()

    MILESTONES = [
        ("Analyzing the application", "[*] Analyzing Dart application functions..."),
        ("Dumping Object Pool", "[*] Dumping Dart Object Pool (pp.txt)..."),
        ("Dumping Objects", "[*] Dumping Dart Objects (objs.txt)..."),
        ("Generating application assemblies", "[*] Generating decompiled class structure (asm/)..."),
        ("Generating application functions in asm folder", "[*] Generating decompiled class structure (asm/)..."),
        ("Dumping 4Ida", "[*] Generating IDA Pro & Ghidra labeling scripts..."),
        ("Generating Frida script", "[*] Generating Frida instrumentation script (blutter_frida.js)..."),
    ]

    fn_count = 0
    err_count = 0
    exception_lines = []
    seen_milestones = set()

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

        if "Analysis error at line" in line_stripped:
            err_count += 1
            continue

        if "Analyzing function:" in line_stripped or "AnalyzeAll: lib" in line_stripped:
            fn_count += 1
            if fn_count % 1000 == 0:
                print(f"\r[*] Analyzing Dart functions: {fn_count:,} functions processed...", end="", flush=True)
            continue

        # Check for milestone headers
        matched_milestone = False
        for tag, msg in MILESTONES:
            if tag in line_stripped and tag not in seen_milestones:
                seen_milestones.add(tag)
                if fn_count > 0:
                    print()  # newline after live counter
                print(msg)
                matched_milestone = True
                break

        if matched_milestone:
            continue

        # Capture Blutter internal exceptions
        if line_stripped.lower().startswith("exception:"):
            exception_lines.append(line_stripped)
            print(f"  [!] {line_stripped}")
            continue

    proc.wait()

    if fn_count > 0 and not verbose:
        print()  # ensure final newline

    print(f"[*] Analysis summary: {fn_count:,} Dart functions processed, {err_count} non-critical warnings")

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
        snapshot_hash = extract_snapshot_hash(elf_path)

        # Step 5: Run Blutter (exits via sys.exit on failure, finally block still runs)
        run_blutter(elf_path, output_dir, dart_version, snapshot_hash=snapshot_hash, verbose=args.verbose)

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
