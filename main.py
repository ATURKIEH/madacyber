import sys
import os
import traceback
import datetime
import shutil
import argparse
import re

from fetcher import CrtShFetcher
from command_executer import CommandExecutor
from gospider_module import GoSpiderRunner
from gau_module import GauRunner

# to be installed in order to run this without Linux:
#  -> Homebrew
#  -> ffuf through brew install ffuf
#  -> gospider through brew install gospider
#  -> gau through brew install gau
# and also all other imports such as shlex, traceback, etc.
# configurable paths

YELLOW = "\033[1;33m"
GREEN  = "\033[0;32m"
RED    = "\033[0;31m"
RESET  = "\033[0m"

COMMON_TOOL_DIRECTORIES = [
    os.path.expanduser("~/go/bin"),
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/usr/bin"
]
DEFAULT_SECLISTS_BASE_PATHS = [
    "SecLists",
    os.path.expanduser("~/SecLists"),
    "/opt/SecLists",
    "/usr/share/seclists"
]
DEFAULT_FFUF_WORDLIST_SUFFIX = "Discovery/DNS/subdomains-top1million-110000.txt"
FFUF_OVERALL_TIMEOUT_SECONDS = 300
DEFAULT_GOSPIDER_OPERATIONAL_FLAGS = (
    "-c 10 -t 5 -d 2 --other-source --robots --sitemap --js -v "
    "--blacklist \"jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,svg\" --timeout 60"
)
DEFAULT_GAU_ADDITIONAL_FLAGS = "--subs --providers wayback,otx,commoncrawl,urlscan --threads 10"

# Colored print helpers

def print_stage(msg: str):    print(f"{YELLOW}{msg}{RESET}")
def print_info(msg: str):     print(f"{GREEN}{msg}{RESET}")
def print_warn(msg: str):     print(f"{YELLOW}{msg}{RESET}")
def print_error(msg: str):    print(f"{RED}{msg}{RESET}")

# Helper to sanitize folder names for output directories
def _sanitize_folder_name(name: str) -> str:
    return re.sub(r'[^A-Za-z0-9\.-]+', '_', name)

# Find an executable in PATH or common directories
def find_executable(tool_name: str, suggested_dirs: list[str]) -> str | None:
    path = shutil.which(tool_name)
    if path:
        return os.path.abspath(path)
    for d in suggested_dirs:
        candidate = os.path.expanduser(os.path.join(d, tool_name))
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return os.path.abspath(candidate)
    return None

# Find a directory in common paths
def find_directory(name: str, paths: list[str]) -> str | None:
    for p in paths:
        full = os.path.expanduser(p)
        if os.path.isdir(full):
            return full
    return None

# Parse a string into domain and optional flags
def parse_domain_and_flags(input_string: str) -> tuple[str | None, str]:
    parts = input_string.split(None, 1)
    domain = None
    flags = ""
    if parts:
        if '.' in parts[0] and not parts[0].startswith('-'):
            domain = parts[0]
        if len(parts) > 1:
            flags = parts[1].strip()
    return domain, flags

# Main pipeline that runs CrtSh, FFUF, GoSpider, and GAU
def run_recon_pipeline(
    target_domain: str,
    gospider_additional_flags: str,
    ffuf_exe: str,
    wordlist: str,
    gospider_exe: str,
    curl_exe: str,
    gau_exe: str,
    fast_mode: bool,
    gau_additional_flags: str,
    gau_config_file: str | None,
    main_run_base_output_directory: str
):
    print_stage(f"\n--- Starting Full Recon Pipeline for: {target_domain} ---")
    safe_dir = target_domain.replace('.', '_')
    output_dir = os.path.join(main_run_base_output_directory, safe_dir)
    try:
        os.makedirs(output_dir, exist_ok=True)
        print_info(f"[*] Output directory: {output_dir}")
    except Exception as e:
        print_error(f"[!] Could not create output dir '{output_dir}': {e}")
        output_dir = main_run_base_output_directory

    # Paths for outputs
    crt_raw        = os.path.join(output_dir, f"{safe_dir}_crtsh_raw.json")
    crt_txt        = os.path.join(output_dir, f"{safe_dir}_crtsh.txt")
    ffuf_pref      = os.path.join(output_dir, f"{safe_dir}_ffuf_prefixes.txt")
    final_combined = os.path.join(output_dir, f"{safe_dir}_final.txt")
    gospider_live  = os.path.join(output_dir, f"{safe_dir}_gospider_live.txt")

    # --- CrtShFetcher ---
    print_stage("--- Running CrtShFetcher ---")
    try:
        crt   = CrtShFetcher(domain_query=target_domain)
        hosts = crt.run_full_process(crt_raw, crt_txt) or []
        print_info(f"[+] CrtSh fetched {len(hosts)} hostnames")
    except Exception as e:
        print_error(f"[!] CrtShFetcher error: {e}")
        traceback.print_exc()
        hosts = []
    host_set = set(hosts)

    # ---------------- FAST MODE LOGIC ----------------
    if fast_mode:
        print("[FAST MODE] enabled")
        print("[FAST MODE] FFUF disabled")
        print("[FAST MODE] GoSpider disabled")
        print("[FAST MODE] GAU reduced to historical only")

        ffuf_enabled = False
        run_gospider = False
        gau_additional_flags = "--providers wayback,commoncrawl --threads 3"
    else:
        ffuf_enabled = True
        run_gospider = True
    # --- FFUF ---
    print_stage("--- Running FFUF ---")

    if not ffuf_enabled:
        print_warn("[FAST MODE] FFUF skipped")
    else:
        if ffuf_exe and wordlist and os.path.exists(wordlist):
            cmd = (
                f"{ffuf_exe} -u https://FUZZ.{target_domain} -w {wordlist} "
                f"-H \"Host: FUZZ.{target_domain}\" "
                f"-mc 200,301,302,307,401,403,405,500 -ac"
            )
            executor = CommandExecutor()
            try:
                _, prefixes = executor.execute_and_collect_ffuf_prefixes(
                    cmd, timeout_seconds=FFUF_OVERALL_TIMEOUT_SECONDS
                )
                if prefixes:
                    full_hosts = [f"{p}.{target_domain}" for p in prefixes]
                    host_set.update(full_hosts)
                    with open(ffuf_pref, 'w') as f:
                        for h in sorted(full_hosts):
                            f.write(h + "\n")
                    print_info(f"[+] FFUF discovered {len(full_hosts)} prefixes")
            except Exception as e:
                print_error(f"[!] FFUF error: {e}")
                traceback.print_exc()
        else:
            print_warn("[!] Skipping FFUF: prerequisites not met")

    # --- Combine ---
    if host_set:
        with open(final_combined, 'w') as f:
            for h in sorted(host_set):
                f.write(h + "\n")
        print_info(f"[+] Combined hostnames: {len(host_set)}")
    else:
        print_error("[!] No hostnames; aborting.")
        return

    # --- GoSpider ---
    if run_gospider:
        print_stage("--- Running GoSpider ---")
        try:
            go = GoSpiderRunner(
                input_hostnames_filepath=final_combined,
                base_run_output_directory=output_dir,
                gospider_exe_path=gospider_exe,
                curl_exe_path=curl_exe,
                additional_gospider_flags=gospider_additional_flags
            )
            live = go.run_on_all(original_target_domain_for_scoping=target_domain)
        except Exception as e:
            print_error(f"[!] GoSpider error: {e}")
            traceback.print_exc()
    else:
        print_warn("[FAST MODE] GoSpider skipped")
        live = []

        # --- GAU ---
    print_stage("--- Running GAU ---")
    input_for_gau = gospider_live if os.path.exists(gospider_live) and os.path.getsize(gospider_live) > 0 else final_combined
    try:
        gau = GauRunner(
            input_hostnames_filepath=input_for_gau,
            base_run_output_directory=output_dir,
            gau_exe_path=gau_exe,
            additional_gau_flags=gau_additional_flags,
            gau_config_filepath=gau_config_file
        )
        gau.run_on_all()
        print_info("[+] GAU stage complete")
        # Print full GAU outputs for each host
        gau_output_dir = os.path.join(output_dir, "gau_temp_outputs")
        if os.path.isdir(gau_output_dir):
            for fname in sorted(os.listdir(gau_output_dir)):
                if fname.endswith("_gau_output.txt"):
                    host = fname[:-len("_gau_output.txt")]
                    file_path = os.path.join(gau_output_dir, fname)
                    print_stage(f"--- GAU results for {host} ---")
                    try:
                        with open(file_path, 'r', encoding='utf-8') as gf:
                            for line in gf:
                                print(f"{YELLOW}{line.rstrip()}{RESET}")
                    except Exception as e:
                        print_error(f"[!] Could not read GAU output file {file_path}: {e}")
    except Exception as e:
        print_error(f"[!] GAU error: {e}")
        traceback.print_exc()

    print_stage(f"--- Recon complete. Results in {output_dir} ---")

# Entry point
def main_entry():
    FAST_MODE = os.environ.get("FAST_MODE", "0") == "1"
    parser = argparse.ArgumentParser(description="Comprehensive Domain Reconnaissance Tool.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Single domain (e.g., \"example.com\")")
    group.add_argument("-dL", "--domain-list", metavar="FILE", help="File with domains (one per line)")

    parser.add_argument("--ffuf-path", default=find_executable("ffuf", COMMON_TOOL_DIRECTORIES))
    parser.add_argument("--gospider-path", default=find_executable("gospider", COMMON_TOOL_DIRECTORIES))
    parser.add_argument("--gau-path", default=find_executable("gau", COMMON_TOOL_DIRECTORIES))
    parser.add_argument("--curl-path", default=find_executable("curl", COMMON_TOOL_DIRECTORIES))
    parser.add_argument("--wordlist", help="Path to FFUF wordlist")
    parser.add_argument("--gospider-flags", dest="gospider_common_flags", default=DEFAULT_GOSPIDER_OPERATIONAL_FLAGS, help="Flags for GoSpider scans")
    parser.add_argument("--gau-flags", dest="gau_common_flags", default=DEFAULT_GAU_ADDITIONAL_FLAGS, help="Flags for GAU scans")
    parser.add_argument("--gau-config", dest="gau_config_file_cmd", help="Path to .gau.toml config file")

    args = parser.parse_args()

    # prepare output directory
    if args.domain:
        dom, _ = parse_domain_and_flags(args.domain)
        base_name = _sanitize_folder_name(dom or "batch")
    else:
        base_name = "batch"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    base_output = f"/tmp/{base_name}_{timestamp}"
    os.makedirs(base_output, exist_ok=True)
    print_info(f"[*] Saving results into: {base_output}")

    # determine wordlist
    wordlist = args.wordlist or None
    if not wordlist:
        sec_dir = find_directory("SecLists", DEFAULT_SECLISTS_BASE_PATHS)
        if sec_dir:
            candidate = os.path.join(sec_dir, DEFAULT_FFUF_WORDLIST_SUFFIX)
            if os.path.isfile(candidate):
                wordlist = candidate

    # determine GAU config
    gau_conf = None
    if args.gau_config_file_cmd and os.path.isfile(args.gau_config_file_cmd):
        gau_conf = os.path.abspath(args.gau_config_file_cmd)
        print_info(f"[*] Using GAU config: {gau_conf}")

    # gather targets
    targets = []
    if args.domain:
        dom, flags = parse_domain_and_flags(args.domain)
        targets.append((dom, flags or DEFAULT_GOSPIDER_OPERATIONAL_FLAGS, args.gau_common_flags))
    else:
        with open(args.domain_list, 'r', encoding='utf-8') as f:
            for line in f:
                dom, flags = parse_domain_and_flags(line.strip())
                if dom:
                    targets.append((dom, flags or DEFAULT_GOSPIDER_OPERATIONAL_FLAGS, args.gau_common_flags))

    if not targets:
        parser.print_help()
        sys.exit(1)

    # run pipeline for each target
    for dom, gsp_flags, gau_flags in targets:
        run_recon_pipeline(
            target_domain=dom,
            gospider_additional_flags=gsp_flags,
            ffuf_exe=args.ffuf_path,
            wordlist=wordlist or "",
            gospider_exe=args.gospider_path,
            curl_exe=args.curl_path,
            gau_exe=args.gau_path,
            fast_mode=FAST_MODE,
            gau_additional_flags=gau_flags,
            gau_config_file=gau_conf,
            main_run_base_output_directory=base_output
        )

if __name__ == '__main__':
    main_entry()
