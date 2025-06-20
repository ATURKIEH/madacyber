# main.py
import sys
import os
import traceback
import datetime
import subprocess
import shutil
import argparse
import re

from fetcher import CrtShFetcher
from command_executer import CommandExecutor
from gospider_module import GoSpiderRunner
from gau_module import GauRunner

#to be installed in order to run this without linux
#--> Homebrew
#--> ffuf through homebrew
#--> gospider ""
#--> gau ""
#and also all the other import such as shlex, traceback, etc..
#configurable paths

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
DEFAULT_FFUF_WORDLIST_SUFFIX = (
    "Discovery/DNS/subdomains-top1million-110000.txt"
)
FFUF_OVERALL_TIMEOUT_SECONDS = 1800
DEFAULT_GOSPIDER_OPERATIONAL_FLAGS = (
    "-c 10 -t 5 -d 2 --other-source --robots --sitemap --js -v "
    "--blacklist \"jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,svg\" "
    "--timeout 60"
)
DEFAULT_GAU_ADDITIONAL_FLAGS = "--subs --providers wayback,otx,commoncrawl,urlscan --threads 10"

# Helper to sanitize folder names for output directories
def _sanitize_folder_name(name: str) -> str:
    # Replace any character that's not alphanumeric, dot, or dash with underscore
    return re.sub(r'[^A-Za-z0-9\.-]+', '_', name)


def find_executable(tool_name: str, suggested_dirs: list[str]) -> str | None:
    found_path = shutil.which(tool_name)
    if found_path:
        print(f"[*] Found '{tool_name}' in system PATH: {found_path}")
        return os.path.abspath(found_path)
    for dir_path in suggested_dirs:
        expanded = os.path.expanduser(dir_path)
        potential = os.path.join(expanded, tool_name)
        if os.path.isfile(potential) and os.access(potential, os.X_OK):
            print(f"[*] Found '{tool_name}' at common path: {potential}")
            return os.path.abspath(potential)
    return None


def find_directory(dir_name_to_log: str, potential_paths: list[str]) -> str | None:
    print(f"[*] Searching for directory '{dir_name_to_log}' in: {potential_paths}")
    for path_option in potential_paths:
        abs_path = os.path.abspath(os.path.expanduser(path_option))
        if os.path.isdir(abs_path):
            print(f"[*] Found directory '{dir_name_to_log}' at: {abs_path}")
            return abs_path
    print(f"[!] Could not find directory '{dir_name_to_log}' in checked locations")
    return None


def parse_domain_and_flags(input_string: str) -> tuple[str | None, str]:
    parts = input_string.split(None, 1)
    domain = None
    flags_string = ""
    if parts:
        if "." in parts[0] and not parts[0].startswith("-"):
            domain = parts[0]
        if len(parts) > 1:
            flags_string = parts[1].strip()
    if domain is None and flags_string:
        print(f"[WARN] Input '{input_string}' treated as flags only, no domain parsed.")
    return domain, flags_string


def run_recon_pipeline(
    target_domain: str,
    gospider_additional_flags: str,
    ffuf_exe: str,
    wordlist: str,
    gospider_exe: str,
    curl_exe: str,
    gau_exe: str,
    gau_additional_flags: str,
    gau_config_file: str | None,
    main_run_base_output_directory: str
):
    print(f"\n\n--- Starting Full Recon Pipeline for: {target_domain} ---")
    safe_dir = target_domain.replace(".", "_")
    output_dir = os.path.join(main_run_base_output_directory, safe_dir)
    try:
        os.makedirs(output_dir, exist_ok=True)
        print(f"[*] Output directory for {target_domain}: {output_dir}")
    except OSError as e:
        print(f"[!] Error creating output dir '{output_dir}': {e}")
        output_dir = main_run_base_output_directory

    # file paths
    crt_raw = os.path.join(output_dir, f"{safe_dir}_crtsh_raw.json")
    crt_txt = os.path.join(output_dir, f"{safe_dir}_crtsh.txt")
    ffuf_prefixes = os.path.join(output_dir, f"{safe_dir}_ffuf_prefixes.txt")
    final_combined = os.path.join(output_dir, f"{safe_dir}_final.txt")
    gospider_live = os.path.join(output_dir, f"{safe_dir}_gospider_live.txt")

    # CRT.sh
    print("\n--- Running CrtShFetcher ---")
    crtsh_hosts = []
    try:
        crt = CrtShFetcher(domain_query=target_domain)
        res = crt.run_full_process(crt_raw, crt_txt)
        if res is not None:
            crtsh_hosts = res
    except Exception as e:
        print(f"[!] CrtShFetcher error: {e}")
        traceback.print_exc()
    hosts_set = set(crtsh_hosts)

    # FFUF
    print("\n--- Running FFUF ---")
    ffuf_ready = shutil.which(ffuf_exe) or (os.path.isfile(ffuf_exe) and os.access(ffuf_exe, os.X_OK))
    if ffuf_ready and wordlist and os.path.exists(wordlist):
        cmd = (
            f"{ffuf_exe} -u https://FUZZ.{target_domain} -w {wordlist} "
            f"-H \"Host: FUZZ.{target_domain}\" -mc 200,301,302,307,401,403,405,500 -ac"
        )
        exec_ffuf = CommandExecutor()
        try:
            code, prefixes = exec_ffuf.execute_and_collect_ffuf_prefixes(cmd, timeout_seconds=FFUF_OVERALL_TIMEOUT_SECONDS)
            if prefixes:
                hosts_set.update(prefixes)
                with open(ffuf_prefixes, 'w', encoding='utf-8') as f:
                    for p in sorted(prefixes):
                        f.write(f"{p}.{target_domain}\n")
                print(f"[+] FFUF prefixes saved: {ffuf_prefixes}")
        except KeyboardInterrupt:
            print("[WARN] FFUF aborted by user.")
        except Exception as e:
            print(f"[!] FFUF error: {e}")
            traceback.print_exc()
    else:
        print("[!] FFUF prerequisites not met; skipping FFUF.")

    # combine
    if hosts_set:
        with open(final_combined, 'w', encoding='utf-8') as f:
            for h in sorted(hosts_set):
                f.write(h + "\n")
        print(f"[+] Combined hostnames saved: {final_combined}")
    else:
        print("[!] No hosts to scan; exiting.")
        return

    # GoSpider
    if os.path.exists(final_combined) and os.path.getsize(final_combined) > 0:
        go = GoSpiderRunner(
            input_hostnames_filepath=final_combined,
            base_run_output_directory=output_dir,
            gospider_exe_path=gospider_exe,
            curl_exe_path=curl_exe,
            additional_gospider_flags=gospider_additional_flags
        )
        live_hosts = go.run_on_all(original_target_domain_for_scoping=target_domain)
        if live_hosts:
            with open(gospider_live, 'w', encoding='utf-8') as f:
                for u in live_hosts:
                    f.write(u + "\n")
            print(f"[+] Live hosts saved: {gospider_live}")

    # GAU
    input_for_gau = gospider_live if os.path.exists(gospider_live) and os.path.getsize(gospider_live) > 0 else final_combined
    if os.path.exists(input_for_gau) and os.path.getsize(input_for_gau) > 0:
        print("\n--- Running GAU ---")
        gau_r = GauRunner(
            input_hostnames_filepath=input_for_gau,
            base_run_output_directory=output_dir,
            gau_exe_path=gau_exe,
            additional_gau_flags=gau_additional_flags,
            gau_config_filepath=gau_config_file
        )
        gau_r.run_on_all()

    print(f"\n--- Recon complete. Results in {output_dir} ---")


def main_entry():
    parser = argparse.ArgumentParser(description="Comprehensive Domain Reconnaissance Tool.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Single domain (e.g., 'example.com')")
    group.add_argument("-dL", "--domain-list", metavar="FILE", help="File with domains (one per line)")

    parser.add_argument("--ffuf-path", default=find_executable("ffuf", COMMON_TOOL_DIRECTORIES))
    parser.add_argument("--gospider-path", default=find_executable("gospider", COMMON_TOOL_DIRECTORIES))
    parser.add_argument("--gau-path", default=find_executable("gau", COMMON_TOOL_DIRECTORIES))
    parser.add_argument("--curl-path", default=find_executable("curl", COMMON_TOOL_DIRECTORIES))
    parser.add_argument("--wordlist", default=None, help="Path to FFUF wordlist")
    parser.add_argument("--gospider-flags", dest="gospider_common_flags", default=DEFAULT_GOSPIDER_OPERATIONAL_FLAGS,
                        help="Flags for GoSpider scans")
    parser.add_argument("--gau-flags", dest="gau_common_flags", default=DEFAULT_GAU_ADDITIONAL_FLAGS,
                        help="Flags for GAU scans")
    parser.add_argument("--gau-config", dest="gau_config_file_cmd", help="Path to .gau.toml config file")

    args = parser.parse_args()

    # prepare output directory name
    if args.domain:
        dom, _ = parse_domain_and_flags(args.domain)
        base_name = _sanitize_folder_name(dom or "batch")
    else:
        base_name = "batch"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    base_output = os.path.join(os.getcwd(), f"{base_name}_{timestamp}")
    os.makedirs(base_output, exist_ok=True)
    print(f"[*] Saving results into: {base_output}")

    # determine FFUF wordlist
    wordlist = args.wordlist
    if not wordlist:
        sec_dir = find_directory("SecLists", DEFAULT_SECLISTS_BASE_PATHS)
        if sec_dir:
            candidate = os.path.join(sec_dir, DEFAULT_FFUF_WORDLIST_SUFFIX)
            if os.path.isfile(candidate):
                wordlist = candidate

    # determine GAU config file
    gau_conf = None
    if args.gau_config_file_cmd and os.path.isfile(args.gau_config_file_cmd):
        gau_conf = os.path.abspath(args.gau_config_file_cmd)
        print(f"[*] Using GAU config: {gau_conf}")

    # gather targets
    targets = []
    if args.domain:
        dom, flags = parse_domain_and_flags(args.domain)
        targets.append((dom, flags or DEFAULT_GOSPIDER_OPERATIONAL_FLAGS, args.gau_common_flags))
    else:
        with open(args.domain_list, 'r', encoding='utf-8') as f:
            for line in f:
                dom, flags = parse_domain_and_flags(line)
                if dom:
                    targets.append((dom, flags or DEFAULT_GOSPIDER_OPERATIONAL_FLAGS, args.gau_common_flags))

    if not targets:
        parser.print_help()
        sys.exit(1)

    for dom, gsp_flags, gau_flags in targets:
        run_recon_pipeline(
            target_domain=dom,
            gospider_additional_flags=gsp_flags,
            ffuf_exe=args.ffuf_path,
            wordlist=wordlist or "",
            gospider_exe=args.gospider_path,
            curl_exe=args.curl_path,
            gau_exe=args.gau_path,
            gau_additional_flags=gau_flags,
            gau_config_file=gau_conf,
            main_run_base_output_directory=base_output
        )


if __name__ == '__main__':
    main_entry()
