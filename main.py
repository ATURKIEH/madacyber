import sys
import os
import traceback
import datetime
import subprocess
import shutil

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

# configurable paths
COMMON_TOOL_DIRECTORIES = [
    os.path.expanduser("~/go/bin"),
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/usr/bin",
]

DEFAULT_SECLISTS_BASE_PATHS = [
    "/opt/seclists/SecLists",
    os.path.expanduser("~/SecLists"),
    "SecLists"
]
DEFAULT_FFUF_WORDLIST_SUFFIX = "Discovery/DNS/bug-bounty-program-subdomains-trickest-inventory.txt"

FFUF_OVERALL_TIMEOUT_SECONDS = 1800


def find_executable(tool_name: str, suggested_dirs: list[str]) -> str | None:
    found_path = shutil.which(tool_name)
    if found_path:
        print(f"[*] Found '{tool_name}' in system PATH: {found_path}")
        return os.path.abspath(found_path)
    for dir_path in suggested_dirs:
        potential_path = os.path.join(dir_path, tool_name)
        if os.path.isfile(potential_path) and os.access(potential_path, os.X_OK):
            print(f"[*] Found '{tool_name}' at common path: {potential_path}")
            return os.path.abspath(potential_path)
    print(f"[!] '{tool_name}' not found in system PATH or common suggested locations.")
    return None  # Return None if not found


def find_file_or_dir(name_part: str, base_paths: list[str], is_file: bool = True) -> str | None:
    for base_path in base_paths:
        potential_path = os.path.abspath(os.path.expanduser(base_path))
        if os.path.isabs(name_part) and (os.path.isfile(name_part) if is_file else os.path.isdir(name_part)):
            return name_part
        full_path_to_check = potential_path if name_part == "." else os.path.join(potential_path, name_part)
        if is_file:
            if os.path.isfile(full_path_to_check):
                print(f"[*] Found file '{name_part}' at: {full_path_to_check}")
                return full_path_to_check
        else:
            if os.path.isdir(full_path_to_check):
                print(f"[*] Found directory '{name_part}' at: {full_path_to_check}")
                return full_path_to_check
    print(
        f"[!] Could not find {'file' if is_file else 'directory'} for '{name_part}' in checked locations: {base_paths}")
    return None


def main():
    #1st step tool and path configuration
    print("--- Automatically Configuring Tool Paths & Settings ---")

    ffuf_exe_path = find_executable("ffuf", COMMON_TOOL_DIRECTORIES)
    gospider_exe_path = find_executable("gospider", COMMON_TOOL_DIRECTORIES)
    gau_exe_path = find_executable("gau", COMMON_TOOL_DIRECTORIES)
    curl_exe_path = find_executable("curl", COMMON_TOOL_DIRECTORIES)

    seclists_base_dir = find_file_or_dir("SecLists", DEFAULT_SECLISTS_BASE_PATHS, is_file=False)
    wordlist_path = None
    if seclists_base_dir:
        potential_wordlist_path = os.path.join(seclists_base_dir, DEFAULT_FFUF_WORDLIST_SUFFIX)
        if os.path.isfile(potential_wordlist_path):
            wordlist_path = potential_wordlist_path
            print(f"[*] Using FFUF wordlist: {wordlist_path}")
        else:
            print(f"[!] Default FFUF wordlist not found at expected location: {potential_wordlist_path}")

    if not ffuf_exe_path: print(
        f"[WARN] FFUF executable could not be auto-detected. FFUF stage will be skipped if path remains invalid.")
    if not gospider_exe_path: print(
        f"[WARN] GoSpider executable could not be auto-detected. GoSpider stage will be skipped if path remains invalid.")
    if not gau_exe_path: print(
        f"[WARN] GAU executable could not be auto-detected. GAU stage will be skipped if path remains invalid.")
    if not curl_exe_path: print(
        f"[WARN] CURL executable could not be auto-detected. GoSpider live check might fail if path remains invalid.")
    if not wordlist_path: print(
        f"[WARN] FFUF wordlist could not be auto-detected. FFUF stage might fail or be skipped.")
    print("----------------------------------------------------")

    #get domain and create directory
    domain_input = input("\nEnter the target domain (e.g., example.com): ").strip()
    if not domain_input: print("[!] No domain entered. Exiting."); sys.exit(1)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    safe_domain_for_dir = domain_input.replace('.', '_')
    output_directory = f"{safe_domain_for_dir}_{timestamp}"
    try:
        os.makedirs(output_directory, exist_ok=True);
        print(f"[*] Output directory: {os.path.abspath(output_directory)}")
    except OSError as e:
        print(f"[!] Error creating output dir '{output_directory}': {e}"); output_directory = "."

    crtsh_raw_json_filename = os.path.join(output_directory, f"{safe_domain_for_dir}_crtsh_raw_output.json")
    crtsh_processed_filename = os.path.join(output_directory, f"{safe_domain_for_dir}_crtsh_processed_hostnames.txt")
    ffuf_prefixes_generated_filename = os.path.join(output_directory, f"{safe_domain_for_dir}_ffuf_prefixes.txt")
    final_combined_filename = os.path.join(output_directory, f"{safe_domain_for_dir}_final_combined_hostnames.txt")
    gospider_live_hosts_filename = os.path.join(output_directory, f"{safe_domain_for_dir}_gospider_live_hosts.txt")

    crtsh_processed_hostnames = []
    ffuf_discovered_prefixes_set = set()

    #3rd step run crt.sh fetcher
    print("\n--- Running CrtShFetcher ---")
    try:
        crt_fetcher = CrtShFetcher(domain_query=domain_input)
        hostnames_list_from_crtsh = crt_fetcher.run_full_process(
            raw_json_output_path=crtsh_raw_json_filename,
            processed_hostnames_output_path=crtsh_processed_filename)
        if hostnames_list_from_crtsh is not None: crtsh_processed_hostnames = hostnames_list_from_crtsh
    except ValueError as ve:
        print(f"[!] CrtShFetcher Init Error: {ve}")
    except Exception as e:
        print(f"[!] Error during CrtShFetcher: {e}"); traceback.print_exc()
    print("\n--- Finished CrtShFetcher Stage ---")

    all_unique_hostnames_set = set(crtsh_processed_hostnames)

    #4th step execute ffuf
    print("\n--- Preparing for FFUF Execution ---")
    ffuf_ready_to_run = True
    if not ffuf_exe_path or (not shutil.which(ffuf_exe_path) and not (
            os.path.isfile(ffuf_exe_path) and os.access(ffuf_exe_path, os.X_OK))):
        print(f"[!] FFUF executable not found or not executable: '{ffuf_exe_path}'. Skipping FFUF.");
        ffuf_ready_to_run = False
    if ffuf_ready_to_run and (not wordlist_path or not os.path.exists(wordlist_path)):
        print(f"[!] FFUF Wordlist not found: '{wordlist_path}'. Skipping FFUF.");
        ffuf_ready_to_run = False

    if ffuf_ready_to_run:
        ffuf_command_to_run = (f"{ffuf_exe_path} -u https://FUZZ.{domain_input} -w {wordlist_path} "
                               f"-H \"Host: FUZZ.{domain_input}\" -mc 200,301,302,307,401,403,405,500 -ac")
        executor_ffuf = CommandExecutor()
        try:
            print(f"\nExecuting FFUF for {domain_input} (Overall Timeout: {FFUF_OVERALL_TIMEOUT_SECONDS}s).")
            _ffuf_exit_code, collected_prefixes = executor_ffuf.execute_and_collect_ffuf_prefixes(
                ffuf_command_to_run, timeout_seconds=FFUF_OVERALL_TIMEOUT_SECONDS)
            if collected_prefixes: ffuf_discovered_prefixes_set.update(collected_prefixes)
        except KeyboardInterrupt:
            print("\n[WARN] Main script caught FFUF KeyboardInterrupt!")
            if hasattr(executor_ffuf, 'discovered_prefixes_from_ffuf_stdout'):
                ffuf_discovered_prefixes_set.update(executor_ffuf.discovered_prefixes_from_ffuf_stdout)
        except Exception as e:
            print(f"[!] FFUF Error in Main: {e}"); traceback.print_exc()
        if ffuf_discovered_prefixes_set:
            print(f"\n--- Processing {len(ffuf_discovered_prefixes_set)} FFUF discovered prefixes ---")
            ffuf_generated_hostnames_for_file = [f"{prefix}.{domain_input}" for prefix in ffuf_discovered_prefixes_set]
            try:
                with open(ffuf_prefixes_generated_filename, 'w', encoding='utf-8') as f:
                    for hostname in sorted(ffuf_generated_hostnames_for_file): f.write(f"{hostname}\n")
                print(f"[+] FFUF discovered hostnames saved to: {ffuf_prefixes_generated_filename}")
            except IOError as e:
                print(f"[!] Error writing FFUF hostnames: {e}")
        elif ffuf_ready_to_run:
            print("[*] No prefixes collected from FFUF for ffuf_prefixes.txt.")
        if ffuf_discovered_prefixes_set:
            temp_helper_fetcher = CrtShFetcher(domain_input)
            newly_added_from_ffuf_count = 0
            for prefix in ffuf_discovered_prefixes_set:
                processed_hostname = temp_helper_fetcher._strip_www_if_present(f"{prefix}.{domain_input}")
                if processed_hostname not in all_unique_hostnames_set:
                    all_unique_hostnames_set.add(processed_hostname);
                    newly_added_from_ffuf_count += 1
            if newly_added_from_ffuf_count > 0:
                print(f"[+] Added {newly_added_from_ffuf_count} new unique hostnames from FFUF.")
            elif ffuf_discovered_prefixes_set:
                print("[*] All FFUF hostnames (after www-strip) already in CrtSh results.")
    else:
        print("[!] FFUF prerequisites not met. Skipping FFUF stage.")
    print("\n--- Finished FFUF Stage ---")

    if all_unique_hostnames_set:
        with open(final_combined_filename, 'w', encoding='utf-8') as f:
            for item in sorted(list(all_unique_hostnames_set)): f.write(item + '\n')
        print(f"\n[+] Combined hostnames ({len(all_unique_hostnames_set)}) saved to {final_combined_filename}")
    else:
        print("\n[!] No hostnames from CrtSh or FFUF. Cannot proceed further.");
        sys.exit(1)

    #5th step gospider
    gospider_live_hosts_list = []
    if os.path.exists(final_combined_filename) and os.path.getsize(final_combined_filename) > 0:
        print(f"\n--- Preparing for GoSpider Scans (Input from: {final_combined_filename}) ---")
        gospider_ready_to_run = True
        if not gospider_exe_path or (not shutil.which(gospider_exe_path) and not (
                os.path.isfile(gospider_exe_path) and os.access(gospider_exe_path, os.X_OK))):
            print(f"[!] GoSpider executable not found or not executable: '{gospider_exe_path}'. Skipping GoSpider.");
            gospider_ready_to_run = False
        if gospider_ready_to_run and (not curl_exe_path or (not shutil.which(curl_exe_path) and not (
                os.path.isfile(curl_exe_path) and os.access(curl_exe_path, os.X_OK)))):
            print(
                f"[!] CURL executable ('{curl_exe_path}') not found or not executable. GoSpider live check will fail. Skipping GoSpider.");
            gospider_ready_to_run = False

        if gospider_ready_to_run:
            try:
                gospider_runner = GoSpiderRunner(
                    input_hostnames_filepath=final_combined_filename,
                    base_run_output_directory=output_directory,
                    gospider_exe_path=gospider_exe_path,
                    curl_exe_path=curl_exe_path)
                gospider_live_hosts_list = gospider_runner.run_on_all(original_target_domain_for_scoping=domain_input)
                print(f"[*] GoSpider processing stage complete.")
                print(
                    f"    Individual host raw outputs are in subdirs within: {gospider_runner.gospider_per_host_output_basedir}")
                print(
                    f"    Filtered, in-scope URLs for each scanned host are saved as '_filtered.txt' files within their respective gospider raw output directories.")
                if gospider_live_hosts_list:
                    with open(gospider_live_hosts_filename, 'w', encoding='utf-8') as f_live:
                        for host in gospider_live_hosts_list: f_live.write(host + '\n')
                    print(
                        f"[+] GoSpider confirmed {len(gospider_live_hosts_list)} live hosts. Saved to: {gospider_live_hosts_filename}")
                else:
                    print("[*] GoSpider did not confirm any live hosts from its input list.")
            except KeyboardInterrupt:
                print("\n[WARN] Main script caught GoSpider stage KeyboardInterrupt.")
            except ValueError as ve:
                print(f"[!] GoSpiderRunner Init Error: {ve}")
            except Exception as e:
                print(f"[!] Error during GoSpider stage: {e}"); traceback.print_exc()
    else:
        print("\n[*] Skipping GoSpider: Input file '{final_combined_filename}' is empty or not created.")
    print("\n--- Finished GoSpider Stage ---")

    #6th step run gau
    input_for_gau = gospider_live_hosts_filename if gospider_live_hosts_list and os.path.exists(
        gospider_live_hosts_filename) else final_combined_filename
    if os.path.exists(input_for_gau) and os.path.getsize(input_for_gau) > 0:
        print(f"\n--- Preparing for GAU Scans (Input from: {input_for_gau}) ---")
        if not gau_exe_path or (not shutil.which(gau_exe_path) and not (
                os.path.isfile(gau_exe_path) and os.access(gau_exe_path, os.X_OK))):
            print(f"[!] GAU executable not found or not executable: '{gau_exe_path}'. Skipping GAU scans.")
        else:
            try:
                gau_runner = GauRunner(
                    input_hostnames_filepath=input_for_gau,
                    base_run_output_directory=output_directory,
                    gau_exe_path=gau_exe_path)
                gau_runner.run_on_all()
                print(f"[*] GAU processing stage complete.")
                print(f"    Individual host GAU outputs are in files within: {gau_runner.gau_per_host_output_basedir}")
            except KeyboardInterrupt:
                print("\n[WARN] Main script caught GAU stage KeyboardInterrupt.")
            except ValueError as ve:
                print(f"[!] GauRunner Init Error: {ve}")
            except Exception as e:
                print(f"[!] Error during GAU stage: {e}"); traceback.print_exc()
    else:
        print(f"\n[*] Skipping GAU: Input file for GAU '{input_for_gau}' is empty or not created.")
    print("\n--- Finished GAU Stage ---")

    print(f"\n--- All processes finished. Output is in directory: {os.path.abspath(output_directory)} ---")


if __name__ == "__main__":
    main()