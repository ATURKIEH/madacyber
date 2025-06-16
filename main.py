import sys
import os
import traceback
import datetime
import subprocess
import shutil

#modules/files
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
COMMON_TOOL_PATHS = [
    os.path.expanduser("~/go/bin"),
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/usr/bin",
]

DEFAULT_SECLISTS_BASE = "/opt/seclists/SecLists"
DEFAULT_FFUF_WORDLIST_SUFFIX = "Discovery/DNS/subdomains-top1million-110000.txt"

FFUF_OVERALL_TIMEOUT_SECONDS = 4000

def find_executable(tool_name: str, suggested_paths: list[str] | None = None) -> str:

    found_path = shutil.which(tool_name)
    if found_path:
        print(f"[*] Found '{tool_name}' in system PATH: {found_path}")
        return os.path.abspath(found_path)

    if suggested_paths:
        for s_path_dir in suggested_paths:
            potential_path = os.path.join(s_path_dir, tool_name)
            if os.path.isfile(potential_path) and os.access(potential_path, os.X_OK):
                print(f"[*] Found '{tool_name}' at suggested path: {potential_path}")
                return os.path.abspath(potential_path)

    print(f"[!] '{tool_name}' not found in system PATH or common suggested locations. Will try running as '{tool_name}'.")
    return tool_name

def get_tool_path_from_user(tool_name: str, auto_detected_path: str) -> str:

    user_path = input(f"Enter full path for '{tool_name}' [default: {auto_detected_path}]: ").strip()
    chosen_path = user_path or auto_detected_path

    if os.path.sep in chosen_path and not os.path.exists(chosen_path):
        print(f"[WARN] Specified path for '{tool_name}' does not exist: {chosen_path}. Will attempt to run as '{tool_name}'.")
        return tool_name
    elif not os.path.sep in chosen_path and shutil.which(chosen_path) is None:
         print(f"[WARN] '{tool_name}' (as '{chosen_path}') not found in PATH. Execution might fail.")

    print(f"[*] Using '{tool_name}' path: {chosen_path}")
    return chosen_path

def get_file_path_from_user(prompt_message: str, default_path: str) -> str:
    user_path = input(f"{prompt_message} [default: {default_path}]: ").strip()
    chosen_path = user_path or default_path

    if not os.path.exists(chosen_path):
        print(f"[WARN] Specified file path does not exist: {chosen_path}. Tool using this might fail.")
    else:
        print(f"[*] Using file path: {chosen_path}")
    return chosen_path

def main():
    print("--- Configuring Tool Paths & Settings ---")

    ffuf_exe_path_default = find_executable("ffuf", COMMON_TOOL_PATHS)
    gospider_exe_path_default = find_executable("gospider", COMMON_TOOL_PATHS)
    gau_exe_path_default = find_executable("gau", COMMON_TOOL_PATHS)
    curl_exe_path_default = find_executable("curl", ["/usr/bin"])

    ffuf_exe_path = get_tool_path_from_user("FFUF", ffuf_exe_path_default)
    gospider_exe_path = get_tool_path_from_user("GoSpider", gospider_exe_path_default)
    gau_exe_path = get_tool_path_from_user("GAU", gau_exe_path_default)
    curl_exe_path = get_tool_path_from_user("CURL", curl_exe_path_default)

    seclists_base_path_default = os.path.expanduser(os.environ.get("SECLISTS_PATH", DEFAULT_SECLISTS_BASE))
    seclists_base_path = get_file_path_from_user(f"Enter SecLists base directory", seclists_base_path_default)
    wordlist_path = os.path.join(seclists_base_path, DEFAULT_FFUF_WORDLIST_SUFFIX)
    print(f"[*] Using FFUF wordlist: {wordlist_path}")

    #get domain
    domain_input = input("\nEnter the target domain (e.g., example.com): ").strip()
    if not domain_input:
        print("[!] No domain entered. Exiting."); sys.exit(1)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    safe_domain_for_dir = domain_input.replace('.', '_')
    output_directory = f"{safe_domain_for_dir}_{timestamp}"
    try:
        os.makedirs(output_directory, exist_ok=True)
        print(f"[*] Output directory: {os.path.abspath(output_directory)}")
    except OSError as e:
        print(f"[!] Error creating output directory '{output_directory}': {e}"); output_directory = "."

    crtsh_raw_json_filename = os.path.join(output_directory, f"{safe_domain_for_dir}_crtsh_raw_output.json")
    crtsh_processed_filename = os.path.join(output_directory, f"{safe_domain_for_dir}_crtsh_processed_hostnames.txt")
    ffuf_prefixes_generated_filename = os.path.join(output_directory, f"{safe_domain_for_dir}_ffuf_prefixes.txt")
    final_combined_filename = os.path.join(output_directory, f"{safe_domain_for_dir}_final_combined_hostnames.txt")
    gospider_live_hosts_filename = os.path.join(output_directory, f"{safe_domain_for_dir}_gospider_live_hosts.txt")

    crtsh_processed_hostnames = []
    ffuf_discovered_prefixes_set = set()

    #crtsetcher
    print("\n--- Running CrtShFetcher ---")
    try:
        crt_fetcher = CrtShFetcher(domain_query=domain_input)
        hostnames_list_from_crtsh = crt_fetcher.run_full_process(
            raw_json_output_path=crtsh_raw_json_filename,
            processed_hostnames_output_path=crtsh_processed_filename)
        if hostnames_list_from_crtsh is not None: crtsh_processed_hostnames = hostnames_list_from_crtsh
    except ValueError as ve: print(f"[!] CrtShFetcher Init Error: {ve}")
    except Exception as e: print(f"[!] Error during CrtShFetcher: {e}"); traceback.print_exc()
    print("\n--- Finished CrtShFetcher Stage ---")

    all_unique_hostnames_set = set(crtsh_processed_hostnames)

    #ffuf execution
    print("\n--- Preparing for FFUF Execution ---")
    ffuf_ready_to_run = True
    if not (os.path.isfile(ffuf_exe_path) and os.access(ffuf_exe_path, os.X_OK)) and not shutil.which(ffuf_exe_path):
        print(f"[!] FFUF executable not found or not executable: '{ffuf_exe_path}'. Skipping."); ffuf_ready_to_run = False
    if ffuf_ready_to_run and not os.path.exists(wordlist_path):
        print(f"[!] Wordlist not found: '{wordlist_path}'. Skipping."); ffuf_ready_to_run = False

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
        except Exception as e: print(f"[!] FFUF Error in Main: {e}"); traceback.print_exc()
        if ffuf_discovered_prefixes_set:
            print(f"\n--- Processing {len(ffuf_discovered_prefixes_set)} FFUF discovered prefixes ---")
            ffuf_generated_hostnames_for_file = [f"{prefix}.{domain_input}" for prefix in ffuf_discovered_prefixes_set]
            try:
                with open(ffuf_prefixes_generated_filename, 'w', encoding='utf-8') as f:
                    for hostname in sorted(ffuf_generated_hostnames_for_file): f.write(f"{hostname}\n")
                print(f"[+] FFUF discovered hostnames saved to: {ffuf_prefixes_generated_filename}")
            except IOError as e: print(f"[!] Error writing FFUF hostnames: {e}")
        elif ffuf_ready_to_run: print("[*] No prefixes collected from FFUF for ffuf_prefixes.txt.")
        if ffuf_discovered_prefixes_set:
            temp_helper_fetcher = CrtShFetcher(domain_input)
            newly_added_from_ffuf_count = 0
            for prefix in ffuf_discovered_prefixes_set:
                processed_hostname = temp_helper_fetcher._strip_www_if_present(f"{prefix}.{domain_input}")
                if processed_hostname not in all_unique_hostnames_set:
                    all_unique_hostnames_set.add(processed_hostname); newly_added_from_ffuf_count += 1
            if newly_added_from_ffuf_count > 0: print(f"[+] Added {newly_added_from_ffuf_count} new unique hostnames from FFUF.")
            elif ffuf_discovered_prefixes_set: print("[*] All FFUF hostnames (after www-strip) already in CrtSh results.")
    else: print("[!] FFUF prerequisites not met. Skipping FFUF stage.")
    print("\n--- Finished FFUF Stage ---")

    if all_unique_hostnames_set:
        with open(final_combined_filename, 'w', encoding='utf-8') as f:
            for item in sorted(list(all_unique_hostnames_set)): f.write(item + '\n')
        print(f"\n[+] Combined hostnames ({len(all_unique_hostnames_set)}) saved to {final_combined_filename}")
    else:
        print("\n[!] No hostnames from CrtSh or FFUF. Cannot proceed further.")
        print(f"\n--- All processes finished (No GoSpider/GAU). Output in: {os.path.abspath(output_directory)} ---")
        sys.exit(1)

    #gospider
    gospider_live_hosts_list = []
    if os.path.exists(final_combined_filename) and os.path.getsize(final_combined_filename) > 0:
        print(f"\n--- Preparing for GoSpider Scans (Input from: {final_combined_filename}) ---")
        if not (os.path.isfile(gospider_exe_path) and os.access(gospider_exe_path, os.X_OK)) and not shutil.which(gospider_exe_path):
            print(f"[!] GoSpider executable not found or not executable: '{gospider_exe_path}'. Skipping.")
        elif not (os.path.isfile(curl_exe_path) and os.access(curl_exe_path, os.X_OK)) and not shutil.which(curl_exe_path):
             print(f"[!] CURL executable ('{curl_exe_path}') not found or not executable. GoSpider live check will fail. Skipping GoSpider.")
        else:
            try:
                gospider_runner = GoSpiderRunner(
                    input_hostnames_filepath=final_combined_filename,
                    base_run_output_directory=output_directory,
                    gospider_exe_path=gospider_exe_path,
                    curl_exe_path=curl_exe_path )
                gospider_live_hosts_list = gospider_runner.run_on_all(original_target_domain_for_scoping=domain_input)
                print(f"[*] GoSpider processing stage complete.")
                print(f"    Individual host raw outputs are in subdirs within: {gospider_runner.gospider_per_host_output_basedir}")
                print(f"    Filtered, in-scope URLs for each scanned host are saved as '_filtered.txt' files within their respective gospider raw output directories.")
                if gospider_live_hosts_list:
                    with open(gospider_live_hosts_filename, 'w', encoding='utf-8') as f_live:
                        for host in gospider_live_hosts_list: f_live.write(host + '\n')
                    print(f"[+] GoSpider confirmed {len(gospider_live_hosts_list)} live hosts. Saved to: {gospider_live_hosts_filename}")
                else: print("[*] GoSpider did not confirm any live hosts from its input list.")
            except KeyboardInterrupt: print("\n[WARN] Main script caught GoSpider stage KeyboardInterrupt.")
            except ValueError as ve: print(f"[!] GoSpiderRunner Init Error: {ve}")
            except Exception as e: print(f"[!] Error during GoSpider stage: {e}"); traceback.print_exc()
    else: print("\n[*] Skipping GoSpider: Input file '{final_combined_filename}' is empty or not created.")
    print("\n--- Finished GoSpider Stage ---")

    #gau
    input_for_gau = gospider_live_hosts_filename if gospider_live_hosts_list and os.path.exists(gospider_live_hosts_filename) else final_combined_filename
    if os.path.exists(input_for_gau) and os.path.getsize(input_for_gau) > 0:
        print(f"\n--- Preparing for GAU Scans (Input from: {input_for_gau}) ---")
        if not (os.path.isfile(gau_exe_path) and os.access(gau_exe_path, os.X_OK)) and not shutil.which(gau_exe_path):
            print(f"[!] GAU executable not found or not executable: '{gau_exe_path}'. Skipping GAU scans.")
        else:
            try:
                gau_runner = GauRunner(
                    input_hostnames_filepath=input_for_gau,
                    base_run_output_directory=output_directory,
                    gau_exe_path=gau_exe_path )
                gau_runner.run_on_all()
                print(f"[*] GAU processing stage complete.")
                print(f"    Individual host GAU outputs are in files within: {gau_runner.gau_per_host_output_basedir}")
            except KeyboardInterrupt: print("\n[WARN] Main script caught GAU stage KeyboardInterrupt.")
            except ValueError as ve: print(f"[!] GauRunner Init Error: {ve}")
            except Exception as e: print(f"[!] Error during GAU stage: {e}"); traceback.print_exc()
    else: print(f"\n[*] Skipping GAU: Input file for GAU '{input_for_gau}' is empty or not created.")
    print("\n--- Finished GAU Stage ---")

    print(f"\n--- All processes finished. Output is in directory: {os.path.abspath(output_directory)} ---")

if __name__ == "__main__":
    main()