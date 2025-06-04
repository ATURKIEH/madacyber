import shlex
import os
import traceback
import datetime
import requests
import re
from urllib.parse import urlparse, urljoin
from command_executer import CommandExecutor
import sys
import subprocess


class GoSpiderRunner:
    GOSPIDER_TIMEOUT_PER_HOST_SECONDS = 120
    GOSPIDER_LIVE_CHECK_TIMEOUT_SECONDS = 10

    def __init__(self,
                 input_hostnames_filepath: str,
                 base_run_output_directory: str,
                 gospider_exe_path: str = "gospider",
                 curl_exe_path: str = "curl"):

        if not input_hostnames_filepath: raise ValueError("Input hostnames filepath must be provided.")
        if not base_run_output_directory: raise ValueError("Base run output directory must be provided.")

        self.input_hostnames_filepath = input_hostnames_filepath
        self.base_run_output_directory = base_run_output_directory
        self.gospider_exe_path = gospider_exe_path
        self.curl_exe_path = curl_exe_path
        self.gospider_per_host_output_basedir = os.path.join(self.base_run_output_directory, "gospider_temp_outputs")
        self.command_executor = CommandExecutor()

    def _read_hostnames(self) -> list[str]:
        raw_hostnames = []
        if not os.path.exists(self.input_hostnames_filepath):
            print(f"[!] GoSpider: Input hostnames file not found: {self.input_hostnames_filepath}")
            return []
        try:
            with open(self.input_hostnames_filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    hostname = line.strip()
                    if hostname and not hostname.startswith('#'): raw_hostnames.append(hostname)
            if not raw_hostnames: print(
                f"[*] GoSpider: No hostnames found in {self.input_hostnames_filepath}"); return []
            print(f"[*] GoSpider: Read {len(raw_hostnames)} total entries from {self.input_hostnames_filepath}.")
            processed_for_gospider = set()
            for hostname in raw_hostnames:
                if hostname.startswith("*."):
                    base_domain = hostname[2:]
                    if '.' in base_domain:
                        print(
                            f"    Transforming wildcard '{hostname}' to base domain '{base_domain}' for GoSpider."); processed_for_gospider.add(
                            base_domain)
                    else:
                        print(
                            f"    Skipping transformed wildcard '{base_domain}' from '{hostname}' (not a valid domain).")
                elif '.' in hostname:
                    processed_for_gospider.add(hostname)
                else:
                    print(f"    Skipping potentially invalid hostname for GoSpider: '{hostname}'")
            valid_hostnames_for_gospider = sorted(list(processed_for_gospider))
            if valid_hostnames_for_gospider:
                print(
                    f"[*] GoSpider: Filtered to {len(valid_hostnames_for_gospider)} unique, valid hostnames for scanning.")
            else:
                print(f"[*] GoSpider: No valid hostnames remaining after filtering.")
            return valid_hostnames_for_gospider
        except Exception as e:
            print(
                f"[!] GoSpider: Error reading/filtering hostnames from '{self.input_hostnames_filepath}': {e}"); traceback.print_exc(); return []

    def _sanitize_hostname_for_filename(self, hostname: str) -> str:
        name = hostname.replace("*.", "wildcard_")
        name = name.replace(":", "_")
        name = name.replace("/", "_")
        name = name.replace("\\", "_")
        name = re.sub(r'[<>:"/\\|?*\x00-\x1F]', '_', name)
        return name

    def _is_host_live(self, hostname: str, timeout: int = GOSPIDER_LIVE_CHECK_TIMEOUT_SECONDS, url_effective=None) -> tuple[
        bool, str | None, str | None]:
        print(f"    [GS LIVE CHECK] Checking liveness for: {hostname}")
        protocols_to_try = [f"https://{hostname}", f"http://{hostname}"]
        for url_to_check in protocols_to_try:
            command_string = f"{self.curl_exe_path} -Ls -o /dev/null --connect-timeout {timeout} -m {timeout + 5} -w \"%{url_effective} %{{http_code}}\\n\" \"{url_to_check}\""
            command_parts = shlex.split(command_string)
            try:
                result = subprocess.run(command_parts, capture_output=True, text=True, check=False)
                if result.returncode == 0 and result.stdout.strip():
                    parts = result.stdout.strip().split()
                    if len(parts) == 2:
                        effective_url, status_code_str = parts[0], parts[1]
                        try:
                            status_code = int(status_code_str)
                            if 200 <= status_code < 400:
                                protocol = urlparse(effective_url).scheme
                                print(
                                    f"    [GS LIVE CHECK] Host {hostname} confirmed live at {effective_url} (Status: {status_code}).")
                                return True, protocol, effective_url
                            #else: print(f"[GS LIVE CHECK] Host {hostname} on {url_to_check} status {status_code} (not 2xx/3xx).")
                        except ValueError:
                            pass  #print(f"[GS LIVE CHECK] Bad status code: '{status_code_str}' for {url_to_check}")
            except FileNotFoundError:
                print(
                    f"[!] CURL executable not found at '{self.curl_exe_path}'. Cannot perform live check."); return False, None, None
            except Exception:
                pass  # print(f"    [GS LIVE CHECK with CURL] Error for {url_to_check}: {e}")
        print(f"    [GS LIVE CHECK] Host {hostname} non-responsive or not meeting 2xx/3xx criteria.")
        return False, None, None

    def _process_gospider_host_output_and_save_filtered(self, scanned_hostname_for_context: str,
                                                        original_target_domain_for_scoping: str, gospider_host_dir: str,
                                                        base_url_for_relative_paths: str | None):
        print(
            f"\n[*] GoSpider: Processing output from '{gospider_host_dir}' for '{scanned_hostname_for_context}', scoping to '{original_target_domain_for_scoping}'")
        files_to_scan_set = set()
        try:
            if not os.path.isdir(gospider_host_dir): return
            for item_name in os.listdir(gospider_host_dir):
                item_path = os.path.join(gospider_host_dir, item_name)
                if os.path.isfile(item_path) and os.path.getsize(item_path) > 0 and not item_name.endswith(
                        "_filtered.txt"):
                    files_to_scan_set.add(item_name)
        except Exception:
            pass
        if not files_to_scan_set: print(f"    No non-empty raw output files found in '{gospider_host_dir}'."); return

        url_finder_pattern = re.compile(r"https?://[^\s\"'<>()]+")
        relative_url_finder_pattern = re.compile(r"^/[^\s\"'<>()#]+")
        gospider_prefix_pattern = re.compile(
            r"^(?:\[(?:url|link|href|src|form|script|asset|include|javascript|subdomain|wayback|sitemap|other)\]\s*-\s*(?:\[code-\d+\]\s*-\s*)?)?(.*)$");
        host_specific_inscope_urls = set()
        for filename in files_to_scan_set:
            filepath = os.path.join(gospider_host_dir, filename);
            extracted_from_this_file_count = 0
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as infile:
                    for line_content in infile:
                        line_content_stripped_ws = line_content.strip()
                        if not line_content_stripped_ws: continue
                        match_strip = gospider_prefix_pattern.search(line_content_stripped_ws)
                        content_to_parse = match_strip.group(1).strip() if match_strip and match_strip.group(
                            1) else line_content_stripped_ws
                        urls_found_in_line = [];
                        abs_urls = url_finder_pattern.findall(content_to_parse)
                        if abs_urls: urls_found_in_line.extend(abs_urls)
                        if base_url_for_relative_paths:
                            relative_paths = relative_url_finder_pattern.findall(content_to_parse)
                            if relative_paths:
                                for rel_path in relative_paths:
                                    try:
                                        urls_found_in_line.append(urljoin(base_url_for_relative_paths, rel_path))
                                    except ValueError:
                                        pass
                        if not urls_found_in_line and "." in content_to_parse and not content_to_parse.startswith(
                                "http") and not content_to_parse.startswith(
                                "/") and original_target_domain_for_scoping in content_to_parse:
                            if content_to_parse.endswith(
                                f".{original_target_domain_for_scoping}") or content_to_parse == original_target_domain_for_scoping: urls_found_in_line.append(
                                f"https://{content_to_parse}"); urls_found_in_line.append(f"http://{content_to_parse}")
                        for url_to_check in urls_found_in_line:
                            url_to_check = url_to_check.strip().rstrip('\'"')
                            try:
                                parsed_url = urlparse(url_to_check)
                                if parsed_url.scheme in ['http', 'https'] and parsed_url.hostname:
                                    if parsed_url.hostname.endswith(
                                        f".{original_target_domain_for_scoping}") or parsed_url.hostname == original_target_domain_for_scoping: host_specific_inscope_urls.add(
                                        url_to_check); extracted_from_this_file_count += 1
                            except ValueError:
                                pass
            except Exception as e:
                print(f"[!] GoSpider: Error reading/processing file '{filepath}': {e}")
            if extracted_from_this_file_count > 0: print(
                f"    Extracted {extracted_from_this_file_count} in-scope URLs from {os.path.basename(filepath)}")
        if host_specific_inscope_urls:
            sanitized_filename_part = self._sanitize_hostname_for_filename(scanned_hostname_for_context);
            individual_filtered_filepath = os.path.join(gospider_host_dir, f"{sanitized_filename_part}_filtered.txt")
            try:
                with open(individual_filtered_filepath, 'w', encoding='utf-8') as ind_outfile:
                    for url_item in sorted(list(host_specific_inscope_urls)): ind_outfile.write(url_item + '\n')
                print(
                    f"    Saved {len(host_specific_inscope_urls)} filtered in-scope URLs for '{scanned_hostname_for_context}' to: {os.path.basename(individual_filtered_filepath)}")
            except IOError as e:
                print(f"[!] GoSpider: Error writing individual filtered file for '{scanned_hostname_for_context}': {e}")
        else:
            print(f"    No new in-scope URLs found for '{scanned_hostname_for_context}' to save in its filtered file.")
        print(f"--- Finished processing for: {scanned_hostname_for_context} ---")

    def run_gospider_for_hostname(self, hostname_to_scan: str, original_target_domain_for_scoping: str) -> bool:
        is_live, live_protocol, determined_target_url = self._is_host_live(hostname_to_scan)
        if not is_live: print(
            f"[*] GoSpider: Skipping gospider scan for non-live host: {hostname_to_scan}"); return False
        if determined_target_url and urlparse(determined_target_url).scheme and urlparse(determined_target_url).netloc:
            target_site_for_gospider = determined_target_url
        elif live_protocol:
            target_site_for_gospider = f"{live_protocol}://{hostname_to_scan}"
        else:
            target_site_for_gospider = f"https://{hostname_to_scan}"; print(
                f"[WARN] GoSpider: Defaulting to {target_site_for_gospider}")
        sanitized_scanned_hostname = self._sanitize_hostname_for_filename(hostname_to_scan)
        hostname_gospider_individual_output_dir = os.path.join(self.gospider_per_host_output_basedir,
                                                               sanitized_scanned_hostname)
        try:
            os.makedirs(hostname_gospider_individual_output_dir, exist_ok=True)
        except OSError as e:
            print(
                f"[!] GoSpider: Error creating output dir '{hostname_gospider_individual_output_dir}': {e}"); return False
        command_string = (
            f"{self.gospider_exe_path} -s \"{target_site_for_gospider}\" -o \"{hostname_gospider_individual_output_dir}\" "
            f"-c 10 -t 5 -d 2 --other-source --robots --sitemap --js -v "
            f"--blacklist \"jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,svg\" --timeout 60")
        print(
            f"\n--- Running gospider for {target_site_for_gospider} (Original scanned host for context: {hostname_to_scan}) ---")
        print(f"Gospider individual raw output will be in: {hostname_gospider_individual_output_dir}")
        completion_result = self.command_executor.execute_direct_output(command_string,
                                                                        timeout_seconds=self.GOSPIDER_TIMEOUT_PER_HOST_SECONDS)
        if os.path.isdir(hostname_gospider_individual_output_dir):
            self._process_gospider_host_output_and_save_filtered(scanned_hostname_for_context=hostname_to_scan,
                                                                 original_target_domain_for_scoping=original_target_domain_for_scoping,
                                                                 gospider_host_dir=hostname_gospider_individual_output_dir,
                                                                 base_url_for_relative_paths=target_site_for_gospider)
        else:
            print(
                f"[*] GoSpider: Raw output directory for {hostname_to_scan} not created by gospider: {hostname_gospider_individual_output_dir}")
        if completion_result:
            if completion_result.returncode == 0:
                print(f"[+] GoSpider: Finished successfully for {hostname_to_scan}.")
            elif completion_result.returncode == 130:
                print(f"[WARN] GoSpider: Scan for {hostname_to_scan} was interrupted.")
            elif completion_result.returncode == -99:
                print(f"[WARN] GoSpider: Scan for {hostname_to_scan} timed out by script.")
            else:
                print(f"[!] GoSpider: Finished for {hostname_to_scan} with exit code {completion_result.returncode}.")
        else:
            print(f"[!] GoSpider: Failed to start gospider for {hostname_to_scan}.")
        return True

    def run_on_all(self, original_target_domain_for_scoping: str) -> list[str]:
        hostnames_to_scan = self._read_hostnames()
        if not hostnames_to_scan: return []

        gospider_ran_on_these_live_hosts = []
        try:
            os.makedirs(self.gospider_per_host_output_basedir, exist_ok=True)
            print(
                f"[*] GoSpider: Base directory for gospider's per-host raw outputs: {self.gospider_per_host_output_basedir}")
        except OSError as e:
            print(f"[!] GoSpider: Error creating base gospider temp output dir: {e}"); return []
        print(
            f"\n--- Starting GoSpider scans for {len(hostnames_to_scan)} hostnames (scoping to '{original_target_domain_for_scoping}') ---")
        for i, current_hostname_to_scan in enumerate(hostnames_to_scan):
            print(f"\n[{i + 1}/{len(hostnames_to_scan)}] Processing Gospider target: {current_hostname_to_scan}")
            try:
                scan_was_attempted_on_live_host = self.run_gospider_for_hostname(current_hostname_to_scan,
                                                                                 original_target_domain_for_scoping)
                if scan_was_attempted_on_live_host:
                    gospider_ran_on_these_live_hosts.append(current_hostname_to_scan)
            except KeyboardInterrupt:
                print(f"\n[WARN] GoSpider: KeyboardInterrupt in run_on_all. Stopping further scans.")
                print(f"    Scan for '{current_hostname_to_scan}' might be incomplete.");
                break
            except Exception as e:
                print(f"[!] GoSpider: Unexpected error processing {current_hostname_to_scan}: {e}");
                traceback.print_exc()
                print(f"    Skipping to next host due to error with {current_hostname_to_scan}.");
                continue
        print("\n--- GoSpider scans finished (or were interrupted earlier) ---")
        return gospider_ran_on_these_live_hosts