import os
import traceback
import sys
from command_executer import CommandExecutor
import re
import shlex
import subprocess

class GauRunner:

    GAU_TIMEOUT_PER_HOST_SECONDS = 120  # 5 minutes/host

    def __init__(self,
                 input_hostnames_filepath: str,
                 base_run_output_directory: str,
                 gau_exe_path: str = "gau"):

        if not input_hostnames_filepath: raise ValueError("Input hostnames filepath must be provided.")
        if not base_run_output_directory: raise ValueError("Base run output directory must be provided.")

        self.input_hostnames_filepath = input_hostnames_filepath
        self.base_run_output_directory = base_run_output_directory
        self.gau_exe_path = gau_exe_path
        self.gau_per_host_output_basedir = os.path.join(self.base_run_output_directory, "gau_temp_outputs")

        self.command_executor = CommandExecutor()

    def _read_hostnames(self) -> list[str]:
        hostnames = []
        if not os.path.exists(self.input_hostnames_filepath):
            print(f"[!] GAU: Input hostnames file not found: {self.input_hostnames_filepath}")
            return []
        try:
            with open(self.input_hostnames_filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    hostname = line.strip()
                    if hostname and not hostname.startswith('#') and '.' in hostname:  # Basic validation
                        hostnames.append(hostname)
            if hostnames:
                print(f"[*] GAU: Read {len(hostnames)} hostnames from {self.input_hostnames_filepath} for GAU.")
            else:
                print(f"[*] GAU: No valid hostnames found in {self.input_hostnames_filepath} for GAU.")
            return sorted(list(set(hostnames)))  # sorted and unique
        except Exception as e:
            print(f"[!] GAU: Error reading hostnames from '{self.input_hostnames_filepath}': {e}")
            traceback.print_exc()
        return []

    def _sanitize_hostname_for_filename(self, hostname: str) -> str:
        name = hostname.replace("*.", "wildcard_")
        name = name.replace(":", "_")
        name = name.replace("/", "_")
        name = name.replace("\\", "_")
        name = re.sub(r'[<>:"/\\|?*\x00-\x1F]', '_', name)
        return name

    def run_gau_for_hostname(self, hostname_to_scan: str):
        sanitized_hostname = self._sanitize_hostname_for_filename(hostname_to_scan)
        output_file_for_host = os.path.join(self.gau_per_host_output_basedir, f"{sanitized_hostname}_gau_output.txt")

        try:
            os.makedirs(self.gau_per_host_output_basedir, exist_ok=True)  #ensures base output directory exists
        except OSError as e:
            print(f"[!] GAU: Error creating base output dir '{self.gau_per_host_output_basedir}': {e}")
            return

        command_string = (
            f"{self.gau_exe_path} {hostname_to_scan}"

        )

        print(f"\n--- Running GAU for {hostname_to_scan} ---")
        print(f"GAU output will be redirected to: {output_file_for_host}")


        try:
            command_parts = shlex.split(command_string)
            #uses subprocess.run to capture output
            result = subprocess.run(
                command_parts,
                capture_output=True,
                text=True,
                timeout=self.GAU_TIMEOUT_PER_HOST_SECONDS,
                check=False  # Don't raise exception for non-zero exit codes
            )

            if result.stdout:
                try:
                    with open(output_file_for_host, 'w', encoding='utf-8') as f_out:
                        f_out.write(result.stdout)
                    print(
                        f"[+] GAU: Output for {hostname_to_scan} saved to {output_file_for_host} ({len(result.stdout.splitlines())} lines)")
                except IOError as e:
                    print(f"[!] GAU: Error writing output for {hostname_to_scan} to file: {e}")
            else:
                print(f"[*] GAU: No stdout received from GAU for {hostname_to_scan}.")
                # empty file created
                open(output_file_for_host, 'w').close()

            if result.returncode != 0:
                print(f"[WARN] GAU for {hostname_to_scan} finished with exit code {result.returncode}.")
                if result.stderr:
                    print(f"    GAU Stderr: {result.stderr.strip()}")
            else:
                print(f"[+] GAU: Finished successfully for {hostname_to_scan}.")

        except subprocess.TimeoutExpired:
            print(
                f"[WARN] GAU for {hostname_to_scan} timed out after {self.GAU_TIMEOUT_PER_HOST_SECONDS}s. Output file may be incomplete or empty.")
            open(output_file_for_host, 'a').close()
        except FileNotFoundError:
            print(f"[!] GAU: Executable not found at '{self.gau_exe_path}'. Cannot run GAU for {hostname_to_scan}.")
        except KeyboardInterrupt:
            print(f"\n[WARN] GAU for {hostname_to_scan} interrupted by user. Output file may be incomplete.")
            raise
        except Exception as e:
            print(f"[!] GAU: An unexpected error occurred while running GAU for {hostname_to_scan}: {e}")
            traceback.print_exc()

    def run_on_all(self):
        hostnames_to_scan = self._read_hostnames()
        if not hostnames_to_scan:
            print("[*] GAU: No hostnames to scan.")
            return

        try:
            os.makedirs(self.gau_per_host_output_basedir, exist_ok=True)
            print(f"[*] GAU: Base directory for GAU's per-host raw outputs: {self.gau_per_host_output_basedir}")
        except OSError as e:
            print(f"[!] GAU: Error creating base GAU output dir: {e}")
            return

        print(f"\n--- Starting GAU scans for {len(hostnames_to_scan)} hostnames ---")
        for i, current_hostname_to_scan in enumerate(hostnames_to_scan):
            print(f"\n[{i + 1}/{len(hostnames_to_scan)}] Processing GAU target: {current_hostname_to_scan}")
            try:
                self.run_gau_for_hostname(current_hostname_to_scan)
            except KeyboardInterrupt:
                print(f"\n[WARN] GAU: KeyboardInterrupt caught in run_on_all. Stopping further GAU scans.")
                print(f"    Scan for current host '{current_hostname_to_scan}' might be incomplete.")
                break
            except Exception as e:  # Catch other errors for a single host scan
                print(f"[!] GAU: Unexpected error processing {current_hostname_to_scan} with GAU: {e}")
                traceback.print_exc()
                print(f"    Skipping GAU for {current_hostname_to_scan} and continuing...")
                continue

        print("\n--- GAU scans finished (or were interrupted earlier) ---")