import os
import traceback
import sys
import subprocess
import shlex


class GauRunner:
    GAU_TIMEOUT_PER_HOST_SECONDS = 300  #5min/host

    def __init__(self,
                 input_hostnames_filepath: str,
                 base_run_output_directory: str,
                 gau_exe_path: str = "gau",
                 gau_config_filepath: str | None = ".gau.toml"):

        if not input_hostnames_filepath: raise ValueError("Input hostnames filepath must be provided.")
        if not base_run_output_directory: raise ValueError("Base run output directory must be provided.")

        self.input_hostnames_filepath = input_hostnames_filepath
        self.base_run_output_directory = base_run_output_directory
        self.gau_exe_path = gau_exe_path
        self.gau_config_filepath = gau_config_filepath

        self.gau_per_host_output_basedir = os.path.join(self.base_run_output_directory, "gau_temp_outputs")

    def _read_hostnames(self) -> list[str]:
        hostnames = []
        if not os.path.exists(self.input_hostnames_filepath):
            print(f"[!] GAU: Input hostnames file not found: {self.input_hostnames_filepath}")
            return []
        try:
            with open(self.input_hostnames_filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    hostname = line.strip()
                    if hostname and not hostname.startswith('#') and '.' in hostname and not hostname.startswith("*."):
                        hostnames.append(hostname)
                    elif hostname.startswith("*."):
                        print(f"    GAU: Skipping wildcard '{hostname}', GAU runs on specific domains/subdomains.")

            unique_hostnames = sorted(list(set(hostnames)))
            if unique_hostnames:
                print(
                    f"[*] GAU: Read {len(unique_hostnames)} unique, non-wildcard hostnames from {self.input_hostnames_filepath} for GAU.")
            else:
                print(f"[*] GAU: No valid hostnames found in {self.input_hostnames_filepath} for GAU.")
            return unique_hostnames
        except Exception as e:
            print(f"[!] GAU: Error reading hostnames from '{self.input_hostnames_filepath}': {e}")
            traceback.print_exc()
        return []

    def _sanitize_hostname_for_filename(self, hostname: str) -> str:
        name = hostname.replace("*.", "wildcard_")
        name = name.replace(":", "_");
        name = name.replace("/", "_");
        name = name.replace("\\", "_")
        invalid_chars = '<>:"|?*\x00-\x1F'
        for char_to_replace in invalid_chars:
            name = name.replace(char_to_replace, '_')
        return name

    def run_gau_for_hostname(self, hostname_to_scan: str):
        sanitized_hostname = self._sanitize_hostname_for_filename(hostname_to_scan)
        output_file_for_host = os.path.join(self.gau_per_host_output_basedir, f"{sanitized_hostname}_gau_output.txt")

        try:
            os.makedirs(self.gau_per_host_output_basedir, exist_ok=True)
        except OSError as e:
            print(f"[!] GAU: Error creating base output dir '{self.gau_per_host_output_basedir}': {e}")
            return

        command_parts = [self.gau_exe_path]
        if self.gau_config_filepath and os.path.exists(self.gau_config_filepath):
            command_parts.extend(["--config", self.gau_config_filepath])
            print(f"[*] GAU: Using config file: {self.gau_config_filepath}")
        elif self.gau_config_filepath:
            print(
                f"[WARN] GAU: Specified config file not found: {self.gau_config_filepath}. GAU will use its default config search.")
        else:
            print(
                "[*] GAU: No specific config file provided. GAU will use its default config search (e.g., ~/.config/gau/gau.toml).")

        command_parts.append(hostname_to_scan)

        command_string_display = " ".join(shlex.quote(part) for part in command_parts)

        print(f"\n--- Running GAU for {hostname_to_scan} ---")
        print(f"GAU output will be saved to: {output_file_for_host}")
        print(f"Executing: {command_string_display}")

        process = None
        try:
            process = subprocess.Popen(
                command_parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            stdout_data, stderr_data = process.communicate(timeout=self.GAU_TIMEOUT_PER_HOST_SECONDS)
            exit_code = process.returncode

            if stdout_data:
                try:
                    with open(output_file_for_host, 'w', encoding='utf-8') as f_out:
                        f_out.write(stdout_data)
                    print(
                        f"[+] GAU: Output for {hostname_to_scan} saved to {output_file_for_host} ({len(stdout_data.splitlines())} lines)")
                except IOError as e:
                    print(f"[!] GAU: Error writing output for {hostname_to_scan} to file: {e}")
            else:
                print(f"[*] GAU: No stdout received from GAU for {hostname_to_scan}.")
                open(output_file_for_host, 'w').close()

            if exit_code != 0:
                print(f"[WARN] GAU for {hostname_to_scan} finished with exit code {exit_code}.")
                if stderr_data: print(f"    GAU Stderr for {hostname_to_scan}:\n{stderr_data.strip()}")
            else:
                print(f"[+] GAU: Finished successfully for {hostname_to_scan}.")

        except subprocess.TimeoutExpired:
            print(f"[WARN] GAU for {hostname_to_scan} timed out after {self.GAU_TIMEOUT_PER_HOST_SECONDS}s.")
            if process: process.kill(); process.wait()
            open(output_file_for_host, 'a').close()
        except FileNotFoundError:
            print(f"[!] GAU: Executable not found at '{self.gau_exe_path}'. Cannot run GAU for {hostname_to_scan}.")
        except KeyboardInterrupt:
            print(f"\n[WARN] GAU for {hostname_to_scan} interrupted by user.")
            if process: process.kill(); process.wait()
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
                print(f"    Scan for current host '{current_hostname_to_scan}' might be incomplete.");
                break
            except Exception as e:
                print(f"[!] GAU: Unexpected error processing {current_hostname_to_scan} with GAU: {e}")
                traceback.print_exc()
                print(f"    Skipping GAU for {current_hostname_to_scan} and continuing...");
                continue

        print("\n--- GAU scans finished (or were interrupted earlier) ---")