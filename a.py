import requests
import sys
import json
import os
import traceback


class CrtShFetcher:
    def __init__(self, domain_query):
        if not domain_query or not isinstance(domain_query, str):
            raise ValueError("Domain query must be a non-empty string.")
        self.domain_query = domain_query.strip()
        self.raw_json_data = None
        self.processed_hostnames = None
        self.user_agent = 'MyCrtShPythonClass/FilterWildcard1.1Nocomment'

    def _make_safe_filename_prefix(self):
        return self.domain_query.replace('.', '_')

    def _strip_www_if_present(self, hostname):
        if hostname.lower().startswith("www."):
            if len(hostname) > 4 and hostname[3] == '.':
                return hostname[4:]
        return hostname

    def fetch_data(self, timeout=90):
        url = f"https://crt.sh/?q=%.{self.domain_query}&output=json"
        headers = {'User-Agent': self.user_agent}
        print(f"[*] CrtSh: Fetching data for query: %.{self.domain_query} from {url}")
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()
            self.raw_json_data = response.text
            if self.raw_json_data.strip() == "[]":
                print(f"[*] CrtSh: No records found for query '{self.domain_query}' (empty JSON '[]').")
            return True
        except requests.exceptions.HTTPError as e:
            print(f"[!] CrtSh: HTTP error: {e}")
            if e.response: print(f"[!] CrtSh: Response: {e.response.text[:500]}...")
        except requests.exceptions.ConnectionError as e:
            print(f"[!] CrtSh: Connection error: {e}")
        except requests.exceptions.Timeout:
            print(f"[!] CrtSh: Request timed out for {url}")
        except requests.exceptions.RequestException as e:
            print(f"[!] CrtSh: Request error: {e}")
        self.raw_json_data = None
        return False

    def save_raw_json(self, filename=None):
        if not self.raw_json_data:
            print("[!] CrtSh: No raw JSON data to save.")
            return False
        print(f"[*] CrtSh: Saving raw JSON to: {filename}")
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.raw_json_data)
            print(f"[+] CrtSh: Raw JSON saved to {filename}")
            return True
        except IOError as e:
            print(f"[!] CrtSh: Error writing raw JSON to {filename}: {e}")
            return False

    def extract_and_process_hostnames(self):
        if not self.raw_json_data:
            print("[!] CrtSh: No raw JSON to process.")
            self.processed_hostnames = None
            return None
        if self.raw_json_data.strip() == "[]":
            print("[*] CrtSh: Raw JSON is '[]', no hostnames to process from name_value.")
            self.processed_hostnames = []
            return self.processed_hostnames

        unique_hostnames_found = set()
        try:
            data = json.loads(self.raw_json_data)
            if not isinstance(data, list):
                print("[!] CrtSh: Expected list from JSON, got something else.")
                self.processed_hostnames = None
                return None

            found_name_values = False
            for entry in data:
                if isinstance(entry, dict) and 'name_value' in entry and entry['name_value']:
                    found_name_values = True
                    for name_value_entry in entry['name_value'].split('\n'):
                        hostname = name_value_entry.strip()
                        if hostname:
                            unique_hostnames_found.add(hostname)

            if not found_name_values and data:
                if data: print("[*] CrtSh: JSON data parsed, but no 'name_value' fields found with content.")

            final_processed_set = set()
            for hostname in unique_hostnames_found:
                if hostname.startswith("*."):
                    print(f"    CrtSh: Skipping wildcard certificate entry: {hostname}")
                    continue
                processed_name = self._strip_www_if_present(hostname)
                final_processed_set.add(processed_name)

            self.processed_hostnames = sorted(list(final_processed_set))
            return self.processed_hostnames

        except json.JSONDecodeError:
            print("[!] CrtSh: Error decoding JSON from crt.sh.")
            self.processed_hostnames = None
            return None
        except Exception as e:
            print(f"[!] CrtSh: Error during hostname processing: {e}")
            self.processed_hostnames = None
            return None

    def save_processed_hostnames(self, filename=None):
        if self.processed_hostnames is None:
            print("[!] CrtSh: No processed hostnames available to save (error occurred).")
            return False
        if not self.processed_hostnames:
            print("[*] CrtSh: List of processed hostnames is empty, nothing to save.")
            return True
        print(f"\n[*] CrtSh: Saving {len(self.processed_hostnames)} unique processed hostnames to: {filename}")
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                for item in self.processed_hostnames: f.write(item + '\n')
            print(f"[+] CrtSh: Processed hostnames saved to {filename}")
            return True
        except IOError as e:
            print(f"[!] CrtSh: Error writing processed hostnames to {filename}: {e}")
            return False

    def run_full_process(self, raw_json_output_path: str, processed_hostnames_output_path: str):
        print(f"--- Starting CrtShFetcher process for {self.domain_query} ---")
        if not self.fetch_data():
            print(f"[!] Crt.sh - Failed to fetch data for {self.domain_query}.")
            self.processed_hostnames = None
            print(f"--- CrtShFetcher process finished for {self.domain_query} (Fetch Failed) ---")
            return self.processed_hostnames
        self.save_raw_json(raw_json_output_path)
        extraction_result = self.extract_and_process_hostnames()
        if extraction_result is not None:
            if self.processed_hostnames:
                print(
                    f"\n[*] CrtSh: Processed {len(self.processed_hostnames)} unique non-wildcard hostnames ('www.' stripped).")
            elif isinstance(self.processed_hostnames, list):
                print("[*] CrtSh: No non-wildcard hostnames found in 'name_value' or data was empty.")
            self.save_processed_hostnames(processed_hostnames_output_path)
        else:
            print("[!] CrtSh: Hostname processing critically failed.")
        print(f"--- CrtShFetcher process finished for {self.domain_query} ---")
        return self.processed_hostnames