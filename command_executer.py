import subprocess
import shlex
import traceback
import sys
import re
import signal
import os
import datetime


PTY_AVAILABLE = False
try:
    import pty
    import select
    PTY_AVAILABLE = True
except ImportError:
    print(
        "[WARN] pty/select modules not available. PTY execution mode will fall back to simple Popen (this is expected on Windows).")


def strip_ansi_codes(text: str) -> str:
    ansi_escape_pattern = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape_pattern.sub('', text)


class CommandExecutor:
    def __init__(self):
        self.discovered_prefixes_from_ffuf_stdout = set()

    def execute_and_collect_ffuf_prefixes(self, command_string: str, timeout_seconds: int | None = None) -> tuple[
        int | None, set]:
        self.discovered_prefixes_from_ffuf_stdout.clear()
        if not command_string.strip():
            print("[!] No command provided to FFUF executor.")
            return None, self.discovered_prefixes_from_ffuf_stdout
        timeout_msg = f" (overall timeout: {timeout_seconds}s)" if timeout_seconds else ""
        print(f"\n>>> Executing FFUF{timeout_msg}: {command_string}")
        print("-------------------------------------------")
        command_parts = []
        process = None
        exit_code = None
        try:
            command_parts = shlex.split(command_string)
            if not command_parts: return None, self.discovered_prefixes_from_ffuf_stdout
            process = subprocess.Popen(command_parts, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, bufsize=1, universal_newlines=True, errors='ignore')
            if process.stdout:
                for raw_line in process.stdout:
                    cleaned_line_for_print = strip_ansi_codes(raw_line)
                    if '\r' in cleaned_line_for_print:
                        print(cleaned_line_for_print.strip('\n') + '\r', end='')
                    else:
                        print(cleaned_line_for_print, end='')
                    sys.stdout.flush()
                    line_to_parse = strip_ansi_codes(raw_line).strip()
                    ignore_keywords = ['[ERROR]', '::', '***', ' progrès:', ' Progress:', 'Output:', 'Command:',
                                       'Method:', 'Matcher:', 'Filter:', 'Threads:', 'Wordlist:', 'Follow:',
                                       'Extensions:', 'Timeout:', 'Retries:']
                    if not line_to_parse or any(
                        kw in line_to_parse for kw in ignore_keywords) or line_to_parse.lower().startswith(
                        "fuzz "): continue
                    parts = line_to_parse.split(None, 1)
                    if parts and len(parts) > 1 and "[Status:" in parts[1]:
                        prefix = parts[0]
                        if prefix and '.' not in prefix and prefix.lower() != "fuzz":
                            self.discovered_prefixes_from_ffuf_stdout.add(prefix)
            exit_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            print(f"\n[WARN] FFUF command exceeded overall timeout of {timeout_seconds}s. Terminating...")
            if process: process.terminate(); exit_code = -99
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill();
            process.wait()
            print(f"[WARN] FFUF terminated due to overall timeout. Exit code set to {exit_code}.")
        except FileNotFoundError:
            executable_name = command_parts[0] if command_parts else command_string.split()[
                0] if command_string.strip() else "Unknown"
            print(f"\n[ERROR] FFUF executable not found: '{executable_name}'.")
            exit_code = -100
        except KeyboardInterrupt:
            print("\n[WARN] KeyboardInterrupt in CommandExecutor (FFUF stream)!")
            if process:
                if process.poll() is None: process.terminate()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()
                exit_code = process.returncode if process.returncode is not None else 130
            else:
                exit_code = 130
            print(f"\n--- FFUF (Streaming) Interrupted (Assumed Exit Code: {exit_code}) ---")
        except Exception as e:
            print(f"\n[ERROR] Unexpected error in FFUF streaming executor: {e}")
            traceback.print_exc()
            exit_code = -101
        finally:
            print()
            if exit_code is not None:
                print(f"-------------------------------------------")
                print(f"--- FFUF (Streaming) Final Exit Code: {exit_code} ---")
                if exit_code == 0:
                    print("FFUF (Streaming) command finished successfully.")
                elif exit_code != 130 and exit_code != -99:
                    print(f"FFUF (Streaming) command finished with error code {exit_code}.")
        return exit_code, self.discovered_prefixes_from_ffuf_stdout
    def execute_direct_output(self, command_string: str,
                              timeout_seconds: int | None = None) -> subprocess.CompletedProcess | None:
        if not PTY_AVAILABLE:
            print("[WARN] PTY module not available. Falling back to simple Popen for direct output.")
            return self._execute_direct_output_simple_popen(command_string,
                                                            timeout_seconds)  # Ensure this fallback is robust

        if not command_string.strip():
            print("No command provided to execute.")
            return None

        timeout_msg = f" (overall PTY timeout: {timeout_seconds}s)" if timeout_seconds else ""
        print(f"\n>>> Executing command (PTY direct output{timeout_msg}): {command_string}")
        print("-------------------------------------------")

        command_parts = []
        master_fd = -1
        slave_fd = -1
        process = None
        exit_code = None

        try:
            command_parts = shlex.split(command_string)
            if not command_parts:
                print("[ERROR] Command string resulted in no command parts after splitting.")
                return None

            master_fd, slave_fd = pty.openpty()

            process = subprocess.Popen(
                command_parts,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
            )
            os.close(slave_fd)
            slave_fd = -1

            start_time = datetime.datetime.now()

            while True:
                if timeout_seconds:
                    if (datetime.datetime.now() - start_time).total_seconds() > timeout_seconds:
                        raise subprocess.TimeoutExpired(process.args if process else command_parts, timeout_seconds)

                if process.poll() is not None:
                    break

                try:
                    rlist, _, _ = select.select([master_fd], [], [], 0.1)  # Non-blocking check
                except ValueError:  # master_fd might have been closed if process exited very fast
                    if process.poll() is not None:
                        break
                    else:
                        raise

                if master_fd in rlist:  #if master_fd has data
                    try:
                        data = os.read(master_fd, 1024) #1024 bytes
                        if not data:
                            break
                        sys.stdout.write(data.decode(errors='ignore'))
                        sys.stdout.flush()
                    except OSError:
                        break
            if process.returncode is None:
                process.wait(timeout=1)
            exit_code = process.returncode

        except subprocess.TimeoutExpired:
            print(
                f"\n[WARN] Command '{command_parts[0] if command_parts else 'N/A'}' timed out via PTY ({timeout_seconds}s). Terminating...")
            if process and process.poll() is None:
                process.terminate()
                exit_code = -99
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
            elif process:
                exit_code = process.returncode if process.returncode is not None else -99
            else:
                exit_code = -99
            print(f"[WARN] Command terminated (PTY timeout). Exit code set to {exit_code}.")
        except KeyboardInterrupt:
            print("\n[WARN] KeyboardInterrupt in CommandExecutor (PTY)!")
            if process and process.poll() is None:
                print("[WARN] Sending SIGINT to PTY child process...")
                process.send_signal(signal.SIGINT)
                try:
                    print("[INFO] Waiting for PTY child process to terminate after SIGINT (max 5s)...")
                    process.wait(timeout=5)
                    exit_code = process.returncode
                except subprocess.TimeoutExpired:
                    print("[WARN] PTY Child did not respond to SIGINT. Sending SIGTERM...")
                    process.terminate()
                    try:
                        process.wait(timeout=3); exit_code = process.returncode
                    except subprocess.TimeoutExpired:
                        print(
                            "[WARN] PTY Child no SIGTERM. SIGKILL..."); process.kill(); process.wait(); exit_code = process.returncode if process.returncode is not None else -signal.SIGKILL
                except Exception as e_wait:
                    print(f"[ERROR] Error waiting for PTY process after SIGINT: {e_wait}")
                    exit_code = process.returncode if process.poll() is not None else 130
            else:
                exit_code = 130
            raise
        except FileNotFoundError:
            executable_name = command_parts[0] if command_parts and len(command_parts) > 0 else "Unknown"
            print(f"\n[ERROR] Command executable not found: '{executable_name}'.")
            exit_code = -100
        except Exception as e:
            print(f"\n[ERROR] Unexpected error in PTY executor: {e}")
            traceback.print_exc()
            exit_code = -101
        finally:
            if master_fd != -1:
                try:
                    os.close(master_fd)
                except OSError:
                    pass
            if slave_fd != -1:
                try:
                    os.close(slave_fd)
                except OSError:
                    pass
            print()
            if exit_code is not None:
                print(f"-------------------------------------------")
                print(f"--- Command Final Exit Code: {exit_code} ---")
                if exit_code == 0:
                    print("Command finished successfully.")
                elif exit_code == 130:
                    pass
                elif exit_code == -99:
                    pass
                elif exit_code < 0:
                    try:
                        sig_name = signal.Signals(-exit_code).name if exit_code <= -1 else "ScriptDefinedError"
                    except ValueError:
                        sig_name = "UnknownSignalOrError"
                    print(f"Command terminated by signal/script error: {sig_name} ({exit_code})")
                else:
                    print(f"Command finished with error code {exit_code}.")

        if exit_code is not None and command_parts:
            return subprocess.CompletedProcess(args=command_parts, returncode=exit_code, stdout=None, stderr=None)
        return None

    def _execute_direct_output_simple_popen(self, command_string: str,
                                            timeout_seconds: int | None = None) -> subprocess.CompletedProcess | None:
        if not command_string.strip(): print("No command provided."); return None
        timeout_msg = f" (timeout: {timeout_seconds}s)" if timeout_seconds else ""
        print(
            f"\n>>> Executing (simple Popen{timeout_msg}): {command_string}\n-------------------------------------------")
        command_parts = []
        process = None
        exit_code = None
        try:
            command_parts = shlex.split(command_string)
            if not command_parts: return None
            process = subprocess.Popen(command_parts)
            exit_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            print(
                f"\n[WARN] Command '{command_parts[0] if command_parts else 'N/A'}' timed out (simple Popen). Terminating...")
            if process: process.terminate(); exit_code = -99;
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill();
            process.wait()
        except KeyboardInterrupt:
            print("\n[WARN] KeyboardInterrupt (simple Popen)!")
            if process and process.poll() is None:
                print("[WARN] Sending SIGINT...")
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=5); exit_code = process.returncode
                except subprocess.TimeoutExpired:
                    print("[WARN] SIGINT no resp. SIGTERM..."); process.terminate()
                    try: process.wait(timeout=3)
                    #exit_code = process.returncodec
                    except subprocess.TimeoutExpired: (
                        print("[WARN] SIGTERM no resp. SIGKILL..."));
                    process.kill()
                    process.wait()
                    exit_code = process.returncode
            else:
                exit_code = 130
            raise

        except FileNotFoundError:
            executable_name = command_parts[0] if command_parts and len(command_parts) > 0 else "Unknown"
        print(f"\n[ERROR] Executable not found (simple Popen): '{executable_name}'.")
        exit_code: int = -100
        try:
            pass


        except Exception as e: print(f"\n[ERROR] Unexpected error (simple Popen): {e} ");traceback.print_exc();
        exit_code = -101
        try:
            pass

        finally:
            print()
            if exit_code is not None:
                   print(f"-------------------------------------------\n--- Command Final Exit Code: {exit_code} ---")
                   if exit_code == 0:
                        print("Command finished successfully.")
                   elif exit_code != 130 and exit_code != -99:
                       print(f"Command finished with error code {exit_code}.")
        if exit_code is not None and command_parts:
            return subprocess.CompletedProcess(args=command_parts, returncode=exit_code, stdout=None, stderr=None)
        return None