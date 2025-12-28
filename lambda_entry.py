import os
import json
import uuid
import traceback
import boto3

from main import run_recon_pipeline, find_executable, COMMON_TOOL_DIRECTORIES, DEFAULT_GOSPIDER_OPERATIONAL_FLAGS, DEFAULT_GAU_ADDITIONAL_FLAGS

s3 = boto3.client("s3")

def _s3_put_text(bucket: str, key: str, text: str):
    s3.put_object(Bucket=bucket, Key=key, Body=text.encode("utf-8"))

def _s3_get_text(bucket: str, key: str) -> str:
    obj = s3.get_object(Bucket=bucket, Key=key)
    return obj["Body"].read().decode("utf-8", errors="replace")

def _s3_put_file(bucket: str, key: str, path: str):
    s3.upload_file(path, bucket, key)

def lambda_handler(event, context):
    """
    event examples:
      {"stage":"discover","domain":"example.com"}
      {"stage":"crawl","domain":"example.com","run_id":"<same as discover run_id>"}
      {"stage":"gau","domain":"example.com","run_id":"<same as discover run_id>"}
    """
    bucket = os.environ.get("RESULTS_BUCKET")
    if not bucket:
        return {"statusCode": 500, "body": json.dumps({"error": "RESULTS_BUCKET env var not set"})}

    stage = (event.get("stage") or "").strip().lower()
    domain = (event.get("domain") or "").strip().lower()

    if not domain or "." not in domain:
        return {"statusCode": 400, "body": json.dumps({"error": "missing/invalid 'domain' in event"})}

    if stage not in {"discover", "crawl", "gau"}:
        return {"statusCode": 400, "body": json.dumps({"error": "stage must be one of: discover, crawl, gau"})}

    run_id = (event.get("run_id") or "").strip() or uuid.uuid4().hex[:10]
    prefix = f"{domain}/{run_id}"

    # Lambda writable base dir
    base_output = f"/tmp/{domain}_{run_id}"
    os.makedirs(base_output, exist_ok=True)

    # tools (they should be in /usr/local/bin from your Dockerfile copy)
    ffuf_exe = find_executable("ffuf", COMMON_TOOL_DIRECTORIES) or "/usr/local/bin/ffuf"
    gospider_exe = find_executable("gospider", COMMON_TOOL_DIRECTORIES) or "/usr/local/bin/gospider"
    gau_exe = find_executable("gau", COMMON_TOOL_DIRECTORIES) or "/usr/local/bin/gau"
    curl_exe = find_executable("curl", COMMON_TOOL_DIRECTORIES) or "/usr/bin/curl"

    # stage-specific switches
    fast_mode = os.environ.get("FAST_MODE", "1") == "1"
    gospider_flags = os.environ.get("GOSPIDER_FLAGS", DEFAULT_GOSPIDER_OPERATIONAL_FLAGS)
    gau_flags = os.environ.get("GAU_FLAGS", DEFAULT_GAU_ADDITIONAL_FLAGS)
    gau_config_file = os.environ.get("GAU_CONFIG", None)

    try:
        # ---- DISCOVER: only crtsh (and optionally ffuf, but we’ll keep it off in lambda) ----
        if stage == "discover":
            # Force fast_mode in lambda discover (skip ffuf)
            os.environ["FAST_MODE"] = "1"

            # run pipeline but we will stop after crtsh by using a tiny trick:
            # call run_recon_pipeline with fast_mode True and no ffuf wordlist (it will skip)
            run_recon_pipeline(
                target_domain=domain,
                gospider_additional_flags=gospider_flags,
                ffuf_exe=ffuf_exe,
                wordlist="",                 # forces ffuf skip
                gospider_exe=gospider_exe,
                curl_exe=curl_exe,
                gau_exe=gau_exe,
                fast_mode=True,              # forces ffuf skip
                gau_additional_flags="--providers wayback,commoncrawl --threads 5",  # still okay but we won't use here
                gau_config_file=gau_config_file,
                main_run_base_output_directory=base_output
            )

            # Find the combined hosts file your code writes:
            # it writes into base_output/<safe_dir>/<safe_dir>_final.txt
            safe_dir = domain.replace(".", "_")
            combined_path = f"{base_output}/{safe_dir}/{safe_dir}_final.txt"

            if not os.path.exists(combined_path):
                return {"statusCode": 500, "body": json.dumps({"error": "discover ran but no final host list found", "run_id": run_id})}

            _s3_put_file(bucket, f"{prefix}/hosts_final.txt", combined_path)

            return {"statusCode": 200, "body": json.dumps({"ok": True, "stage": stage, "domain": domain, "run_id": run_id, "s3_prefix": prefix})}

        # ---- CRAWL: run gospider on host list from S3, save live list ----
        if stage == "crawl":
            hosts_key = f"{prefix}/hosts_final.txt"
            hosts_text = _s3_get_text(bucket, hosts_key)

            safe_dir = domain.replace(".", "_")
            stage_dir = f"{base_output}/{safe_dir}"
            os.makedirs(stage_dir, exist_ok=True)

            hosts_path = f"{stage_dir}/{safe_dir}_final.txt"
            with open(hosts_path, "w", encoding="utf-8") as f:
                f.write(hosts_text)

            # run full pipeline but make it effectively only gospider:
            # - skip ffuf by fast_mode True
            # - keep gau flags minimal, but we won't rely on it here
            run_recon_pipeline(
                target_domain=domain,
                gospider_additional_flags=gospider_flags,
                ffuf_exe=ffuf_exe,
                wordlist="",
                gospider_exe=gospider_exe,
                curl_exe=curl_exe,
                gau_exe=gau_exe,
                fast_mode=True,
                gau_additional_flags="--providers wayback,commoncrawl --threads 5",
                gau_config_file=gau_config_file,
                main_run_base_output_directory=base_output
            )

            live_path = f"{stage_dir}/{safe_dir}_gospider_live.txt"
            if os.path.exists(live_path) and os.path.getsize(live_path) > 0:
                _s3_put_file(bucket, f"{prefix}/gospider_live.txt", live_path)
                return {"statusCode": 200, "body": json.dumps({"ok": True, "stage": stage, "domain": domain, "run_id": run_id, "s3_prefix": prefix})}

            # even if empty, still continue
            _s3_put_text(bucket, f"{prefix}/gospider_live.txt", "")
            return {"statusCode": 200, "body": json.dumps({"ok": True, "stage": stage, "domain": domain, "run_id": run_id, "note": "no live hosts found"})}

        # ---- GAU: run gau using live list if exists, else host list ----
        if stage == "gau":
            safe_dir = domain.replace(".", "_")
            stage_dir = f"{base_output}/{safe_dir}"
            os.makedirs(stage_dir, exist_ok=True)

            live_key = f"{prefix}/gospider_live.txt"
            hosts_key = f"{prefix}/hosts_final.txt"

            live_text = _s3_get_text(bucket, live_key) if True else ""
            if live_text.strip():
                input_text = live_text
                input_name = f"{safe_dir}_gospider_live.txt"
            else:
                input_text = _s3_get_text(bucket, hosts_key)
                input_name = f"{safe_dir}_final.txt"

            input_path = f"{stage_dir}/{input_name}"
            with open(input_path, "w", encoding="utf-8") as f:
                f.write(input_text)

            # run pipeline but we want GAU to use the file we wrote:
            # Your main code decides input_for_gau based on gospider_live existence.
            # So if we named it as _gospider_live.txt, we also ensure it exists.
            if input_name.endswith("_gospider_live.txt"):
                # also create the exact expected filename
                expected_live = f"{stage_dir}/{safe_dir}_gospider_live.txt"
                if expected_live != input_path:
                    with open(expected_live, "w", encoding="utf-8") as f:
                        f.write(input_text)

            run_recon_pipeline(
                target_domain=domain,
                gospider_additional_flags=gospider_flags,
                ffuf_exe=ffuf_exe,
                wordlist="",
                gospider_exe=gospider_exe,
                curl_exe=curl_exe,
                gau_exe=gau_exe,
                fast_mode=True,
                gau_additional_flags=gau_flags,
                gau_config_file=gau_config_file,
                main_run_base_output_directory=base_output
            )

            # upload whole run folder (best effort: upload key outputs)
            out_dir = f"{base_output}/{safe_dir}"
            # upload combined host list again + gospider live if present + any gau outputs dir
            for local_name, s3_name in [
                (f"{out_dir}/{safe_dir}_final.txt", "hosts_final.txt"),
                (f"{out_dir}/{safe_dir}_gospider_live.txt", "gospider_live.txt"),
            ]:
                if os.path.exists(local_name):
                    _s3_put_file(bucket, f"{prefix}/{s3_name}", local_name)

            gau_dir = f"{out_dir}/gau_temp_outputs"
            if os.path.isdir(gau_dir):
                for fname in os.listdir(gau_dir):
                    fpath = os.path.join(gau_dir, fname)
                    if os.path.isfile(fpath):
                        _s3_put_file(bucket, f"{prefix}/gau/{fname}", fpath)

            return {"statusCode": 200, "body": json.dumps({"ok": True, "stage": stage, "domain": domain, "run_id": run_id, "s3_prefix": prefix})}

    except Exception as e:
        traceback.print_exc()
        return {"statusCode": 500, "body": json.dumps({"error": str(e), "stage": stage, "domain": domain, "run_id": run_id})}
