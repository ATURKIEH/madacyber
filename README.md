# Madacyber – Subdomain Enumeration & Recon Pipeline

Madacyber is a **modular subdomain enumeration and reconnaissance tool** designed to discover subdomains and historical endpoints for a given target domain.

The project is intentionally built in **two clear layers**:

1. **A standalone, local subdomain enumeration pipeline**
2. **A cloud-native AWS Lambda implementation** of the same pipeline for scalable, serverless execution

---

## 🚀 Part 1 – Subdomain Enumeration Pipeline (Core Logic)

This part of the project focuses purely on **subdomain discovery and URL enumeration**, independent of any cloud infrastructure.

### Features
* **Certificate Transparency** enumeration using `crt.sh`.
* **Optional DNS brute-forcing** via `FFUF`.
* **Optional crawling** via `GoSpider`.
* **Historical URL discovery** using `GAU` (GetAllURLs).
* **Automatic deduplication** of results.
* **Modular Python architecture** (easy to extend or swap tools).

### Local Usage Example
```bash
python main.py -d example.com
```
### Local Outputs
* Discovered subdomains: Clean list of unique hosts.

* Historical endpoints: Extensive URL lists per subdomain.

* Deduplicated URL lists: Optimized for security testing.

## ☁️ Part 2 – AWS Serverless Implementation
The second part of the project packages the same enumeration pipeline into a serverless AWS architecture for scalable execution.

### Architecture Overview
* AWS Lambda (Docker-based): Executes the logic in a reproducible container.

* Amazon ECR: Stores the container images containing external binaries (gau, ffuf, gospider).

* Amazon S3: Persistent storage for all scan artifacts.

* AWS CloudWatch Logs: Real-time monitoring of execution steps.

#### Lambda Invocation Example

```bash
aws lambda invoke \
  --function-name madacyber-cli-lambda \
  --region us-east-2 \
  --invocation-type Event \
  --cli-binary-format raw-in-base64-out \
  --payload file://event_discover.json \
  response.json
```
#### Monitor Execution
```bash
aws logs tail /aws/lambda/madacyber-cli-lambda --follow
```
### 📦 Output & Artifacts (S3)
All execution results are written to Amazon S3 under the following structure: s3://subdomain-enum-results-aref-4821/runs/<domain>/<job-id>/

Stored Files:
* meta.json: Job metadata (domain, timestamp, artifact location).

* artifacts.tar.gz: Compressed enumeration results.

* subdomains.txt: Combined unique subdomain list.

* gau_urls.txt: Historical URLs from GAU.

### 📂 Repository Structure
```plaintext
.
├── main.py              # Local entry point
├── lambda_entry.py      # AWS Lambda handler
├── fetcher.py           # Core logic for data retrieval
├── gau_module.py        # GAU integration
├── gospider_module.py   # GoSpider integration
├── command_executer.py  # Shell command wrapper
├── Dockerfile           # Lambda container definition
├── requirements.txt     # Python dependencies
├── artifacts/           # Local output directory
└── wordlists/           # FFUF discovery lists
```

