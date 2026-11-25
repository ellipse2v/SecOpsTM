# Full option matrix: 2026-11-25

Every CLI option and subcommand of `secopstm`, plus every web-server endpoint, run against
the 18 templates, the multi-model project `projects/example_1`, the 3 Ansible playbooks,
a Terraform and a docker-compose fixture (`fixtures/`). Environment: Python 3.11 venv,
Graphviz 2.43, no AI provider key (the AI rows check the graceful fallback).

**Result: 88/88 CLI rows and 50/50 server requests pass, after 4 fixes in this branch.**

## Bugs found and fixed in this branch

| # | Bug | Fix |
|---|-----|-----|
| 1 | Terraform: `aws_db_instance` (the real RDS resource) was not mapped and was dropped | added to the database types |
| 2 | Terraform: servers were placed only through `vpc_id`; `subnet_id`, `vpc_security_group_ids`… were ignored | placement uses the most specific boundary |
| 3 | Terraform: any subnet or security group without a server made the generated model invalid (`Boundary … defined but not used`), so `--terraform-path` exited 1 on realistic configs | empty boundaries are omitted |
| 4 | `--project --output-file` silently wrote nothing; `--sarif`, `--stdout`, `--output-format` were silently ignored | the file is copied (`.json` → root model JSON, else the global HTML report); the others print a warning |
| 5 | `--ai-config-file /missing.yaml` ran the whole analysis without AI and exited 0 | exits 1 with `file not found` |
| 6 | Server `/api/export` format `diagram` without Graphviz: generic 500 from a 404 on a missing temp SVG | same clear error as format `svg` |

Not a bug: `--ansible-path` takes a `.yml` file, not a directory (rows re-run with the file).

## Where to look

- `templates/<Template>/`: `report.html` (STRIDE/MITRE report), `diagram.svg`, `diagram.html`,
  `report.json`, `report.sarif.json`, `navigator_layer.json`, `stix_attack_flow.json`, `afb/`
- `iac/`: reports generated from Ansible, Terraform, docker-compose, and model + compose
- `project/`: `report.html` (global project report), `report.json`
- `formats/`: html / json / stix / `--stdout` / mitigations+CVE outputs
- `server/`, `server_project/`: every endpoint's response (`export_*.svg|html|md|zip`), `server.log`
- `logs/<row>.log`: full output of each CLI row

## CLI rows

| Result | Row | Exit | Expected | Time |
|---|---|---|---|---|
| PASS | `version` | 0 | 0 | 1s |
| PASS | `help` | 0 | 0 | 0s |
| PASS | `demo_list` | 0 | 0 | 0s |
| PASS | `demo_cloud` | 0 | 0 | 3s |
| PASS | `demo_onprem` | 0 | 0 | 3s |
| PASS | `demo_bad` | 2 | 2 | 0s |
| PASS | `validate_Advanced_Cloud_WebApp` | 0 | 0 | 0s |
| PASS | `all_Advanced_Cloud_WebApp` | 0 | 0 | 2s |
| PASS | `validate_CI_CD_Pipeline` | 0 | 0 | 0s |
| PASS | `all_CI_CD_Pipeline` | 0 | 0 | 2s |
| PASS | `validate_Cloud_Native_Architecture` | 0 | 0 | 1s |
| PASS | `all_Cloud_Native_Architecture` | 0 | 0 | 2s |
| PASS | `validate_Data_Warehouse_Data_Lake` | 0 | 0 | 0s |
| PASS | `all_Data_Warehouse_Data_Lake` | 0 | 0 | 2s |
| PASS | `validate_GDAF_Debate_Smoke_Test` | 0 | 0 | 0s |
| PASS | `all_GDAF_Debate_Smoke_Test` | 0 | 0 | 2s |
| PASS | `validate_IP_Camera_Surveillance` | 0 | 0 | 0s |
| PASS | `all_IP_Camera_Surveillance` | 0 | 0 | 3s |
| PASS | `validate_IoT` | 0 | 0 | 0s |
| PASS | `all_IoT` | 0 | 0 | 2s |
| PASS | `validate_Kubernetes_Helm_Cluster` | 0 | 0 | 0s |
| PASS | `all_Kubernetes_Helm_Cluster` | 0 | 0 | 3s |
| PASS | `validate_LLM_RAG_Application` | 0 | 0 | 0s |
| PASS | `all_LLM_RAG_Application` | 0 | 0 | 3s |
| PASS | `validate_Microservices_Architecture` | 0 | 0 | 1s |
| PASS | `all_Microservices_Architecture` | 0 | 0 | 2s |
| PASS | `validate_Mobile_Application` | 0 | 0 | 0s |
| PASS | `all_Mobile_Application` | 0 | 0 | 2s |
| PASS | `validate_On-Prem_Enterprise_Network` | 0 | 0 | 0s |
| PASS | `all_On-Prem_Enterprise_Network` | 0 | 0 | 3s |
| PASS | `validate_Satellite_Ground_Segment` | 0 | 0 | 0s |
| PASS | `all_Satellite_Ground_Segment` | 0 | 0 | 3s |
| PASS | `validate_Serverless_AWS_Lambda` | 0 | 0 | 0s |
| PASS | `all_Serverless_AWS_Lambda` | 0 | 0 | 2s |
| PASS | `validate_Simple_Monolithic_Web_Application` | 0 | 0 | 0s |
| PASS | `all_Simple_Monolithic_Web_Application` | 0 | 0 | 2s |
| PASS | `validate_Three_Tier_Architecture` | 0 | 0 | 1s |
| PASS | `all_Three_Tier_Architecture` | 0 | 0 | 2s |
| PASS | `validate_Traditional_Enterprise_Network` | 0 | 0 | 0s |
| PASS | `all_Traditional_Enterprise_Network` | 0 | 0 | 2s |
| PASS | `validate_UAV_Drone_System` | 0 | 0 | 0s |
| PASS | `all_UAV_Drone_System` | 0 | 0 | 3s |
| PASS | `validate_Zero_Trust` | 0 | 0 | 0s |
| PASS | `all_Zero_Trust` | 0 | 0 | 2s |
| PASS | `validate_project` | 0 | 0 | 0s |
| PASS | `validate_missing` | 1 | 1,2 | 0s |
| PASS | `fmt_html` | 0 | 0 | 2s |
| PASS | `fmt_json` | 0 | 0 | 2s |
| PASS | `fmt_stix` | 0 | 0 | 2s |
| PASS | `fmt_all` | 0 | 0 | 2s |
| PASS | `fmt_default_outdir` | 0 | 0 | 3s |
| PASS | `stdout` | 0 | 0 | 2s |
| PASS | `stdout_parse` | 0 | 0 | 0s |
| PASS | `stdout_json_navigator_sarif` | 0 | 0 | 2s |
| PASS | `log_debug` | 0 | 0 | 2s |
| PASS | `log_error` | 0 | 0 | 2s |
| PASS | `mitig_cve` | 0 | 0 | 2s |
| PASS | `project_all` | 0 | 0 | 2s |
| PASS | `project_json` | 0 | 0 | 2s |
| PASS | `terraform` | 0 | 0 | 0s |
| PASS | `docker_compose` | 0 | 0 | 2s |
| PASS | `iac_plus_model` | 0 | 0 | 2s |
| PASS | `diff_same` | 0 | 0 | 0s |
| PASS | `diff_two` | 0 | 0 | 1s |
| PASS | `diff_missing` | 2 | 1,2 | 0s |
| PASS | `gate_CRITICAL` | 1 | 0,1 | 0s |
| PASS | `gate_HIGH` | 1 | 0,1 | 1s |
| PASS | `gate_MEDIUM` | 1 | 0,1 | 0s |
| PASS | `gate_LOW` | 1 | 0,1 | 1s |
| PASS | `gate_baseline_self` | 0 | 0 | 0s |
| PASS | `gate_accepted` | 1 | 0,1 | 0s |
| PASS | `gate_missing` | 2 | 1,2 | 1s |
| PASS | `ai_default` | 0 | 0 | 12s |
| PASS | `ai_norag_perf` | 0 | 0 | 6s |
| PASS | `ai_quality` | 0 | 0 | 5s |
| PASS | `ai_fail_on_error` | 3 | 0,3 | 6s |
| PASS | `ai_config_file` | 0 | 0 | 6s |
| PASS | `ai_config_missing` | 1 | 1,2 | 2s |
| PASS | `err_missing_model` | 1 | 1,2 | 0s |
| PASS | `err_missing_project` | 1 | 1,2 | 1s |
| PASS | `err_invalid_model` | 1 | 1 | 0s |
| PASS | `err_bad_format` | 2 | 2 | 1s |
| PASS | `err_noargs` | 0 | 0,1,2 | 12s |
| PASS | `ansible_complex_network_topology_playbook` | 0 | 0 | - |
| PASS | `ansible_simple_web_server` | 0 | 0 | - |
| PASS | `ansible_three_tier_web_app` | 0 | 0 | - |
| PASS | `project_output_file_html` | 0 | 0 | - |
| PASS | `project_output_file_json_sarif` | 0 | 0 | - |

## Server requests (`--server --no-ai`, then `--project example_1 --graphical-editor`)

```
200	GET /	6197 bytes
200	GET /simple	157041 bytes
404	GET /graphical	207 bytes
200	GET /diff	17858 bytes
200	GET /api/data_dictionary	1459 bytes
200	GET /api/ai_status	20 bytes
200	GET /api/models	29 bytes
200	GET /api/workspaces	3 bytes
200	POST /api/validate_markdown	113 bytes
200	POST /api/validate_markdown	168 bytes
200	POST /api/markdown_to_json	2462 bytes
200	POST /api/update	829338 bytes
200	POST /api/export	372543 bytes
200	POST /api/export	453529 bytes
200	POST /api/export	1237512 bytes
200	POST /api/export	1422 bytes
400	POST /api/export	39 bytes
200	POST /api/export_all	885064 bytes
200	POST /api/export_navigator_stix	7915 bytes
200	POST /api/export_json	1119506 bytes
200	POST /api/generate_all	690 bytes
400	POST /api/export	54 bytes
400	POST /api/update	38 bytes
200	POST /api/diff_reports	87 bytes
400	POST /api/diff_reports	33 bytes
```

`GET /graphical` answers 404 without `--graphical-editor` and 200 with it (expected).
