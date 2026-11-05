#!/bin/bash
# Runs every CLI combination of SecOpsTM, one folder per case under test_runs/<case>/
V=/tmp/claude-0/-home-user-SecOpsTM/5ffa15b6-1b01-550b-b3a4-aee193405fe5/scratchpad/venv/bin
cd /home/user/SecOpsTM
R=test_runs; M=threatModel_Template
SUMMARY=$R/summary.tsv; echo -e "case\texit\tseconds\tfiles\tcommand" > $SUMMARY
run() { # name, args...
  local n=$1; shift; local d=$R/$n; rm -rf $d; mkdir -p $d
  local t0=$(date +%s)
  ( cd $d && timeout 600 env PYTHONPATH=/home/user/SecOpsTM $V/secopstm "$@" ) > $d/stdout.log 2> $d/stderr.log
  local rc=$?; local t=$(( $(date +%s)-t0 ))
  local nf=$(find $d -type f ! -name '*.log' | wc -l)
  echo -e "$n\t$rc\t$t\t$nf\tsecopstm $*" | tee -a $SUMMARY
}
ABS=/home/user/SecOpsTM
# Pre-create output via cwd so each run is isolated (outputs go to ./output in cwd)
S=$M/Simple_Monolithic_Web_Application/model.md
run fmt_all      --model-file $ABS/$S --no-ai --output-format all
run fmt_html     --model-file $ABS/$S --no-ai --output-format html
run fmt_json     --model-file $ABS/$S --no-ai --output-format json
run fmt_stix     --model-file $ABS/$S --no-ai --output-format stix
run stdout       --model-file $ABS/$S --no-ai --stdout
run output_file  --model-file $ABS/$S --no-ai --output-format json --output-file $ABS/$R/output_file/report.json
run navigator    --model-file $ABS/$S --no-ai --navigator
run sarif        --model-file $ABS/$S --no-ai --sarif
run attack_flow  --model-file $ABS/$S --no-ai --attack-flow
run all_extras   --model-file $ABS/$S --no-ai --navigator --sarif --attack-flow --output-format all
run no_rag       --model-file $ABS/$S --no-rag
run log_debug    --model-file $ABS/$S --no-ai --log-level DEBUG
run default_tpl  --model-file $ABS/$M/threat_model.md --no-ai
run version      --version
run help         --help
run demo_list    demo --list
run demo_cloud   demo cloud --no-browser
run demo_onprem  demo on-prem --no-browser
# every bundled template
for d in $ABS/$M/*/; do n=$(basename $d); [ -f $d/model.md ] && run tpl_$n --model-file $d/model.md --no-ai --navigator --sarif; done
# projects (multi-model)
for d in $ABS/$M/projects/*/; do n=$(basename $d); run proj_$n --project $d --no-ai; done
# IaC plugins
run iac_ansible   --model-file $ABS/$S --no-ai --ansible-path $ABS/tests/ansible_playbooks/simple_web_server
run iac_ansible_3 --model-file $ABS/$S --no-ai --ansible-path $ABS/tests/ansible_playbooks/three_tier_web_app
run iac_compose   --model-file $ABS/$S --no-ai --docker-compose-path $ABS/test_runs/fixtures/compose
run iac_terraform --model-file $ABS/$S --no-ai --terraform-path $ABS/test_runs/fixtures/tf
# validate
run validate      validate --model-dir $ABS/$M/IoT
run validate_v    validate --model-dir $ABS/$M/IoT --verbose
run validate_proj validate --model-dir $ABS/$M/projects/example_1
# diff / gate (use reports from earlier runs)
J1=$(ls $ABS/$R/fmt_json/output/*/*.json | grep -v -E "stix|metadata|navigator" | head -1)
J2=$(ls $ABS/$R/tpl_IoT/output/*/*.json | grep -v -E "stix|metadata|navigator" | head -1)
run diff_same     --diff $J1 $J1
run diff_other    --diff $J1 $J2
run gate_crit     --gate $J1
for s in HIGH MEDIUM LOW; do run gate_$s --gate $J1 --fail-on $s; done
run gate_baseline --gate $J2 --baseline $J1 --fail-on HIGH
cat > $ABS/$R/fixtures/accepted.yaml <<'Y'
accepted_risks: []
Y
run gate_accepted --gate $J1 --accepted-risks $ABS/$R/fixtures/accepted.yaml
# error cases
run err_missing_model --model-file /nonexistent.md --no-ai
run err_bad_diff      --diff /nope1.json /nope2.json
run err_bad_format    --output-format xml
