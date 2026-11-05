#!/bin/bash
V=/tmp/claude-0/-home-user-SecOpsTM/5ffa15b6-1b01-550b-b3a4-aee193405fe5/scratchpad/venv/bin
ABS=/home/user/SecOpsTM; R=$ABS/test_runs; S=$ABS/threatModel_Template/Simple_Monolithic_Web_Application/model.md
run() { n=$1; shift; d=$R/$n; rm -rf $d; mkdir -p $d; t0=$(date +%s)
  ( cd $d && timeout 300 env PYTHONPATH=$ABS $V/secopstm "$@" ) >$d/stdout.log 2>$d/stderr.log; rc=$?
  echo -e "$n\t$rc\t$(( $(date +%s)-t0 ))\t$(find $d -type f ! -name '*.log'|wc -l)\tsecopstm $*" | tee -a $R/summary.tsv; }
J1=$(ls $R/fmt_json/output/*/*.json | grep -v -E "stix|metadata|navigator" | head -1)
cat > $R/fixtures/accepted.yaml <<'Y'
accepted_risks:
  - description_contains: "Spoofing"
    decision: false_positive
    rationale: test fixture
    reviewer: tester
Y
sed -i '/^iac_ansible/d;/^gate_accepted/d' $R/summary.tsv
run iac_ansible   --model-file $S --no-ai --ansible-path $ABS/tests/ansible_playbooks/simple_web_server/simple_web_server.yml
run iac_ansible_3 --model-file $S --no-ai --ansible-path $ABS/tests/ansible_playbooks/three_tier_web_app/three_tier_web_app.yml
run iac_ansible_gi --model-file $S --no-ai --ansible-path $ABS/tests/ansible_playbooks/generic_infrastructure/complex_network_topology_playbook.yml
run gate_accepted --gate $J1 --accepted-risks $R/fixtures/accepted.yaml --fail-on HIGH
run gate_pass_baseline --gate $J1 --baseline $J1
run impl_mitig --model-file $S --no-ai --implemented-mitigations-file $ABS/tests/implemented_mitigations.txt --cve-definitions-file $ABS/tests/cve_definitions.yml
run ai_config_missing --model-file $S --ai-config-file /nonexistent.yaml
run all_combo --model-file $S --no-ai --navigator --sarif --attack-flow --output-format all --log-level WARNING --output-file $R/all_combo/report
