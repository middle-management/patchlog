#!/usr/bin/env bash
# How many devices a deployment holds, each long-polling its own resource
# (§7.7) as a device that started a workflow run waits for its result:
# cmd/devicebench on load generator instances of their own connects devices
# in steps to SERVERS instances of the core, which share an RDS Postgres (or
# one instance on SQLite), until the run's last step or until it breaks. Each
# step completes random devices' resources and measures how long that took to
# reach them, beside a background writer loading the same namespace.
# deploy/devices-summary.py prints a row per step and names the first that
# looks broken.
#
#   ./deploy/ec2-devices.sh [-y]       a run
#   ./deploy/ec2-devices.sh cleanup    the IAM role, profile, RDS instance
#
# Settings (environment), with their defaults:
#   REGION        aws configure's
#   BACKEND       postgres (RDS) or sqlite (one server on its own disk)
#   SERVERS       3 core instances (1 for sqlite); writes go to the first,
#                 device i long-polls the (i mod SERVERS)th
#   LOADGENS      3 load generator instances
#   DEVICES       40000 devices per load generator, so LOADGENS × DEVICES in all
#   STEP          5000 devices added per load generator a step
#   STEP_SECS     90 seconds measured a step (RDS CPU comes in one-minute
#                 averages: keep it 60 or more)
#   SETTLE        20 seconds a step has to connect its devices first
#   COMPLETIONS   50 completions a second per load generator
#   BG            300 background writes a second, from the first load generator
#   SERVER_TYPE   c7g.xlarge (4 vCPU, 8 GiB)
#   LOADGEN_TYPE  c7g.xlarge, the same architecture as SERVER_TYPE
#   DB_CLASS      db.m7g.large (2 vCPU, 8 GiB)
#   SUBNET        the default VPC's; for postgres, one in the RDS instance's VPC
#   OUT           ./devices-<time>, where the raw results and summary go
#
# What it makes, after asking (-y doesn't ask):
#   - IAM role and instance profile patchlog-devices, kept for the next run:
#     SSM's managed policy (no SSH, no open ports) and reading the RDS URL's
#     parameter.
#   - For postgres, RDS instance patchlog-devices, if it's missing (5–10
#     minutes; billed by the hour while it exists, `cleanup` deletes it):
#     single-AZ, 20 GiB gp3, no backups, not publicly accessible, in the
#     default VPC with its default security group, which the instances share
#     and which lets its members reach each other; its URL, with a generated
#     password, is SecureString parameter /patchlog-devices/db-url.
#   - SERVERS + LOADGENS instances, terminated on exit, and by themselves
#     once the run should have ended, should this script die first.
#
# The core and devicebench are built from this checkout, uncommitted changes
# included, and copied over SSH through SSM with a throwaway key EC2 Instance
# Connect lets in for 60 seconds, as deploy/ec2-bench.sh on branch dynamodb
# does. Needs the AWS CLI v2, credentials allowed to do the above and to read
# CloudWatch, Go, ssh, python3 and AWS's session-manager-plugin.
set -euo pipefail

REGION=${REGION:-${AWS_REGION:-$(aws configure get region || true)}}
BACKEND=${BACKEND:-postgres}
SERVERS=${SERVERS:-$([ "$BACKEND" = sqlite ] && echo 1 || echo 3)}
LOADGENS=${LOADGENS:-3}
DEVICES=${DEVICES:-40000}
STEP=${STEP:-5000}
STEP_SECS=${STEP_SECS:-90}
SETTLE=${SETTLE:-20}
COMPLETIONS=${COMPLETIONS:-50}
BG=${BG:-300}
SERVER_TYPE=${SERVER_TYPE:-c7g.xlarge}
LOADGEN_TYPE=${LOADGEN_TYPE:-c7g.xlarge}
DB_CLASS=${DB_CLASS:-db.m7g.large}
OUT=${OUT:-./devices-$(date +%Y%m%d-%H%M%S)}
NAME=patchlog-devices
ROLE=$NAME DB=$NAME DB_PARAM=/$NAME/db-url
[ -n "$REGION" ] || { echo "ec2-devices: set REGION (or aws configure set region …)" >&2; exit 1; }
export AWS_REGION=$REGION AWS_PAGER=""
case $BACKEND in postgres) ;; sqlite) [ "$SERVERS" = 1 ] || { echo "ec2-devices: sqlite serves from one instance: SERVERS=1" >&2; exit 2; } ;;
  *) echo "ec2-devices: BACKEND is postgres or sqlite" >&2; exit 2 ;; esac
for v in SERVERS LOADGENS DEVICES STEP STEP_SECS SETTLE COMPLETIONS BG; do
  case ${!v} in ''|*[!0-9]*) echo "ec2-devices: $v is a whole number" >&2; exit 2 ;; esac
done
[ "$SERVERS" -ge 1 ] && [ "$LOADGENS" -ge 1 ] && [ "$STEP" -ge 1 ] || { echo "ec2-devices: SERVERS, LOADGENS and STEP are at least 1" >&2; exit 2; }
# A load generator reaches each server from one address: an ephemeral port
# range (1024–65535 here) of connections to each.
[ $(( (DEVICES + SERVERS - 1) / SERVERS )) -le 60000 ] || { echo "ec2-devices: over 60,000 devices from one load generator to one server; add SERVERS or LOADGENS" >&2; exit 2; }

if [ "${1:-}" = cleanup ]; then
  aws iam remove-role-from-instance-profile --instance-profile-name $ROLE --role-name $ROLE 2>/dev/null || true
  aws iam delete-instance-profile --instance-profile-name $ROLE 2>/dev/null || true
  aws iam detach-role-policy --role-name $ROLE --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore 2>/dev/null || true
  aws iam delete-role-policy --role-name $ROLE --policy-name dbparam 2>/dev/null || true
  aws iam delete-role --role-name $ROLE 2>/dev/null || true
  echo "ec2-devices: deleted role and instance profile $ROLE (if they existed)"
  if aws rds describe-db-instances --db-instance-identifier $DB >/dev/null 2>&1; then
    aws rds delete-db-instance --db-instance-identifier $DB --skip-final-snapshot --delete-automated-backups >/dev/null
    echo "ec2-devices: deleting RDS instance $DB (it stops billing once gone, in a few minutes)"
  fi
  aws ssm delete-parameter --name $DB_PARAM 2>/dev/null || true
  exit 0
fi
YES=""
[ "${1:-}" = -y ] && YES=1

for tool in go ssh scp ssh-keygen session-manager-plugin python3; do
  command -v $tool >/dev/null || { echo "ec2-devices: needs $tool" >&2; exit 1; }
done
steps=$(( (DEVICES + STEP - 1) / STEP ))
run_secs=$(( steps * (STEP_SECS + SETTLE) ))
# Instances power off (and so terminate) this long after they start.
life_min=$(( run_secs / 60 + 45 ))

account=$(aws sts get-caller-identity --query Account --output text)
db_state=""
[ "$BACKEND" != postgres ] || db_state=$(aws rds describe-db-instances --db-instance-identifier $DB \
  --query 'DBInstances[0].[DBInstanceStatus,DBInstanceClass]' --output text 2>/dev/null || true)
have_role=$(aws iam get-role --role-name $ROLE --query Role.Arn --output text 2>/dev/null || true)
arch_of() { aws ec2 describe-instance-types --instance-types "$1" --query 'InstanceTypes[0].ProcessorInfo.SupportedArchitectures[0]' --output text; }
arch=$(arch_of "$SERVER_TYPE")
[ "$(arch_of "$LOADGEN_TYPE")" = "$arch" ] || { echo "ec2-devices: SERVER_TYPE and LOADGEN_TYPE differ in architecture" >&2; exit 2; }
case $arch in arm64) goarch=arm64 ;; x86_64) goarch=amd64 ;; *) echo "ec2-devices: $SERVER_TYPE: architecture $arch" >&2; exit 1 ;; esac
if [ -z "${SUBNET:-}" ]; then
  SUBNET=$(aws ec2 describe-subnets --filters Name=default-for-az,Values=true --query 'Subnets[0].SubnetId' --output text)
  [ "$SUBNET" != None ] || { echo "ec2-devices: no default VPC here; set SUBNET to one with a route out" >&2; exit 1; }
fi
if [ -n "$db_state" ]; then
  db_vpc=$(aws rds describe-db-instances --db-instance-identifier $DB --query 'DBInstances[0].DBSubnetGroup.VpcId' --output text)
  sub_vpc=$(aws ec2 describe-subnets --subnet-ids "$SUBNET" --query 'Subnets[0].VpcId' --output text)
  [ "$db_vpc" = "$sub_vpc" ] || { echo "ec2-devices: RDS instance $DB is in $db_vpc, subnet $SUBNET in $sub_vpc; set SUBNET to one of $db_vpc" >&2; exit 1; }
fi
ami=$(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-$arch --query Parameter.Value --output text)
root=$(cd "$(dirname "$0")/.." && pwd)
rev=$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)
[ -z "$(git -C "$root" status --porcelain -- cmd internal go.mod go.sum 2>/dev/null)" ] || rev=$rev+changes

echo "account $account, region $REGION, backend $BACKEND"
case $BACKEND in
postgres) echo "  RDS instance $DB: $([ -n "$db_state" ] && echo "exists ($db_state)" || echo "to make ($DB_CLASS, 5–10 minutes; billed hourly until cleanup)")" ;;
sqlite) echo "  SQLite: a file on the server's disk" ;;
esac
echo "  role $ROLE: $([ -n "$have_role" ] && echo exists || echo 'to make')"
echo "  $SERVERS × $SERVER_TYPE server(s) and $LOADGENS × $LOADGEN_TYPE load generator(s) ($arch, $ami) in $SUBNET,"
echo "    terminated on exit, or by themselves after $life_min minutes"
echo "  core and devicebench built from this checkout ($rev, linux/$goarch)"
echo "  run: $steps steps of $(( LOADGENS * STEP )) devices up to $(( LOADGENS * DEVICES )), ${STEP_SECS}s measured each (about $(( run_secs / 60 + 1 )) minutes),"
echo "    $(( LOADGENS * COMPLETIONS )) completions/s and $BG background writes/s; results in $OUT"
if [ -z "$YES" ]; then
  read -r -p "Go ahead? [y/N] " ok
  [ "$ok" = y ] || [ "$ok" = Y ] || exit 1
fi

# The role: SSM to reach the instances, and the RDS URL's parameter.
if [ -z "$have_role" ]; then
  aws iam create-role --role-name $ROLE --description "patchlog deploy/ec2-devices.sh" \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
  aws iam attach-role-policy --role-name $ROLE --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
  aws iam create-instance-profile --instance-profile-name $ROLE >/dev/null
  aws iam add-role-to-instance-profile --instance-profile-name $ROLE --role-name $ROLE
  echo "made role and instance profile $ROLE"
fi
if [ "$BACKEND" = postgres ]; then
  if [ -z "$db_state" ]; then
    pw=$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)
    aws rds create-db-instance --db-instance-identifier $DB --engine postgres \
      --db-instance-class "$DB_CLASS" --allocated-storage 20 --storage-type gp3 \
      --master-username patchlog --master-user-password "$pw" --db-name patchlog \
      --no-publicly-accessible --no-multi-az --backup-retention-period 0 \
      --tags Key=Name,Value=$NAME >/dev/null
    echo "making RDS instance $DB ($DB_CLASS): 5–10 minutes"
    aws rds wait db-instance-available --db-instance-identifier $DB
    host=$(aws rds describe-db-instances --db-instance-identifier $DB --query 'DBInstances[0].Endpoint.Address' --output text)
    aws ssm put-parameter --name $DB_PARAM --type SecureString --overwrite \
      --value "postgres://patchlog:$pw@$host:5432/patchlog?sslmode=require" >/dev/null
    unset pw
    db_vpc=$(aws rds describe-db-instances --db-instance-identifier $DB --query 'DBInstances[0].DBSubnetGroup.VpcId' --output text)
    sub_vpc=$(aws ec2 describe-subnets --subnet-ids "$SUBNET" --query 'Subnets[0].VpcId' --output text)
    [ "$db_vpc" = "$sub_vpc" ] || { echo "ec2-devices: RDS instance $DB was made in $db_vpc, subnet $SUBNET is in $sub_vpc; set SUBNET to one of $db_vpc" >&2; exit 1; }
  else
    aws rds wait db-instance-available --db-instance-identifier $DB
  fi
  aws iam put-role-policy --role-name $ROLE --policy-name dbparam --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{\"Effect\": \"Allow\", \"Action\": \"ssm:GetParameter\",
      \"Resource\": \"arn:aws:ssm:$REGION:$account:parameter$DB_PARAM\"}]}"
fi

# What's made for this run only goes on exit.
work=$(mktemp -d); ids=""
finish() {
  rm -rf "$work"
  if [ -n "$ids" ]; then echo "terminating $ids"; aws ec2 terminate-instances --instance-ids $ids >/dev/null; fi
}
trap finish EXIT

echo "building the core and devicebench (linux/$goarch)"
(cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=$goarch go build -trimpath -ldflags="-s -w" -o "$work/patchlog" ./cmd/patchlog \
  && CGO_ENABLED=0 GOOS=linux GOARCH=$goarch go build -trimpath -ldflags="-s -w" -o "$work/devicebench" ./cmd/devicebench)
ssh-keygen -q -t ed25519 -N '' -C $NAME -f "$work/key"

# Every instance: limits for many connections, and scripts the run calls
# through SSM. server.sh starts the core and samples its CPU, memory and
# open files every 5 seconds; loadgen.sh starts devicebench with its
# arguments. Both detach, so SSM's command returns.
case $BACKEND in
postgres) dbenv="PATCHLOG_DB=\$(aws ssm get-parameter --region $REGION --name $DB_PARAM --with-decryption --query Parameter.Value --output text); export PATCHLOG_DB" ;;
sqlite) dbenv="export PATCHLOG_DB=/opt/bench/bench.db" ;;
esac
cat >"$work/userdata" <<EOF
#!/bin/bash
shutdown -h +$life_min
set -eux
cat >/etc/sysctl.d/90-devices.conf <<'SYSCTL'
fs.nr_open = 2097152
fs.file-max = 4194304
net.ipv4.ip_local_port_range = 1024 65535
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_tw_reuse = 1
SYSCTL
sysctl --system
mkdir -p /opt/bench && cd /opt/bench
cat >server.sh <<'SH'
#!/bin/bash
set -eu
cd /opt/bench
install -m 755 /tmp/patchlog patchlog
ulimit -n 1048576
$dbenv
setsid nohup ./patchlog serve --dev --addr :8080 --playground=false \\
  --max-rate-per-namespace 1e9,1e9 --max-rate-per-resource 1e9,1e9 --max-rate-per-principal 1e9,1e9 \\
  >server.log 2>&1 </dev/null &
pid=\$!
for _ in \$(seq 1 120); do curl -sf -o /dev/null http://127.0.0.1:8080/_health && break; kill -0 \$pid || { tail -20 server.log; exit 1; }; sleep 1; done
curl -sf -o /dev/null http://127.0.0.1:8080/_health || { tail -20 server.log; exit 1; }
page=\$(getconf PAGESIZE)
setsid nohup bash -c "echo '# clk_tck \$(getconf CLK_TCK)'; while kill -0 \$pid 2>/dev/null; do
  echo \"\\\$(date +%s) \\\$(awk -v p=\$page '{print \\\$14+\\\$15, \\\$24*p/1024}' /proc/\$pid/stat) \\\$(ls /proc/\$pid/fd | wc -l)\"; sleep 5; done" \\
  >server.samples 2>/dev/null </dev/null &
echo "core \$pid up"
SH
cat >loadgen.sh <<'SH'
#!/bin/bash
set -eu
cd /opt/bench
install -m 755 /tmp/devicebench devicebench
ulimit -n 1048576
if [ "\$1" = setup ]; then shift; exec ./devicebench --setup "\$@"; fi
setsid nohup ./devicebench "\$@" >loadgen.log 2>&1 </dev/null &
echo "devicebench \$! started"
SH
chmod +x server.sh loadgen.sh
touch ready
EOF

# launch ROLE-NAME COUNT TYPE: the instance ids, one line. An instance profile
# is usable a few seconds after it's made.
launch() {
  local out i
  for i in $(seq 1 12); do
    if out=$(aws ec2 run-instances --image-id "$ami" --instance-type "$3" --count "$2" \
        --iam-instance-profile Name=$ROLE \
        --network-interfaces "DeviceIndex=0,SubnetId=$SUBNET,AssociatePublicIpAddress=true" \
        --instance-initiated-shutdown-behavior terminate \
        --metadata-options HttpTokens=required \
        --user-data "file://$work/userdata" \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME-$1}]" \
        --query 'Instances[].InstanceId' --output text 2>"$work/launch.err"); then
      echo "$out"; return
    fi
    grep -q 'Invalid IAM Instance Profile\|iamInstanceProfile' "$work/launch.err" && [ "$i" -lt 12 ] || { cat "$work/launch.err" >&2; return 1; }
    sleep 5
  done
}
launched=$(launch server "$SERVERS" "$SERVER_TYPE")
read -r -a server_ids <<<"$launched"
ids="${server_ids[*]}"
launched=$(launch loadgen "$LOADGENS" "$LOADGEN_TYPE")
read -r -a loadgen_ids <<<"$launched"
ids="$ids ${loadgen_ids[*]}"
[ ${#server_ids[@]} = "$SERVERS" ] && [ ${#loadgen_ids[@]} = "$LOADGENS" ] || { echo "ec2-devices: launched $ids" >&2; exit 1; }
echo "servers ${server_ids[*]}, load generators ${loadgen_ids[*]} starting"
aws ec2 wait instance-running --instance-ids $ids
server_ips=()
for id in "${server_ids[@]}"; do
  server_ips+=("$(aws ec2 describe-instances --instance-ids "$id" --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text)")
done

# Reachable once their SSM agents check in.
for id in $ids; do
  for i in $(seq 1 60); do
    [ "$(aws ssm describe-instance-information --filters "Key=InstanceIds,Values=$id" \
      --query 'length(InstanceInformationList)' --output text)" = 1 ] && break
    [ "$i" -lt 60 ] || { echo "ec2-devices: $id never checked in with SSM" >&2; exit 1; }
    sleep 5
  done
done

# scp_to ID ARGS…: scp through an SSM session, the key let in for 60 seconds;
# sshd may still be starting.
scp_to() {
  local id=$1 i; shift
  for i in $(seq 1 6); do
    aws ec2-instance-connect send-ssh-public-key --instance-id "$id" --instance-os-user ec2-user \
      --ssh-public-key "file://$work/key.pub" >/dev/null
    if scp -q -i "$work/key" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR -o ConnectTimeout=20 \
        -o ProxyCommand="aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p" \
        "$@"; then
      return
    fi
    [ "$i" -lt 6 ] || { echo "ec2-devices: scp with $id failed" >&2; return 1; }
    sleep 10
  done
}
# waitall: waits for the background jobs, and fails if one did.
waitall() {
  local pid ok=0
  for pid in $(jobs -p); do wait "$pid" || ok=1; done
  return $ok
}
echo "copying the binaries"
for id in "${server_ids[@]}"; do scp_to "$id" "$work/patchlog" "ec2-user@$id:/tmp/patchlog" & done
for id in "${loadgen_ids[@]}"; do scp_to "$id" "$work/devicebench" "ec2-user@$id:/tmp/devicebench" & done
waitall

# ssm ID TIMEOUT COMMAND: runs COMMAND (no double quotes or backslashes) as
# root once the instance's user data is done, prints its output, and fails
# as it does.
ssm() {
  local id=$1 timeout=$2 cmd status
  cmd=$(aws ssm send-command --instance-ids "$id" --document-name AWS-RunShellScript \
    --parameters "{\"commands\": [\"for i in \$(seq 1 120); do [ -f /opt/bench/ready ] && break; sleep 2; done; $3\"], \"executionTimeout\": [\"$timeout\"]}" \
    --query Command.CommandId --output text)
  while :; do
    sleep 3
    status=$(aws ssm get-command-invocation --command-id "$cmd" --instance-id "$id" --query Status --output text 2>/dev/null || echo Pending)
    case $status in Pending|InProgress|Delayed) ;; *) break ;; esac
  done
  aws ssm get-command-invocation --command-id "$cmd" --instance-id "$id" --query StandardOutputContent --output text
  if [ "$status" != Success ]; then
    aws ssm get-command-invocation --command-id "$cmd" --instance-id "$id" --query StandardErrorContent --output text >&2
    return 1
  fi
}

# The first core makes the schema; the others start once it has.
echo "starting the core"
ssm "${server_ids[0]}" 300 /opt/bench/server.sh
# Not seq: on macOS, seq 1 0 counts down.
i=1; while [ "$i" -lt "$SERVERS" ]; do ssm "${server_ids[$i]}" 300 /opt/bench/server.sh & i=$(( i + 1 )); done
waitall
urls=$(printf 'http://%s:8080,' "${server_ips[@]}"); urls=${urls%,}
write_url=http://${server_ips[0]}:8080

echo "making $(( LOADGENS * DEVICES )) devices' resources"
ssm "${loadgen_ids[0]}" 1800 "/opt/bench/loadgen.sh setup --write-url $write_url --devices $(( LOADGENS * DEVICES ))"

# The start, a minute away by the load generators' clock, not this machine's.
start=$(( $(ssm "${loadgen_ids[0]}" 60 "date +%s") + 60 ))
for i in "${!loadgen_ids[@]}"; do
  bg=0; [ "$i" -gt 0 ] || bg=$BG
  ssm "${loadgen_ids[$i]}" 120 "/opt/bench/loadgen.sh --url $urls --write-url $write_url --first $(( i * DEVICES )) --devices $DEVICES --step $STEP --step-time ${STEP_SECS}s --settle ${SETTLE}s --start-at $start --completions $COMPLETIONS --bg $bg --out /opt/bench/steps.jsonl --label loadgen-$i" &
done
waitall
echo "run starts at $(date -d @$start +%T 2>/dev/null || date -r $start +%T), $steps steps; progress from the first load generator:"
for s in $(seq 1 "$steps"); do
  wait_s=$(( start + s * (STEP_SECS + SETTLE) - $(date +%s) + 5 ))
  [ "$wait_s" -le 0 ] || sleep "$wait_s"
  ssm "${loadgen_ids[0]}" 60 "tail -1 /opt/bench/loadgen.log" || true
done

mkdir -p "$OUT"
echo "collecting results into $OUT"
for i in "${!loadgen_ids[@]}"; do
  scp_to "${loadgen_ids[$i]}" "ec2-user@${loadgen_ids[$i]}:/opt/bench/steps.jsonl" "$OUT/loadgen-$i.jsonl" &
  scp_to "${loadgen_ids[$i]}" "ec2-user@${loadgen_ids[$i]}:/opt/bench/loadgen.log" "$OUT/loadgen-$i.log" &
done
for i in "${!server_ids[@]}"; do
  scp_to "${server_ids[$i]}" "ec2-user@${server_ids[$i]}:/opt/bench/server.samples" "$OUT/server-$i.samples" &
  scp_to "${server_ids[$i]}" "ec2-user@${server_ids[$i]}:/opt/bench/server.log" "$OUT/server-$i.log" &
done
waitall || echo "ec2-devices: some results weren't collected" >&2
if [ "$BACKEND" = postgres ]; then
  echo "waiting 2 minutes for RDS's CloudWatch metrics"
  sleep 120
  aws cloudwatch get-metric-statistics --namespace AWS/RDS --metric-name CPUUtilization \
    --dimensions Name=DBInstanceIdentifier,Value=$DB --statistics Average --period 60 \
    --start-time "$(date -u -d @$start +%FT%TZ 2>/dev/null || date -u -r $start +%FT%TZ)" \
    --end-time "$(date -u +%FT%TZ)" >"$OUT/rds-cpu.json"
fi
cat >"$OUT/settings.txt" <<EOF
rev $rev, backend $BACKEND, $SERVERS × $SERVER_TYPE, $LOADGENS × $LOADGEN_TYPE, DB $DB_CLASS
DEVICES $DEVICES STEP $STEP STEP_SECS $STEP_SECS SETTLE $SETTLE COMPLETIONS $COMPLETIONS BG $BG
EOF
python3 "$root/deploy/devices-summary.py" "$OUT" | tee "$OUT/summary.txt"
