#!/usr/bin/env bash
# Runs deploy/bench.sh against a real DynamoDB table from an EC2 instance in
# the table's region: the server and the bench on one machine of their own,
# not CloudShell's shared one. Prints the bench's numbers and deploy/spans.py's
# summary of where the requests spent their time, then terminates the
# instance.
#
#   ./deploy/ec2-bench.sh [-y] [writes/s] [seconds]   (default 100 20)
#   ./deploy/ec2-bench.sh cleanup                      the IAM role, profile
#
# The arguments, READS and LOGS are bench.sh's. The instance runs this
# checkout's bench.sh and spans.py, and oha's release OHA (default v1.14.0).
#
# Settings (environment):
#   REGION   the table's region (default: aws configure's)
#   TABLE    the table (default patchlog); made, on-demand, if it's missing
#   VERSION  the release to run (default v0.24.0-ddb.3)
#   TYPE     the instance type (default c7g.large, arm64)
#   SUBNET   a subnet with a route out (default: the default VPC's)
#
# What it makes, after asking (-y doesn't ask):
#   - IAM role and instance profile patchlog-bench, kept for the next run
#     (`cleanup` deletes them): SSM's managed policy (no SSH, no open
#     ports) and DynamoDB on this table and its indexes only.
#   - The table, if it's missing. Never deleted: it holds what you wrote.
#   - One instance, terminated on exit, and by itself after 90 minutes
#     should this script die first.
#
# Needs the AWS CLI v2 and credentials allowed to do the above.
set -euo pipefail

REGION=${REGION:-${AWS_REGION:-$(aws configure get region || true)}}
TABLE=${TABLE:-patchlog}
VERSION=${VERSION:-v0.24.0-ddb.3}
TYPE=${TYPE:-c7g.large}
OHA=${OHA:-v1.14.0}
READS=${READS:-}; LOGS=${LOGS:-}
ROLE=patchlog-bench
REPO=middle-management/patchlog
[ -n "$REGION" ] || { echo "ec2-bench: set REGION (or aws configure set region …)" >&2; exit 1; }
export AWS_REGION=$REGION AWS_PAGER=""

if [ "${1:-}" = cleanup ]; then
  aws iam remove-role-from-instance-profile --instance-profile-name $ROLE --role-name $ROLE 2>/dev/null || true
  aws iam delete-instance-profile --instance-profile-name $ROLE 2>/dev/null || true
  aws iam detach-role-policy --role-name $ROLE --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore 2>/dev/null || true
  aws iam delete-role-policy --role-name $ROLE --policy-name dynamodb 2>/dev/null || true
  aws iam delete-role --role-name $ROLE 2>/dev/null || true
  echo "ec2-bench: deleted role and instance profile $ROLE (if they existed)"
  exit 0
fi

YES=""
[ "${1:-}" = -y ] && { YES=1; shift; }
RATE=${1:-100}; SECS=${2:-20}
case "$RATE$SECS$READS$LOGS" in *[!0-9]*) echo "usage: $0 [-y] [writes/s] [seconds] | cleanup" >&2; exit 2 ;; esac

# What's there, and what would be made.
account=$(aws sts get-caller-identity --query Account --output text)
table_arn=$(aws dynamodb describe-table --table-name "$TABLE" --query Table.TableArn --output text 2>/dev/null || true)
have_role=$(aws iam get-role --role-name $ROLE --query Role.Arn --output text 2>/dev/null || true)
arch=$(aws ec2 describe-instance-types --instance-types "$TYPE" \
  --query 'InstanceTypes[0].ProcessorInfo.SupportedArchitectures[0]' --output text)
case $arch in arm64) goarch=arm64 ;; x86_64) goarch=amd64 ;; *) echo "ec2-bench: $TYPE: architecture $arch" >&2; exit 1 ;; esac
if [ -z "${SUBNET:-}" ]; then
  SUBNET=$(aws ec2 describe-subnets --filters Name=default-for-az,Values=true \
    --query 'Subnets[0].SubnetId' --output text)
  [ "$SUBNET" != None ] || { echo "ec2-bench: no default VPC here; set SUBNET to one with a route out" >&2; exit 1; }
fi
ami=$(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-$arch \
  --query Parameter.Value --output text)

echo "account $account, region $REGION"
echo "  table $TABLE: $([ -n "$table_arn" ] && echo exists || echo 'to make (on-demand)')"
echo "  role $ROLE: $([ -n "$have_role" ] && echo 'exists (its DynamoDB policy is set to this table)' || echo 'to make')"
echo "  instance: $TYPE ($arch, $ami) in $SUBNET, terminated on exit"
echo "  run: patchlog $VERSION, bench $RATE writes/s for ${SECS}s${READS:+, reads $READS/s}${LOGS:+, logs $LOGS/s}"
if [ -z "$YES" ]; then
  read -r -p "Go ahead? [y/N] " ok
  [ "$ok" = y ] || [ "$ok" = Y ] || exit 1
fi

# The table, as docs/DYNAMODB.md §3 has it.
if [ -z "$table_arn" ]; then
  aws dynamodb create-table --table-name "$TABLE" --billing-mode PAY_PER_REQUEST \
    --attribute-definitions AttributeName=PK,AttributeType=S AttributeName=SK,AttributeType=S \
      AttributeName=G1PK,AttributeType=S \
    --key-schema AttributeName=PK,KeyType=HASH AttributeName=SK,KeyType=RANGE \
    --global-secondary-indexes 'IndexName=GSI1,KeySchema=[{AttributeName=G1PK,KeyType=HASH}],Projection={ProjectionType=ALL}' \
    >/dev/null
  aws dynamodb wait table-exists --table-name "$TABLE"
  table_arn=$(aws dynamodb describe-table --table-name "$TABLE" --query Table.TableArn --output text)
  echo "made table $TABLE"
fi

# The role: SSM to reach the instance, DynamoDB on the table.
if [ -z "$have_role" ]; then
  aws iam create-role --role-name $ROLE --description "patchlog deploy/ec2-bench.sh" \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
  aws iam attach-role-policy --role-name $ROLE --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
  aws iam create-instance-profile --instance-profile-name $ROLE >/dev/null
  aws iam add-role-to-instance-profile --instance-profile-name $ROLE --role-name $ROLE
  echo "made role and instance profile $ROLE"
fi
aws iam put-role-policy --role-name $ROLE --policy-name dynamodb --policy-document "{
  \"Version\": \"2012-10-17\",
  \"Statement\": [{\"Effect\": \"Allow\", \"Action\": [
    \"dynamodb:DescribeTable\", \"dynamodb:GetItem\", \"dynamodb:BatchGetItem\", \"dynamodb:Query\",
    \"dynamodb:Scan\", \"dynamodb:PutItem\", \"dynamodb:UpdateItem\", \"dynamodb:DeleteItem\",
    \"dynamodb:BatchWriteItem\", \"dynamodb:ConditionCheckItem\"],
    \"Resource\": [\"$table_arn\", \"$table_arn/index/*\"]}]}"

# The instance prepares itself (the release, oha, this checkout's bench.sh
# and spans.py) and powers off after 90 minutes whatever happens: shutdown
# terminates it.
userdata=$(mktemp)
trap 'rm -f "$userdata"' EXIT
scripts=$(tar -C "$(dirname "$0")" -cz bench.sh spans.py | base64 | tr -d '\n')
cat >"$userdata" <<EOF
#!/bin/bash
shutdown -h +90
set -eux
mkdir -p /opt/bench && cd /opt/bench
curl -fsSL https://github.com/$REPO/releases/download/$VERSION/patchlog_${VERSION}_linux_$goarch.tar.gz | tar xz --strip-components=1
curl -fsSL -o oha https://github.com/hatoo/oha/releases/download/$OHA/oha-linux-$goarch
echo $scripts | base64 -d | tar xz
chmod +x patchlog oha bench.sh spans.py
cat >run.sh <<'RUN'
#!/bin/bash
# run.sh RATE SECS: the server with its spans on stderr, the bench, the summary.
set -eu
cd /opt/bench
export PATH=/opt/bench:\$PATH
OTEL_TRACES_EXPORTER=console OTEL_METRICS_EXPORTER=none \\
  ./patchlog serve -dev -addr 127.0.0.1:8080 -max-rate-per-namespace 100000,1000000 \\
    -db 'dynamodb://$TABLE?region=$REGION' 2>spans.jsonl &
server=\$!
for _ in \$(seq 1 60); do curl -s -o /dev/null http://127.0.0.1:8080/ && break; kill -0 \$server || { grep -v '^{' spans.jsonl; exit 1; }; sleep 1; done
${READS:+READS=$READS }${LOGS:+LOGS=$LOGS }./bench.sh "\$1" "\$2" || echo "bench failed: \$?"
kill \$server; wait \$server || true
echo; ./spans.py spans.jsonl
RUN
chmod +x run.sh
touch ready
EOF

# An instance profile is usable a few seconds after it's made.
for i in $(seq 1 12); do
  if id=$(aws ec2 run-instances --image-id "$ami" --instance-type "$TYPE" \
      --iam-instance-profile Name=$ROLE \
      --network-interfaces "DeviceIndex=0,SubnetId=$SUBNET,AssociatePublicIpAddress=true" \
      --instance-initiated-shutdown-behavior terminate \
      --metadata-options HttpTokens=required \
      --user-data "file://$userdata" \
      --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=patchlog-bench}]' \
      --query 'Instances[0].InstanceId' --output text 2>"$userdata.err"); then
    break
  fi
  grep -q 'Invalid IAM Instance Profile\|iamInstanceProfile' "$userdata.err" && [ "$i" -lt 12 ] || { cat "$userdata.err" >&2; exit 1; }
  sleep 5
done
rm -f "$userdata.err"
trap 'rm -f "$userdata"; echo "terminating $id"; aws ec2 terminate-instances --instance-ids "$id" >/dev/null' EXIT
echo "instance $id starting"

# Reachable once its SSM agent checks in.
for _ in $(seq 1 60); do
  [ "$(aws ssm describe-instance-information --filters "Key=InstanceIds,Values=$id" \
    --query 'length(InstanceInformationList)' --output text)" = 1 ] && break
  sleep 5
done
cmd=$(aws ssm send-command --instance-ids "$id" --document-name AWS-RunShellScript \
  --parameters "{\"commands\": [\"for i in \$(seq 1 120); do [ -f /opt/bench/ready ] && break; sleep 2; done; /opt/bench/run.sh $RATE $SECS\"], \"executionTimeout\": [\"3600\"]}" \
  --query Command.CommandId --output text)
echo "running the bench ($cmd)"
while :; do
  sleep 5
  status=$(aws ssm get-command-invocation --command-id "$cmd" --instance-id "$id" \
    --query Status --output text 2>/dev/null || echo Pending)
  case $status in Pending|InProgress|Delayed) ;; *) break ;; esac
done
aws ssm get-command-invocation --command-id "$cmd" --instance-id "$id" \
  --query StandardOutputContent --output text
if [ "$status" != Success ]; then
  echo "ec2-bench: the run ended $status:" >&2
  aws ssm get-command-invocation --command-id "$cmd" --instance-id "$id" \
    --query StandardErrorContent --output text >&2
  exit 1
fi
