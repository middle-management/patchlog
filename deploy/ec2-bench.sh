#!/usr/bin/env bash
# Runs deploy/bench.sh against a real DynamoDB table from an EC2 instance in
# the table's region: the server and the bench on one machine of their own,
# not CloudShell's shared one. Prints the bench's numbers and deploy/spans.py's
# summary of where the requests spent their time, then terminates the
# instance.
#
#   ./deploy/ec2-bench.sh [-y] [writes/s] [seconds]   (default 100 20)
#   ./deploy/ec2-bench.sh cleanup                      the role, profile, bucket
#
# The arguments, READS, LOGS and NAMESPACES are bench.sh's. The instance runs
# this checkout's bench.sh and spans.py, oha's release OHA (default v1.14.0),
# and the server built from this checkout, uncommitted changes included
# (Go needed here), or the release VERSION.
#
# Settings (environment):
#   REGION   the table's region (default: aws configure's)
#   TABLE    the table (default patchlog); made, on-demand, if it's missing
#   VERSION  a release to run instead of building, e.g. v0.24.0-ddb.3
#   TYPE     the instance type (default c7g.large, arm64)
#   SUBNET   a subnet with a route out (default: the default VPC's)
#
# What it makes, after asking (-y doesn't ask):
#   - IAM role and instance profile patchlog-bench, kept for the next run
#     (`cleanup` deletes them): SSM's managed policy (no SSH, no open
#     ports) and DynamoDB on this table and its indexes only.
#   - The table, if it's missing. Never deleted: it holds what you wrote.
#   - S3 bucket patchlog-bench-<account>-<region> for a built server, kept
#     for the next run (`cleanup` deletes it); the binary is deleted on
#     exit, and the instance downloads it by a URL presigned for an hour.
#   - One instance, terminated on exit, and by itself after 90 minutes
#     should this script die first.
#
# Needs the AWS CLI v2 and credentials allowed to do the above.
set -euo pipefail

REGION=${REGION:-${AWS_REGION:-$(aws configure get region || true)}}
TABLE=${TABLE:-patchlog}
VERSION=${VERSION:-}
TYPE=${TYPE:-c7g.large}
OHA=${OHA:-v1.14.0}
READS=${READS:-}; LOGS=${LOGS:-}; NAMESPACES=${NAMESPACES:-}
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
  bucket=patchlog-bench-$(aws sts get-caller-identity --query Account --output text)-$REGION
  aws s3 rb --force "s3://$bucket" >/dev/null 2>&1 || true
  echo "ec2-bench: deleted role and instance profile $ROLE and bucket $bucket (if they existed)"
  exit 0
fi

YES=""
[ "${1:-}" = -y ] && { YES=1; shift; }
RATE=${1:-100}; SECS=${2:-20}
case "$RATE$SECS$READS$LOGS$NAMESPACES" in *[!0-9]*) echo "usage: $0 [-y] [writes/s] [seconds] | cleanup" >&2; exit 2 ;; esac

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
root=$(cd "$(dirname "$0")/.." && pwd)
bucket=patchlog-bench-$account-$REGION
if [ -n "$VERSION" ]; then
  server="release $VERSION"
else
  command -v go >/dev/null || { echo "ec2-bench: building the server needs Go; or set VERSION to a release" >&2; exit 1; }
  rev=$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)
  [ -z "$(git -C "$root" status --porcelain -- cmd internal go.mod go.sum 2>/dev/null)" ] || rev=$rev+changes
  have_bucket=$(aws s3api head-bucket --bucket "$bucket" >/dev/null 2>&1 && echo 1 || true)
  server="built from this checkout ($rev, linux/$goarch), through s3://$bucket$([ -n "$have_bucket" ] || echo ', to make')"
fi

echo "account $account, region $REGION"
echo "  table $TABLE: $([ -n "$table_arn" ] && echo exists || echo 'to make (on-demand)')"
echo "  role $ROLE: $([ -n "$have_role" ] && echo 'exists (its DynamoDB policy is set to this table)' || echo 'to make')"
echo "  instance: $TYPE ($arch, $ami) in $SUBNET, terminated on exit"
echo "  server: $server"
echo "  run: bench $RATE writes/s for ${SECS}s${READS:+, reads $READS/s}${LOGS:+, logs $LOGS/s}${NAMESPACES:+, over $NAMESPACES namespaces}"
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

# What's made for this run only goes on exit.
work=$(mktemp -d); id=""; object=""
finish() {
  rm -rf "$work"
  if [ -n "$id" ]; then echo "terminating $id"; aws ec2 terminate-instances --instance-ids "$id" >/dev/null; fi
  if [ -n "$object" ]; then aws s3 rm --quiet "$object" || true; fi
}
trap finish EXIT
userdata=$work/userdata

# The server: a release, or built here and handed over through S3.
if [ -n "$VERSION" ]; then
  fetch="curl -fsSL https://github.com/$REPO/releases/download/$VERSION/patchlog_${VERSION}_linux_$goarch.tar.gz | tar xz --strip-components=1"
else
  echo "building the server (linux/$goarch)"
  (cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=$goarch go build -trimpath -tags grpcnotrace \
    -ldflags="-s -w -X main.version=bench-$rev" -o "$work/patchlog" ./cmd/patchlog)
  if [ -z "$have_bucket" ]; then
    if [ "$REGION" = us-east-1 ]; then
      aws s3api create-bucket --bucket "$bucket" >/dev/null
    else
      aws s3api create-bucket --bucket "$bucket" --create-bucket-configuration "LocationConstraint=$REGION" >/dev/null
    fi
    echo "made bucket $bucket"
  fi
  object=s3://$bucket/patchlog-$(date +%s)-$RANDOM
  aws s3 cp --quiet "$work/patchlog" "$object"
  fetch="curl -fsSL -o patchlog '$(aws s3 presign "$object" --expires-in 3600)'"
fi

# The instance prepares itself (the server, oha, this checkout's bench.sh
# and spans.py) and powers off after 90 minutes whatever happens: shutdown
# terminates it.
scripts=$(tar -C "$(dirname "$0")" -cz bench.sh spans.py | base64 | tr -d '\n')
cat >"$userdata" <<EOF
#!/bin/bash
shutdown -h +90
set -eux
mkdir -p /opt/bench && cd /opt/bench
$fetch
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
${READS:+READS=$READS }${LOGS:+LOGS=$LOGS }${NAMESPACES:+NAMESPACES=$NAMESPACES }./bench.sh "\$1" "\$2" || echo "bench failed: \$?"
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
