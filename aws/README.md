# GrantAi collector on AWS

One CloudFormation stack, about 20 minutes: VPC, collector EC2 instance (instance profile, no keys
on disk), private RDS for PostgreSQL, Secrets Manager secrets (bootstrap token, install id, export
signing key, licence, model key), S3 bucket with compliance-mode Object Lock for the cold tier, an
Elastic IP, optional Route 53 record and Let's Encrypt certificate. Nothing leaves the account
except the licence check. The same first-boot script as Azure runs from EC2 user data with
`CLOUD=aws`; the Azure path is unchanged.

```bash
aws cloudformation create-stack --stack-name grantai --template-body file://template.yaml \
  --capabilities CAPABILITY_IAM \
  --parameters ParameterKey=AllowedClientCidr,ParameterValue=203.0.113.0/24 \
               ParameterKey=LicenseJwt,ParameterValue="$(cat license.jwt)" \
               ParameterKey=AgentCoreRegion,ParameterValue=us-east-1
```

Outputs: console URL, health URL, the Secrets Manager secret holding the token
(`aws secretsmanager get-secret-value --secret-id grantai/http-token --query SecretString --output text`),
database endpoint, cold bucket. Requirements: permission to create IAM roles (CAPABILITY_IAM) and
2 free vCPUs in the region.

## Capture: Bedrock AgentCore

AgentCore delivers each agent's OpenTelemetry spans (prompts, tool calls, completions) to one
CloudWatch log group per agent, in the `spans` stream. With `AgentCoreRegion` set, the collector's
AgentCore tap reads those spans from a cursor through the instance role and seals one record per
agent turn, model call and tool execution under the caller `agentcore-tap`, source
`agentcore/<agent>/<session>/<span>`: the system prompt, the user message, the model's answer, the
tool call with its arguments and result, token usage, model and trace ids. Agents need no
configuration beyond what AgentCore observability already requires: CloudWatch Transaction Search
on in the account and `aws-opentelemetry-distro` in the agent's requirements (the starter toolkit
adds both). Proven 2026-10-09 with a Strands agent on Nova Lite deployed by `agentcore deploy`:
two fresh collectors each sealed every span within one 30-second sweep, with no agent change.

## Images

`AmiId` empty uses the base Ubuntu 22.04 AMI and installs the release from `PackageUrl` (verified
against `PackageSha256`); this is what the Launch Stack button does and it adds about four minutes
to first boot. A prebuilt collector AMI exists in us-east-1 (`ami-03d551484f59a8c26`, Ubuntu 22.04,
release 2.0.1 from the CI package, built with the Packer configuration below). It is shared per
account on request (`aws ec2 modify-image-attribute --image-id ... --launch-permission
"Add=[{UserId=<account>}]"`); the publishing account blocks public AMIs by default, so making it
public is an owner decision (`aws ec2 disable-image-block-public-access`, then `Add=[{Group=all}]`).
To build it:

```bash
packer build -var cloud=aws -var aws_region=us-east-1 -var version=2.0.1 -var os=ubuntu-22.04 \
  -var package_url=... -var package_sha256=... Deploy/image
```

## Differences from Azure worth knowing

- The cold bucket name includes the stack id, because an Object Lock bucket can never be emptied and
  a redeploy must not collide with it. Objects are retained in compliance mode for `ColdRetentionDays`;
  the collector's role has no delete permission at all.
- Let's Encrypt needs a real hostname: set `PublicHostname` (and `HostedZoneId` for the Route 53
  record). EC2's own public DNS names are not eligible.
- `LlmProvider` defaults to `openai`: point `LlmEndpoint` at an OpenAI-compatible endpoint, or use
  `anthropic` with a key. A Bedrock-native provider is a follow-up.
