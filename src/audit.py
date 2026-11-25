"""
Weekly cost and security report.

Cost checks
- EBS volumes not attached to anything
- Elastic IPs not associated with anything
- EC2 instances missing required tags

Security checks
- Security groups that allow SSH (22) or RDP (3389) from anywhere
- S3 buckets without all four public access blocks switched on

The function only reads. It reports what it finds by email through SNS.
Triggered by EventBridge once a week.
"""
import os

import boto3
from botocore.exceptions import ClientError

ec2 = boto3.client("ec2")
s3 = boto3.client("s3")
sns = boto3.client("sns")

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}


def unattached_volumes():
    found = []
    pages = ec2.get_paginator("describe_volumes").paginate(
        Filters=[{"Name": "status", "Values": ["available"]}])
    for page in pages:
        for vol in page["Volumes"]:
            found.append(f"{vol['VolumeId']} ({vol['Size']} GiB)")
    return found


def unused_elastic_ips():
    return [addr.get("PublicIp", addr.get("AllocationId", "unknown"))
            for addr in ec2.describe_addresses()["Addresses"]
            if not addr.get("AssociationId") and not addr.get("InstanceId")]


def untagged_instances(required):
    found = []
    pages = ec2.get_paginator("describe_instances").paginate(
        Filters=[{"Name": "instance-state-name", "Values": ["pending", "running", "stopped"]}])
    for page in pages:
        for reservation in page["Reservations"]:
            for inst in reservation["Instances"]:
                keys = {tag["Key"] for tag in inst.get("Tags", [])}
                missing = [tag for tag in required if tag not in keys]
                if missing:
                    found.append(f"{inst['InstanceId']} is missing {', '.join(missing)}")
    return found


def open_admin_ports():
    found = []
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for group in page["SecurityGroups"]:
            for rule in group["IpPermissions"]:
                world = any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", [])) or \
                        any(r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", []))
                if not world:
                    continue
                low, high = rule.get("FromPort"), rule.get("ToPort")
                for port, name in ADMIN_PORTS.items():
                    all_traffic = rule.get("IpProtocol") == "-1"
                    in_range = low is not None and high is not None and low <= port <= high
                    if all_traffic or in_range:
                        found.append(f"{group['GroupId']} ({group['GroupName']}) allows {name} from anywhere")
    return found


def buckets_without_public_block():
    found = []
    for bucket in s3.list_buckets()["Buckets"]:
        name = bucket["Name"]
        try:
            config = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all(config.get(key) for key in ("BlockPublicAcls", "IgnorePublicAcls",
                                                   "BlockPublicPolicy", "RestrictPublicBuckets")):
                found.append(f"{name} has public access only partly blocked")
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                found.append(f"{name} has no public access block")
            else:
                print(f"Could not check {name}: {exc}")
    return found


def build_report(sections):
    total = sum(len(items) for items in sections.values())
    lines = [f"AWS guardrail report: {total} finding(s)", ""]
    for title, items in sections.items():
        lines.append(f"{title}: {len(items)}")
        lines.extend(f"  - {item}" for item in items)
        lines.append("")
    return total, "\n".join(lines)


def handler(event, context):
    required = [t.strip() for t in os.environ.get("REQUIRED_TAGS", "").split(",") if t.strip()]
    sections = {
        "Unattached EBS volumes (paying for storage nobody uses)": unattached_volumes(),
        "Unused Elastic IPs (charged while idle)": unused_elastic_ips(),
        "EC2 instances missing required tags": untagged_instances(required),
        "Security groups with admin ports open to the internet": open_admin_ports(),
        "S3 buckets without a full public access block": buckets_without_public_block(),
    }
    total, report = build_report(sections)
    print(report)
    topic = os.environ.get("TOPIC_ARN")
    if topic:
        sns.publish(TopicArn=topic, Subject=f"AWS guardrail report: {total} finding(s)", Message=report)
    return {"findings": total}
