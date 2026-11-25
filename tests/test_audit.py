import importlib
import os
import sys

import boto3
from moto import mock_aws

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


@mock_aws
def test_finds_each_kind_of_problem():
    os.environ.update(AWS_DEFAULT_REGION="eu-west-2", AWS_ACCESS_KEY_ID="test",
                      AWS_SECRET_ACCESS_KEY="test", REQUIRED_TAGS="Owner,Project")
    os.environ.pop("TOPIC_ARN", None)
    ec2 = boto3.client("ec2")
    s3 = boto3.client("s3")

    ec2.create_volume(AvailabilityZone="eu-west-2a", Size=20)
    ec2.allocate_address(Domain="vpc")
    ami = ec2.describe_images()["Images"][0]["ImageId"]
    ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.micro",
                      TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Owner", "Value": "me"}]}])
    ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.micro",
                      TagSpecifications=[{"ResourceType": "instance", "Tags": [
                          {"Key": "Owner", "Value": "me"}, {"Key": "Project", "Value": "x"}]}])
    sg = ec2.create_security_group(GroupName="open-ssh", Description="test")["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    safe = ec2.create_security_group(GroupName="office-ssh", Description="test")["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=safe, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "203.0.113.10/32"}]}])
    cfg = {"LocationConstraint": "eu-west-2"}
    s3.create_bucket(Bucket="open-bucket", CreateBucketConfiguration=cfg)
    s3.create_bucket(Bucket="locked-bucket", CreateBucketConfiguration=cfg)
    s3.put_public_access_block(Bucket="locked-bucket", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})

    import audit
    importlib.reload(audit)

    assert len(audit.unattached_volumes()) == 1
    assert len(audit.unused_elastic_ips()) == 1
    untagged = audit.untagged_instances(["Owner", "Project"])
    assert len(untagged) == 1 and "missing Project" in untagged[0]
    ports = audit.open_admin_ports()
    assert len(ports) == 1 and "open-ssh" in ports[0] and "SSH" in ports[0]
    assert audit.buckets_without_public_block() == ["open-bucket has no public access block"]
    assert audit.handler({}, None) == {"findings": 5}
