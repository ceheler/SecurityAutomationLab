# Cloud Security Detection Pipeline

## Objective

Build an end-to-end cloud security detection pipeline that collects AWS CloudTrail and VPC Flow Log telemetry, normalizes the raw events into a common SecurityEvent format, and analyzes the normalized events with SecurityEventAnalyzer.

The pipeline will be validated using known security-relevant activity generated in a controlled AWS lab. A successful implementation will demonstrate traceability from the original AWS activity through telemetry collection and normalization to a resulting security finding.

## Architecture

The capstone uses a layered architecture that separates infrastructure, telemetry normalization, and detection logic.

AWS infrastructure is deployed through the existing Terraform Security Lab. CloudTrail and VPC Flow Logs provide control-plane and network telemetry from the lab environment.

Raw AWS telemetry is processed by normalization scripts in SecurityAutomationLab. These normalizers convert source-specific AWS records into the common SecurityEvent format already used by the detection pipeline.

Normalized events are then provided to SecurityEventAnalyzer, which applies detection rules and produces SecurityFinding results.

The detection engine does not communicate directly with AWS APIs or depend on AWS credentials. AWS-specific collection and parsing remain outside the analyzer so that detection logic can be tested offline and reused with telemetry from multiple sources.

The intended data flow is:

AWS Security Lab
    |
    +-- CloudTrail
    |
    +-- VPC Flow Logs
            |
            v
    Raw AWS Telemetry
            |
            v
    SecurityAutomationLab
    Python Normalizers
            |
            v
    Normalized SecurityEvent JSON
            |
            v
    SecurityEventAnalyzer
            |
            v
    SecurityFinding Results

## Components

### terraform-security-lab

Responsible for provisioning and securing the AWS lab environment used to generate capstone telemetry.

This repository manages the VPC, subnets, routing, EC2 instance, IAM roles, Systems Manager access, VPC Flow Logs, CloudWatch Logs, and KMS resources required by the lab.

### SecurityAutomationLab

Responsible for source-specific telemetry normalization.

This repository will contain the CloudTrail and VPC Flow Log normalizers that convert AWS-native records into the common SecurityEvent JSON format expected by the analyzer.

It remains the boundary between source-specific log formats and the source-independent detection engine.

### SecurityEventAnalyzer

Responsible for detection and correlation.

This repository consumes normalized SecurityEvent records, applies detection rules, and produces SecurityFinding results.

The analyzer should remain unaware of AWS APIs, CloudWatch, CloudTrail storage locations, or AWS credentials.

### cloudtrail-security-monitor

Provides previously validated CloudTrail detections and ground-truth examples for destructive AWS activity.

This project will be used as a reference for known CloudTrail event structures and previously tested actions such as EC2 instance termination and VPC deletion. It is not being replaced or merged into SecurityEventAnalyzer as part of the capstone.

## Telemetry Sources

### AWS CloudTrail

CloudTrail provides control-plane telemetry describing AWS API activity performed in the lab environment.

The capstone will use CloudTrail records to identify security-relevant administrative actions such as EC2 instance termination and VPC deletion.

Relevant CloudTrail fields are expected to include:

- Event timestamp
- Event name
- AWS service
- Source IP address
- User or assumed-role identity
- AWS account and region
- Request or resource identifiers when available

CloudTrail telemetry will be treated as the authoritative source for validating known AWS API actions performed during controlled testing.

### VPC Flow Logs

VPC Flow Logs provide network-flow metadata for traffic traversing the lab VPC.

The capstone will use both accepted and rejected flow records to provide network visibility and to support network-oriented detection scenarios.

Relevant VPC Flow Log fields are expected to include:

- Start and end timestamps
- Source and destination IP addresses
- Source and destination ports
- Protocol
- Packet and byte counts
- ACCEPT or REJECT action
- Network interface or other resource identifiers when available

VPC Flow Logs provide flow metadata rather than packet payloads and are used as a complementary telemetry source to CloudTrail.

### Normalization Boundary

Raw CloudTrail and VPC Flow Log records will not be passed directly into SecurityEventAnalyzer.

Each source will first be converted into the common SecurityEvent schema by a source-specific normalizer in SecurityAutomationLab. Only the normalized representation crosses into the detection layer.

## Detection Scenarios

The capstone will validate three controlled security-relevant scenarios. The purpose is to demonstrate traceability from a known action through AWS telemetry, normalization, and detection rather than to simulate a large number of attacks.

### EC2 Instance Termination

A controlled EC2 instance termination will generate a CloudTrail `TerminateInstances` event.

The CloudTrail normalizer will convert the relevant event data into the common SecurityEvent format, and SecurityEventAnalyzer will identify the destructive EC2 action.

The event is intentionally generated as ground truth. Detection of the action does not imply that the activity is inherently malicious; the purpose is to demonstrate visibility into a high-impact administrative action.

### VPC Deletion

Deletion of the lab VPC during controlled teardown will generate a CloudTrail `DeleteVpc` event.

The event will be normalized and analyzed as a destructive cloud-resource action. This scenario reuses a behavior previously validated by the cloudtrail-security-monitor project while demonstrating that the same telemetry can participate in the common SecurityEvent pipeline.

### Rejected Network Port Scan

A controlled scan will be directed at the lab EC2 instance across multiple TCP destination ports within a short time window.

The EC2 security group will remain closed to inbound management traffic. The lab will not open unnecessary ports solely to generate test telemetry.

Rejected connection attempts should appear in VPC Flow Logs as `REJECT` records. The VPC Flow Log normalizer will map suitable rejected records into normalized network-block events that can be evaluated by the existing port-scan detection logic.

A successful test should demonstrate multiple distinct destination ports from the same source within the detector's configured time window and produce a port-scan SecurityFinding.

## Success Criteria

The capstone will be considered complete when all of the following are demonstrated:

- The Terraform Security Lab deploys successfully with the new security controls.
- CloudTrail and VPC Flow Logs produce usable telemetry from controlled activity in the lab.
- CloudTrail `TerminateInstances` activity can be traced from the original AWS action to a normalized SecurityEvent and then to a SecurityFinding.
- CloudTrail `DeleteVpc` activity can be traced from the original AWS action to a normalized SecurityEvent and then to a SecurityFinding.
- Rejected network scan traffic can be traced from VPC Flow Logs to normalized network-block events and then to the existing port-scan detection logic.
- The AWS normalizers handle malformed or incomplete records without crashing the overall processing workflow.
- SecurityEventAnalyzer continues to operate on normalized events without requiring AWS credentials or direct AWS API access.
- The end-to-end workflow can be repeated using documented commands or lightweight orchestration without relying on undocumented manual steps.
- New capstone code is covered by appropriate tests and passes the repository CI and security checks.
- Documentation explains the architecture, security decisions, detection scenarios, limitations, and how the pipeline was validated.

## Out of Scope

The following items are intentionally excluded from this capstone unless they become necessary to meet an existing success criterion:

- Building a web dashboard or graphical user interface.
- Deploying a SIEM such as Splunk, Elastic, or Wazuh.
- Adding new AWS services such as GuardDuty, Security Hub, WAF, or Route 53 logging.
- Building a live streaming architecture with Lambda, SQS, Kinesis, or EventBridge.
- Implementing automated remediation or response actions.
- Deploying Terraform automatically from GitHub Actions.
- Building a multi-account or multi-region AWS architecture.
- Adding Kubernetes, containers, or unrelated infrastructure solely for portfolio breadth.
- Replacing the existing SecurityEvent schema or rewriting SecurityEventAnalyzer around AWS-native formats.
- Expanding the detector set beyond the scenarios required to prove the end-to-end pipeline.
- Production high availability, scaling, or enterprise deployment concerns.

Future improvements may revisit these areas after the core detection pipeline has been demonstrated and documented.

## Security Boundaries

The capstone maintains explicit boundaries between infrastructure deployment, telemetry processing, and detection logic.

AWS credentials and deployment authority remain outside SecurityEventAnalyzer. Terraform uses the existing authenticated AWS CLI profile and assumes the dedicated Terraform execution role when infrastructure changes are performed locally.

Environment-specific values such as the Terraform execution-role ARN remain in the local `terraform.tfvars` file and are excluded from source control. Terraform state and other sensitive local deployment artifacts are also excluded from the repository.

GitHub Actions CI does not receive AWS deployment credentials and does not execute `terraform plan` or `terraform apply`. CI is limited to static validation, security scanning, testing, and other checks that do not require access to the AWS environment.

AWS-specific telemetry collection and parsing remain within SecurityAutomationLab. CloudTrail and VPC Flow Log formats are translated into the common SecurityEvent schema before data is passed to SecurityEventAnalyzer.

SecurityEventAnalyzer operates only on normalized event data. It does not retrieve telemetry directly from AWS, communicate with AWS APIs, or require AWS credentials.

Detection rules operate on the common SecurityEvent model rather than source-specific AWS structures. This keeps detection logic isolated from telemetry collection and allows equivalent security behaviors from different sources to reuse the same detection logic when appropriate.

Controlled test activity is performed only within the dedicated lab environment. Security-relevant actions are generated intentionally to provide known ground truth for detection validation.

Infrastructure deployment and destructive AWS actions remain explicit operator-controlled activities. The capstone does not automatically remediate findings or perform destructive actions in response to detections.