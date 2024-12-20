import logging
import os
import uuid
import json
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.authorization.models import RoleAssignmentCreateParameters
import boto3
from google.oauth2 import service_account
from googleapiclient.discovery import build
import azure.functions as func
from ddtrace import tracer

# Initialize AWS IAM client
iam = boto3.client('iam')

# Logging
FORMAT = ('%(asctime)s %(levelname)s [%(name)s] [%(filename)s:%(lineno)d] '
          '[dd.service=%(dd.service)s dd.env=%(dd.env)s dd.version=%(dd.version)s dd.trace_id=%(dd.trace_id)s dd.span_id=%(dd.span_id)s] '
          '- %(message)s')
logging.basicConfig(format=FORMAT)

# Initialize GCP IAM service
@tracer.wrap()
def get_gcp_iam_service():
    service_account_key = os.getenv("GCP_SERVICE_ACCOUNT_KEY")
    if not service_account_key:
        raise ValueError("Environment variable GCP_SERVICE_ACCOUNT_KEY is not set")

    credentials_info = json.loads(service_account_key)
    credentials = service_account.Credentials.from_service_account_info(credentials_info)
    return build("iam", "v1", credentials=credentials)

@tracer.wrap()
def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Get request parameters
        integration = req.params.get('integration')
        action = req.params.get('action')

        # Validate required parameters
        if not integration or not action:
            return func.HttpResponse("Missing required parameters: integration or action", status_code=400)

        if integration == 'azure':
            return handle_azure_action(action)
        elif integration == 'aws':
            return handle_aws_action(action)
        elif integration == 'gcp':
            return handle_gcp_action(action)
        else:
            return func.HttpResponse("Invalid integration parameter", status_code=400)

    except Exception as e:
        logging.error(f"Error: {e}")
        return func.HttpResponse(f"An error occurred: {e}", status_code=500)

@tracer.wrap()
def handle_azure_action(action):
    # Get Azure environment variables
    assignee = os.environ.get("ASSIGNEE_PRINCIPAL_ID")
    role = os.environ.get("ROLE_DEFINITION_ID")
    subscription_id = os.environ.get("SUBSCRIPTION_ID")

    if not all([subscription_id, assignee, role]):
        return func.HttpResponse("Required environment variables are not set", status_code=500)

    # Create scope from subscription ID
    scope = f"/subscriptions/{subscription_id}"

    # Authenticate with Azure and create client
    credential = DefaultAzureCredential()
    client = AuthorizationManagementClient(credential, subscription_id)

    if action == "disable":
        assignments = client.role_assignments.list_for_scope(scope)
        found = False
        for assignment in assignments:
            if assignment.principal_id == assignee and assignment.role_definition_id.endswith(role):
                client.role_assignments.delete_by_id(assignment.id)
                found = True
                return func.HttpResponse("Role assignment deleted", status_code=200)

        if not found:
            return func.HttpResponse("Role assignment not found or already deleted", status_code=201)

    elif action == "enable":
        role_assignment_id = str(uuid.uuid4())
        client.role_assignments.create(
            scope=scope,
            role_assignment_name=role_assignment_id,
            parameters=RoleAssignmentCreateParameters(
                role_definition_id=f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{role}",
                principal_id=assignee,
                principal_type="ServicePrincipal",
            ),
        )
        return func.HttpResponse("Role assignment created", status_code=200)

    else:
        return func.HttpResponse("Invalid action for Azure", status_code=400)

@tracer.wrap()
def handle_aws_action(action):
    # Get AWS environment variables
    role_name = os.getenv("AWS_ROLE_NAME")
    policy_arn = os.getenv("AWS_POLICY_ARN")

    if not all([role_name, policy_arn]):
        return func.HttpResponse("Required AWS environment variables are not set", status_code=500)

    if action == "enable":
        aws_integration_enable(role_name, policy_arn)
        return func.HttpResponse("AWS Integration Enabled!", status_code=200)
    elif action == "disable":
        aws_integration_disable(role_name, policy_arn)
        return func.HttpResponse("AWS Integration Disabled!", status_code=200)
    else:
        return func.HttpResponse("Invalid action for AWS", status_code=400)

@tracer.wrap()
def aws_integration_enable(role_name, policy_arn):
    try:
        iam.delete_role_policy(
            RoleName=role_name,
            PolicyName='AutomatedDenyPleaseUseSharedSandboxOrgSeeIAMRoleDescriptionForHelp'
        )
    except Exception as e:
        logging.error(f"Error deleting role policy: {e}")

    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
             "Effect": "Allow",
             "Action": [
                 "apigateway:GET",
                 "autoscaling:Describe*",
                 "backup:List*",
                 "budgets:ViewBudget",
                 "cloudfront:GetDistributionConfig",
                 "cloudfront:ListDistributions",
                 "cloudtrail:DescribeTrails",
                 "cloudtrail:GetTrailStatus",
                 "cloudtrail:LookupEvents",
                 "cloudwatch:Describe*",
                 "cloudwatch:Get*",
                 "cloudwatch:List*",
                 "codedeploy:List*",
                 "codedeploy:BatchGet*",
                 "directconnect:Describe*",
                 "dynamodb:List*",
                 "dynamodb:Describe*",
                 "ec2:Describe*",
                 "ecs:Describe*",
                 "ecs:List*",
                 "elasticache:Describe*",
                 "elasticache:List*",
                 "elasticfilesystem:DescribeFileSystems",
                 "elasticfilesystem:DescribeTags",
                 "elasticfilesystem:DescribeAccessPoints",
                 "elasticloadbalancing:Describe*",
                 "elasticmapreduce:List*",
                 "elasticmapreduce:Describe*",
                 "es:ListTags",
                 "es:ListDomainNames",
                 "es:DescribeElasticsearchDomains",
                 "events:CreateEventBus",
                 "fsx:DescribeFileSystems",
                 "fsx:ListTagsForResource",
                 "health:DescribeEvents",
                 "health:DescribeEventDetails",
                 "health:DescribeAffectedEntities",
                 "kinesis:List*",
                 "kinesis:Describe*",
                 "lambda:GetPolicy",
                 "lambda:List*",
                 "logs:DeleteSubscriptionFilter",
                 "logs:DescribeLogGroups",
                 "logs:DescribeLogStreams",
                 "logs:DescribeSubscriptionFilters",
                 "logs:FilterLogEvents",
                 "logs:PutSubscriptionFilter",
                 "logs:TestMetricFilter",
                 "organizations:Describe*",
                 "organizations:List*",
                 "rds:Describe*",
                 "rds:List*",
                 "redshift:DescribeClusters",
                 "redshift:DescribeLoggingStatus",
                 "route53:List*",
                 "s3:GetBucketLogging",
                 "s3:GetBucketLocation",
                 "s3:GetBucketNotification",
                 "s3:GetBucketTagging",
                 "s3:ListAllMyBuckets",
                 "s3:PutBucketNotification",
                 "ses:Get*",
                 "sns:List*",
                 "sns:Publish",
                 "sqs:ListQueues",
                 "states:ListStateMachines",
                 "states:DescribeStateMachine",
                 "support:DescribeTrustedAdvisor*",
                 "support:RefreshTrustedAdvisorCheck",
                 "tag:GetResources",
                 "tag:GetTagKeys",
                 "tag:GetTagValues",
                 "xray:BatchGetTraces",
                 "xray:GetTraceSummaries"
                ],
             "Resource": "*"
            }
        ]
    }
    response = iam.create_policy_version(
        PolicyArn=policy_arn,
        PolicyDocument=json.dumps(policy_document),
        SetAsDefault=True
    )
    logging.info(f"Created new policy version: {response['PolicyVersion']['VersionId']}")

    versions = iam.list_policy_versions(PolicyArn=policy_arn)['Versions']
    old_version = [v for v in versions if not v['IsDefaultVersion']][-1]
    iam.delete_policy_version(
        PolicyArn=policy_arn,
        VersionId=old_version['VersionId']
    )
    logging.info(f"Deleted old policy version: {old_version['VersionId']}")

@tracer.wrap()
def aws_integration_disable(role_name, policy_arn):
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
    response = iam.create_policy_version(
        PolicyArn=policy_arn,
        PolicyDocument=json.dumps(policy_document),
        SetAsDefault=True
    )
    logging.info(f"Created new policy version: {response['PolicyVersion']['VersionId']}")

    versions = iam.list_policy_versions(PolicyArn=policy_arn)['Versions']
    old_version = [v for v in versions if not v['IsDefaultVersion']][-1]
    iam.delete_policy_version(
        PolicyArn=policy_arn,
        VersionId=old_version['VersionId']
    )
    logging.info(f"Deleted old policy version: {old_version['VersionId']}")

@tracer.wrap()
def handle_gcp_action(action):
    # Get GCP environment variables
    service_account_email = os.getenv("SERVICE_ACCOUNT_EMAIL")
    if not service_account_email:
        return func.HttpResponse("Environment variable SERVICE_ACCOUNT_EMAIL is not set", status_code=500)

    # Use IAM API to change service account status
    iam_service = get_gcp_iam_service()
    resource_name = f"projects/-/serviceAccounts/{service_account_email}"

    try:
        if action == "disable":
            iam_service.projects().serviceAccounts().disable(name=resource_name).execute()
            return func.HttpResponse(f"Service account {service_account_email} has been disabled", status_code=200)
        elif action == "enable":
            iam_service.projects().serviceAccounts().enable(name=resource_name).execute()
            return func.HttpResponse(f"Service account {service_account_email} has been enabled", status_code=200)
        else:
            return func.HttpResponse("Invalid action for GCP", status_code=400)
    except Exception as e:
        logging.error(f"Error in GCP action: {e}")
        return func.HttpResponse(f"An error occurred: {e}", status_code=500)
