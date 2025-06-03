import logging
import logging.handlers
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

# 環境変数からUDP送信先のホストとポートを取得
UDP_HOST = os.getenv('LOG_UDP_HOST', '127.0.0.1')  # 環境変数が無ければ '127.0.0.1'
UDP_PORT = int(os.getenv('LOG_UDP_PORT', 514))     # 環境変数が無ければ 514
print(f"Debug: UDP_HOST={UDP_HOST}, UDP_PORT={UDP_PORT}")

# ロガーのセットアップ
logger = logging.getLogger('udp_logger')
logger.setLevel(logging.DEBUG)

# DatagramHandlerのセットアップ (UDP送信用)
udp_handler = logging.handlers.DatagramHandler(UDP_HOST, UDP_PORT)
udp_formatter = logging.Formatter(FORMAT)
udp_handler.setFormatter(udp_formatter)

# StreamHandlerのセットアップ (標準出力用)
stream_handler = logging.StreamHandler()
stream_formatter = logging.Formatter(FORMAT)
stream_handler.setFormatter(stream_formatter)

# ハンドラをロガーに追加
logger.addHandler(udp_handler)    # UDP送信用
logger.addHandler(stream_handler) # 標準出力用

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
        logger.error(f"Error: {e}")
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
        logger.error(f"Error deleting role policy: {e}")

    policy_document = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "apigateway:GET",
                "aoss:BatchGetCollection",
                "aoss:ListCollections",
                "autoscaling:Describe*",
                "backup:List*",
                "bcm-data-exports:GetExport",
                "bcm-data-exports:ListExports",
                "bedrock:GetAgent",
                "bedrock:GetAgentAlias",
                "bedrock:GetFlow",
                "bedrock:GetFlowAlias",
                "bedrock:GetGuardrail",
                "bedrock:GetImportedModel",
                "bedrock:GetInferenceProfile",
                "bedrock:GetMarketplaceModelEndpoint",
                "bedrock:ListAgentAliases",
                "bedrock:ListAgents",
                "bedrock:ListFlowAliases",
                "bedrock:ListFlows",
                "bedrock:ListGuardrails",
                "bedrock:ListImportedModels",
                "bedrock:ListInferenceProfiles",
                "bedrock:ListMarketplaceModelEndpoints",
                "bedrock:ListPromptRouters",
                "bedrock:ListProvisionedModelThroughputs",
                "budgets:ViewBudget",
                "cassandra:Select",
                "cloudfront:GetDistributionConfig",
                "cloudfront:ListDistributions",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "cloudtrail:LookupEvents",
                "cloudwatch:Describe*",
                "cloudwatch:Get*",
                "cloudwatch:List*",
                "codeartifact:DescribeDomain",
                "codeartifact:DescribePackageGroup",
                "codeartifact:DescribeRepository",
                "codeartifact:ListDomains",
                "codeartifact:ListPackageGroups",
                "codeartifact:ListPackages",
                "codedeploy:BatchGet*",
                "codedeploy:List*",
                "codepipeline:ListWebhooks",
                "cur:DescribeReportDefinitions",
                "directconnect:Describe*",
                "dynamodb:Describe*",
                "dynamodb:List*",
                "ec2:Describe*",
                "ec2:GetAllowedImagesSettings",
                "ec2:GetEbsDefaultKmsKeyId",
                "ec2:GetInstanceMetadataDefaults",
                "ec2:GetSerialConsoleAccessStatus",
                "ec2:GetSnapshotBlockPublicAccessState",
                "ec2:GetTransitGatewayPrefixListReferences",
                "ec2:SearchTransitGatewayRoutes",
                "ecs:Describe*",
                "ecs:List*",
                "elasticache:Describe*",
                "elasticache:List*",
                "elasticfilesystem:DescribeAccessPoints",
                "elasticfilesystem:DescribeFileSystems",
                "elasticfilesystem:DescribeTags",
                "elasticloadbalancing:Describe*",
                "elasticmapreduce:Describe*",
                "elasticmapreduce:List*",
                "emr-containers:ListManagedEndpoints",
                "emr-containers:ListSecurityConfigurations",
                "emr-containers:ListVirtualClusters",
                "es:DescribeElasticsearchDomains",
                "es:ListDomainNames",
                "es:ListTags",
                "events:CreateEventBus",
                "fsx:DescribeFileSystems",
                "fsx:ListTagsForResource",
                "glacier:GetVaultNotifications",
                "glue:ListRegistries",
                "grafana:DescribeWorkspace",
                "greengrass:GetComponent",
                "greengrass:GetConnectivityInfo",
                "greengrass:GetCoreDevice",
                "greengrass:GetDeployment",
                "health:DescribeAffectedEntities",
                "health:DescribeEventDetails",
                "health:DescribeEvents",
                "kinesis:Describe*",
                "kinesis:List*",
                "lambda:GetPolicy",
                "lambda:List*",
                "lightsail:GetInstancePortStates",
                "logs:DeleteSubscriptionFilter",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:DescribeSubscriptionFilters",
                "logs:FilterLogEvents",
                "logs:PutSubscriptionFilter",
                "logs:TestMetricFilter",
                "macie2:GetAllowList",
                "macie2:GetCustomDataIdentifier",
                "macie2:ListAllowLists",
                "macie2:ListCustomDataIdentifiers",
                "macie2:ListMembers",
                "macie2:GetMacieSession",
                "managedblockchain:GetAccessor",
                "managedblockchain:GetMember",
                "managedblockchain:GetNetwork",
                "managedblockchain:GetNode",
                "managedblockchain:GetProposal",
                "managedblockchain:ListAccessors",
                "managedblockchain:ListInvitations",
                "managedblockchain:ListMembers",
                "managedblockchain:ListNodes",
                "managedblockchain:ListProposals",
                "memorydb:DescribeAcls",
                "memorydb:DescribeMultiRegionClusters",
                "memorydb:DescribeParameterGroups",
                "memorydb:DescribeReservedNodes",
                "memorydb:DescribeSnapshots",
                "memorydb:DescribeSubnetGroups",
                "memorydb:DescribeUsers",
                "oam:ListAttachedLinks",
                "oam:ListSinks",
                "organizations:Describe*",
                "organizations:List*",
                "osis:GetPipeline",
                "osis:GetPipelineBlueprint",
                "osis:ListPipelineBlueprints",
                "osis:ListPipelines",
                "proton:GetComponent",
                "proton:GetDeployment",
                "proton:GetEnvironment",
                "proton:GetEnvironmentAccountConnection",
                "proton:GetEnvironmentTemplate",
                "proton:GetEnvironmentTemplateVersion",
                "proton:GetRepository",
                "proton:GetService",
                "proton:GetServiceInstance",
                "proton:GetServiceTemplate",
                "proton:GetServiceTemplateVersion",
                "proton:ListComponents",
                "proton:ListDeployments",
                "proton:ListEnvironmentAccountConnections",
                "proton:ListEnvironmentTemplateVersions",
                "proton:ListEnvironmentTemplates",
                "proton:ListEnvironments",
                "proton:ListRepositories",
                "proton:ListServiceInstances",
                "proton:ListServiceTemplateVersions",
                "proton:ListServiceTemplates",
                "proton:ListServices",
                "qldb:ListJournalKinesisStreamsForLedger",
                "rds:Describe*",
                "rds:List*",
                "redshift:DescribeClusters",
                "redshift:DescribeLoggingStatus",
                "redshift-serverless:ListEndpointAccess",
                "redshift-serverless:ListManagedWorkgroups",
                "redshift-serverless:ListNamespaces",
                "redshift-serverless:ListRecoveryPoints",
                "redshift-serverless:ListSnapshots",
                "route53:List*",
                "s3:GetBucketLocation",
                "s3:GetBucketLogging",
                "s3:GetBucketNotification",
                "s3:GetBucketTagging",
                "s3:ListAccessGrants",
                "s3:ListAllMyBuckets",
                "s3:PutBucketNotification",
                "s3express:GetBucketPolicy",
                "s3express:GetEncryptionConfiguration",
                "s3express:ListAllMyDirectoryBuckets",
                "s3tables:GetTableBucketMaintenanceConfiguration",
                "s3tables:ListTableBuckets",
                "s3tables:ListTables",
                "savingsplans:DescribeSavingsPlanRates",
                "savingsplans:DescribeSavingsPlans",
                "secretsmanager:GetResourcePolicy",
                "ses:Get*",
                "ses:ListAddonInstances",
                "ses:ListAddonSubscriptions",
                "ses:ListAddressLists",
                "ses:ListArchives",
                "ses:ListContactLists",
                "ses:ListCustomVerificationEmailTemplates",
                "ses:ListMultiRegionEndpoints",
                "ses:ListIngressPoints",
                "ses:ListRelays",
                "ses:ListRuleSets",
                "ses:ListTemplates",
                "ses:ListTrafficPolicies",
                "sns:GetSubscriptionAttributes",
                "sns:List*",
                "sns:Publish",
                "sqs:ListQueues",
                "states:DescribeStateMachine",
                "states:ListStateMachines",
                "support:DescribeTrustedAdvisor*",
                "support:RefreshTrustedAdvisorCheck",
                "tag:GetResources",
                "tag:GetTagKeys",
                "tag:GetTagValues",
                "timestream:DescribeEndpoints",
                "timestream:ListTables",
                "waf-regional:GetRule",
                "waf-regional:GetRuleGroup",
                "waf-regional:ListRuleGroups",
                "waf-regional:ListRules",
                "waf:GetRule",
                "waf:GetRuleGroup",
                "waf:ListRuleGroups",
                "waf:ListRules",
                "wafv2:GetIPSet",
                "wafv2:GetLoggingConfiguration",
                "wafv2:GetRegexPatternSet",
                "wafv2:GetRuleGroup",
                "wafv2:ListLoggingConfigurations",
                "workmail:DescribeOrganization",
                "workmail:ListOrganizations",
                "xray:BatchGetTraces",
                "xray:GetTraceSummaries"
            ],
            "Effect": "Allow",
            "Resource": "*"
        }
    ]
}

    response = iam.create_policy_version(
        PolicyArn=policy_arn,
        PolicyDocument=json.dumps(policy_document),
        SetAsDefault=True
    )
    logger.info(f"Created new policy version: {response['PolicyVersion']['VersionId']}")

    versions = iam.list_policy_versions(PolicyArn=policy_arn)['Versions']
    old_version = [v for v in versions if not v['IsDefaultVersion']][-1]
    iam.delete_policy_version(
        PolicyArn=policy_arn,
        VersionId=old_version['VersionId']
    )
    logger.info(f"Deleted old policy version: {old_version['VersionId']}")

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
    logger.info(f"Created new policy version: {response['PolicyVersion']['VersionId']}")

    versions = iam.list_policy_versions(PolicyArn=policy_arn)['Versions']
    old_version = [v for v in versions if not v['IsDefaultVersion']][-1]
    iam.delete_policy_version(
        PolicyArn=policy_arn,
        VersionId=old_version['VersionId']
    )
    logger.info(f"Deleted old policy version: {old_version['VersionId']}")

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
        logger.error(f"Error in GCP action: {e}")
        return func.HttpResponse(f"An error occurred: {e}", status_code=500)
