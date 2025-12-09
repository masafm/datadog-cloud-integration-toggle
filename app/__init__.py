import logging
import logging.handlers
import socket
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
from ddtrace import patch
patch(logging=True)

# Initialize AWS IAM client
iam = boto3.client('iam')

class UDPTextHandler(logging.Handler):
    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def emit(self, record):
        try:
            msg = self.format(record)
            self.sock.sendto(msg.encode('utf-8'), (self.host, self.port))
        except Exception:
            self.handleError(record)

# Logging
BASIC_FORMAT = ('%(asctime)s %(levelname)s [%(name)s] [%(filename)s:%(lineno)d] '
          '- %(message)s')
FORMAT = ('%(asctime)s %(levelname)s [%(name)s] [%(filename)s:%(lineno)d] '
          '[dd.service=%(dd.service)s dd.env=%(dd.env)s dd.version=%(dd.version)s dd.trace_id=%(dd.trace_id)s dd.span_id=%(dd.span_id)s] '
          '- %(message)s')
logging.basicConfig(format=BASIC_FORMAT)

# 環境変数からUDP送信先のホストとポートを取得
UDP_HOST = os.getenv('LOG_UDP_HOST', '127.0.0.1')
UDP_PORT = int(os.getenv('LOG_UDP_PORT', 514))
print(f"Debug: UDP_HOST={UDP_HOST}, UDP_PORT={UDP_PORT}")

# ロガーのセットアップ
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
dd_logger = logging.getLogger("ddtrace")
dd_logger.setLevel(logging.DEBUG)

udp_handler = UDPTextHandler(UDP_HOST, UDP_PORT)
udp_formatter = logging.Formatter(FORMAT)
udp_handler.setFormatter(udp_formatter)

dd_udp_handler = UDPTextHandler(UDP_HOST, UDP_PORT)
dd_udp_formatter = logging.Formatter(BASIC_FORMAT)
dd_udp_handler.setFormatter(dd_udp_formatter)

stream_handler = logging.StreamHandler()
stream_formatter = logging.Formatter(FORMAT)
stream_handler.setFormatter(stream_formatter)

dd_stream_handler = logging.StreamHandler()
dd_stream_formatter = logging.Formatter(BASIC_FORMAT)
dd_stream_handler.setFormatter(dd_stream_formatter)

logger.addHandler(udp_handler)
logger.addHandler(dd_udp_handler)
logger.addHandler(stream_handler)
logger.addHandler(dd_stream_handler)

# 共通: ログ出力とレスポンス生成を一箇所に集約
def log_and_respond(message: str,
                    status_code: int,
                    cloud: str = "COMMON",
                    level: str = "info") -> func.HttpResponse:
    """
    message: 実際にクライアントへ返すメッセージ
    status_code: HTTP ステータスコード
    cloud: 'AZURE', 'AWS', 'GCP', 'COMMON' など
    level: 'info', 'error', 'warning', ...
    """
    tagged_message = f"[{cloud}] {message}"

    if level == "error":
        logger.error(tagged_message)
    elif level == "warning":
        logger.warning(tagged_message)
    else:
        logger.info(tagged_message)

    # レスポンスの内容とログメッセージを完全に一致させる
    return func.HttpResponse(tagged_message, status_code=status_code)

# Initialize GCP IAM service
@tracer.wrap()
def get_gcp_iam_service():
    service_account_key = os.getenv("GCP_SERVICE_ACCOUNT_KEY")
    if not service_account_key:
        # 環境変数不足は例外にして呼び出し側で共通エラーハンドリング
        raise ValueError("Environment variable GCP_SERVICE_ACCOUNT_KEY is not set")

    credentials_info = json.loads(service_account_key)
    credentials = service_account.Credentials.from_service_account_info(credentials_info)
    return build("iam", "v1", credentials=credentials)

@tracer.wrap()
def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        integration = req.params.get('integration')
        action = req.params.get('action')

        if not integration or not action:
            return log_and_respond(
                "Missing required parameters: integration or action",
                status_code=400,
                cloud="COMMON",
                level="error"
            )

        logger.info(f"[COMMON] Request received: integration={integration}, action={action}")

        if integration == 'azure':
            return handle_azure_action(action)
        elif integration == 'aws':
            return handle_aws_action(action)
        elif integration == 'gcp':
            return handle_gcp_action(action)
        else:
            return log_and_respond(
                "Invalid integration parameter",
                status_code=400,
                cloud="COMMON",
                level="error"
            )

    except Exception as e:
        # 共通エラー（どのクラウドか特定できない場合）
        return log_and_respond(
            f"An error occurred: {e}",
            status_code=500,
            cloud="COMMON",
            level="error"
        )

@tracer.wrap()
def handle_azure_action(action):
    assignee = os.environ.get("ASSIGNEE_PRINCIPAL_ID")
    role = os.environ.get("ROLE_DEFINITION_ID")
    subscription_id = os.environ.get("SUBSCRIPTION_ID")

    if not all([subscription_id, assignee, role]):
        logger.error(
            f"[AZURE] Required environment variables missing: "
            f"subscription_id={subscription_id}, assignee={assignee}, role={role}"
        )
        return log_and_respond(
            "Required environment variables are not set",
            status_code=500,
            cloud="AZURE",
            level="error"
        )

    scope = f"/subscriptions/{subscription_id}"

    logger.info(
        f"[AZURE] Request received: action={action}, "
        f"subscription_id={subscription_id}, assignee_principal_id={assignee}, role_definition_id={role}, scope={scope}"
    )

    credential = DefaultAzureCredential()
    client = AuthorizationManagementClient(credential, subscription_id)

    if action == "disable":
        assignments = client.role_assignments.list_for_scope(scope)
        found = False
        for assignment in assignments:
            if assignment.principal_id == assignee and assignment.role_definition_id.endswith(role):
                logger.info(
                    f"[AZURE] Deleting role assignment: "
                    f"id={assignment.id}, role_definition_id={assignment.role_definition_id}, "
                    f"principal_id={assignment.principal_id}, scope={scope}"
                )
                client.role_assignments.delete_by_id(assignment.id)
                found = True
                return log_and_respond(
                    "Azure Integration Disabled!",
                    status_code=200,
                    cloud="AZURE",
                    level="info"
                )

        if not found:
            logger.info(
                f"[AZURE] Role assignment not found or already deleted: "
                f"subscription_id={subscription_id}, assignee_principal_id={assignee}, role_definition_id_suffix={role}"
            )
            return log_and_respond(
                "Role assignment not found or already deleted",
                status_code=201,
                cloud="AZURE",
                level="info"
            )

    elif action == "enable":
        role_assignment_id = str(uuid.uuid4())
        logger.info(
            f"[AZURE] Creating role assignment: "
            f"role_assignment_id={role_assignment_id}, subscription_id={subscription_id}, "
            f"assignee_principal_id={assignee}, role_definition_id={role}, scope={scope}"
        )
        result = client.role_assignments.create(
            scope=scope,
            role_assignment_name=role_assignment_id,
            parameters=RoleAssignmentCreateParameters(
                role_definition_id=f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{role}",
                principal_id=assignee,
                principal_type="ServicePrincipal",
            ),
        )
        # Azure SDK のモデルは as_dict() で安全に辞書化可能
        try:
            result_dict = result.as_dict()
        except Exception:
            # 念のため fallback（文字列化）
            result_dict = str(result)
        logger.info(f"[AZURE] Role assignment created: {json.dumps(result_dict)}")
        return log_and_respond(
            "Azure Integration Enabled!",
            status_code=200,
            cloud="AZURE",
            level="info"
        )

    else:
        logger.warning(f"[AZURE] Invalid action for Azure: action={action}")
        return log_and_respond(
            "Invalid action for Azure",
            status_code=400,
            cloud="AZURE",
            level="error"
        )

@tracer.wrap()
def handle_aws_action(action):
    role_name = os.getenv("AWS_ROLE_NAME")
    policy_arn = os.getenv("AWS_POLICY_ARN")

    if not all([role_name, policy_arn]):
        logger.error(
            f"[AWS] Required AWS environment variables are not set: "
            f"role_name={role_name}, policy_arn={policy_arn}"
        )
        return log_and_respond(
            "Required AWS environment variables are not set",
            status_code=500,
            cloud="AWS",
            level="error"
        )

    # ここで「どのロール／どのポリシーを操作するか」を事前にログ
    logger.info(f"[AWS] Request received: action={action}, role_name={role_name}, policy_arn={policy_arn}")

    if action == "enable":
        aws_integration_enable(role_name, policy_arn)
        return log_and_respond(
            "AWS Integration Enabled!",
            status_code=200,
            cloud="AWS",
            level="info"
        )
    elif action == "disable":
        aws_integration_disable(role_name, policy_arn)
        return log_and_respond(
            "AWS Integration Disabled!",
            status_code=200,
            cloud="AWS",
            level="info"
        )
    else:
        logger.warning(f"[AWS] Invalid action for AWS: action={action}")
        return log_and_respond(
            "Invalid action for AWS",
            status_code=400,
            cloud="AWS",
            level="error"
        )

@tracer.wrap()
def aws_integration_enable(role_name, policy_arn):
    # どのロールから deny ポリシーを削除しようとしているかログ
    logger.info(f"[AWS] Trying to delete inline deny policy from role_name={role_name}")

    try:
        iam.delete_role_policy(
            RoleName=role_name,
            PolicyName='AutomatedDenyPleaseUseSharedSandboxOrgSeeIAMRoleDescriptionForHelp'
        )
        logger.info(f"[AWS] Deleted inline deny policy from role_name={role_name}")
    except Exception as e:
        # ここはレスポンスではなく内部処理なのでログだけ
        logger.warning(f"[AWS] Error deleting role policy for role_name={role_name}: {e}")

    logger.info(f"[AWS] Creating new ALLOW policy version for policy_arn={policy_arn}, role_name={role_name}")

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
    logger.info(
        f"[AWS] Created new ALLOW policy version: "
        f"policy_arn={policy_arn}, role_name={role_name}, version_id={response['PolicyVersion']['VersionId']}"
    )

    versions = iam.list_policy_versions(PolicyArn=policy_arn)['Versions']
    old_version = [v for v in versions if not v['IsDefaultVersion']][-1]
    iam.delete_policy_version(
        PolicyArn=policy_arn,
        VersionId=old_version['VersionId']
    )
    logger.info(
        f"[AWS] Deleted old policy version: "
        f"policy_arn={policy_arn}, role_name={role_name}, version_id={old_version['VersionId']}"
    )

@tracer.wrap()
def aws_integration_disable(role_name, policy_arn):
    logger.info(f"[AWS] Creating new DENY policy version for policy_arn={policy_arn}, role_name={role_name}")

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
    logger.info(
        f"[AWS] Created new DENY policy version: "
        f"policy_arn={policy_arn}, role_name={role_name}, version_id={response['PolicyVersion']['VersionId']}"
    )

    versions = iam.list_policy_versions(PolicyArn=policy_arn)['Versions']
    old_version = [v for v in versions if not v['IsDefaultVersion']][-1]
    iam.delete_policy_version(
        PolicyArn=policy_arn,
        VersionId=old_version['VersionId']
    )
    logger.info(
        f"[AWS] Deleted old policy version: "
        f"policy_arn={policy_arn}, role_name={role_name}, version_id={old_version['VersionId']}"
    )

@tracer.wrap()
def handle_gcp_action(action):
    service_account_email = os.getenv("SERVICE_ACCOUNT_EMAIL")
    if not service_account_email:
        logger.error("[GCP] Environment variable SERVICE_ACCOUNT_EMAIL is not set")
        return log_and_respond(
            "Environment variable SERVICE_ACCOUNT_EMAIL is not set",
            status_code=500,
            cloud="GCP",
            level="error"
        )

    iam_service = get_gcp_iam_service()
    resource_name = f"projects/-/serviceAccounts/{service_account_email}"

    logger.info(
        f"[GCP] Request received: action={action}, "
        f"service_account_email={service_account_email}, resource_name={resource_name}"
    )

    try:
        if action == "disable":
            logger.info(
                f"[GCP] Disabling service account: "
                f"service_account_email={service_account_email}, resource_name={resource_name}"
            )
            iam_service.projects().serviceAccounts().disable(name=resource_name).execute()
            logger.info(f"[GCP] Service account disabled successfully: service_account_email={service_account_email}")
            return log_and_respond(
                "GCP Integration Disabled!",
                status_code=200,
                cloud="GCP",
                level="info"
            )
        elif action == "enable":
            logger.info(
                f"[GCP] Enabling service account: "
                f"service_account_email={service_account_email}, resource_name={resource_name}"
            )
            iam_service.projects().serviceAccounts().enable(name=resource_name).execute()
            logger.info(f"[GCP] Service account enabled successfully: service_account_email={service_account_email}")
            return log_and_respond(
                "GCP Integration Enabled!",
                status_code=200,
                cloud="GCP",
                level="info"
            )
        else:
            logger.warning(f"[GCP] Invalid action for GCP: action={action}")
            return log_and_respond(
                "Invalid action for GCP",
                status_code=400,
                cloud="GCP",
                level="error"
            )
    except Exception as e:
        logger.error(
            f"[GCP] Error in GCP action: action={action}, "
            f"service_account_email={service_account_email}, error={e}"
        )
        return log_and_respond(
            f"An error occurred: {e}",
            status_code=500,
            cloud="GCP",
            level="error"
        )

