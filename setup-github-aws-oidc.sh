#!/bin/bash
set -e

# Configuration
GITHUB_USERNAME="evanchime"
GITHUB_REPO="me_website"
AWS_REGION="eu-west-2"
ECR_REPO_NAME="me_website"

# ECR role configuration
ROLE_NAME="GitHubActions-ECR-Role"
POLICY_NAME="GitHubActions-ECR-PushPull-Policy"

# Terraform/IaC role configuration
# This role is assumed by the 'iac-execution' job which has environment: production,
# so its OIDC sub claim is repo:OWNER/REPO:environment:production.
TERRAFORM_ROLE_NAME="GitHubActions-Terraform-Role"
TERRAFORM_POLICY_NAME="GitHubActions-Terraform-Deploy-Policy"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if role exists
check_role_exists() {
    aws iam get-role --role-name "$1" >/dev/null 2>&1
}

# Check if policy exists
check_policy_exists() {
    local account_id=$(aws sts get-caller-identity --query Account --output text)
    aws iam get-policy --policy-arn "arn:aws:iam::${account_id}:policy/$1" >/dev/null 2>&1
}

# Check if OIDC provider exists
check_oidc_provider_exists() {
    local account_id=$(aws sts get-caller-identity --query Account --output text)
    aws iam get-open-id-connect-provider \
        --open-id-connect-provider-arn "arn:aws:iam::${account_id}:oidc-provider/token.actions.githubusercontent.com" \
        >/dev/null 2>&1
}

# Main execution
main() {
    local account_id=$(aws sts get-caller-identity --query Account --output text)
    
    log_info "Setting up GitHub Actions OIDC for account: $account_id"
    
    # 1. Check/Create OIDC Provider
    if check_oidc_provider_exists; then
        log_warn "OIDC provider already exists"
    else
        log_info "Creating OIDC provider..."
        # Get current thumbprint
        local thumbprint=$(echo | openssl s_client -servername token.actions.githubusercontent.com \
            -connect token.actions.githubusercontent.com:443 2>/dev/null \
            | openssl x509 -fingerprint -noout -sha1 \
            | cut -d'=' -f2 | tr -d ':')
        
        aws iam create-open-id-connect-provider \
            --url https://token.actions.githubusercontent.com \
            --client-id-list sts.amazonaws.com \
            --thumbprint-list "$thumbprint"
        log_info "✅ OIDC provider created"
    fi
    
    # 2. Create trust policy
    cat > github-trust-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::$account_id:oidc-provider/token.actions.githubusercontent.com"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
                },
                "StringLike": {
                    "token.actions.githubusercontent.com:sub": [
                        "repo:evanchime/me_website:ref:refs/heads/main",
                        "repo:evanchime/me_website:ref:refs/heads/develop",
                        "repo:evanchime/me_website:ref:refs/heads/feature-k8s-migration-monitoring-observability",
                        "repo:evanchime/me_website:ref:refs/tags/*"
                    ]
                }
            }
        }
    ]
}
EOF
    
    # 3. Check/Create Role
    if check_role_exists "$ROLE_NAME"; then
        log_warn "Role '$ROLE_NAME' already exists"
        log_info "Updating assume role policy..."
        aws iam update-assume-role-policy \
            --role-name "$ROLE_NAME" \
            --policy-document file://github-trust-policy.json
        log_info "✅ Assume role policy updated"
    else
        log_info "Creating role '$ROLE_NAME'..."
        aws iam create-role \
            --role-name "$ROLE_NAME" \
            --assume-role-policy-document file://github-trust-policy.json \
            --description "Role for GitHub Actions to push/pull ECR images"
        log_info "✅ Role created"
    fi
    
    # 4. Create ECR permissions policy
    cat > ecr-permissions-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowPushPull",
            "Effect": "Allow",
            "Action": [
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "ecr:BatchCheckLayerAvailability",
                "ecr:PutImage",
                "ecr:InitiateLayerUpload",
                "ecr:UploadLayerPart",
                "ecr:CompleteLayerUpload"
            ],
            "Resource": "arn:aws:ecr:${AWS_REGION}:${account_id}:repository/${ECR_REPO_NAME}"
        },
        {
            "Sid": "AllowGetAuthorizationToken",
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AllowInspectorScan",
            "Effect": "Allow",
            "Action": [
                "inspector-scan:ScanSbom"
            ],
            "Resource": "*" 
        }
    ]
}
EOF
    
    # 5. Check/Create/Update Policy
    local account_id=$(aws sts get-caller-identity --query Account --output text)
    local policy_arn="arn:aws:iam::${account_id}:policy/${POLICY_NAME}"

    if check_policy_exists "$POLICY_NAME"; then
        log_warn "Policy '$POLICY_NAME' already exists. Creating a new version to apply updates..."
        
        # Get the ARN of the policy
        local policy_arn_to_update=$(aws iam get-policy --policy-arn "$policy_arn" --query 'Policy.Arn' --output text)

        # Create a new version of the policy
        aws iam create-policy-version \
            --policy-arn "$policy_arn_to_update" \
            --policy-document file://ecr-permissions-policy.json \
            --set-as-default >/dev/null

        # Optional: Clean up old policy versions to stay within the 5-version limit
        local versions=$(aws iam list-policy-versions --policy-arn "$policy_arn_to_update" --query 'Versions[?IsDefaultVersion==`false`].VersionId' --output text)
        for version_id in $versions; do
            log_info "Deleting old policy version: $version_id"
            aws iam delete-policy-version --policy-arn "$policy_arn_to_update" --version-id "$version_id"
        done

        log_info "✅ Policy updated with new version."
    else
        log_info "Creating policy '$POLICY_NAME'..."
        aws iam create-policy \
            --policy-name "$POLICY_NAME" \
            --policy-document file://ecr-permissions-policy.json \
            --description "Allows GitHub Actions to push/pull images from ECR"
        log_info "✅ Policy created"
    fi
    
    # 6. Attach policy to role (idempotent operation )
    log_info "Attaching policy to role..."
    aws iam attach-role-policy \
        --role-name "$ROLE_NAME" \
        --policy-arn "arn:aws:iam::${account_id}:policy/${POLICY_NAME}" 2>/dev/null || {
        log_warn "Policy might already be attached (this is OK)"
    }
    
    # 7. Display ECR role results
    local ecr_role_arn=$(aws iam get-role --role-name "$ROLE_NAME" --query 'Role.Arn' --output text)

    # =========================================================================
    # Terraform/IaC Role Setup
    # The 'iac-execution' workflow job runs with environment: production, so its
    # OIDC sub claim is repo:OWNER/REPO:environment:production (not a branch ref).
    # The trust policy below must use StringEquals on that exact sub value.
    # =========================================================================

    # 8. Create trust policy for Terraform role
    cat > terraform-trust-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::$account_id:oidc-provider/token.actions.githubusercontent.com"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                    "token.actions.githubusercontent.com:sub": "repo:${GITHUB_USERNAME}/${GITHUB_REPO}:environment:production"
                }
            }
        }
    ]
}
EOF

    # 9. Check/Create Terraform Role
    if check_role_exists "$TERRAFORM_ROLE_NAME"; then
        log_warn "Role '$TERRAFORM_ROLE_NAME' already exists"
        log_info "Updating assume role policy..."
        aws iam update-assume-role-policy \
            --role-name "$TERRAFORM_ROLE_NAME" \
            --policy-document file://terraform-trust-policy.json
        log_info "✅ Terraform assume role policy updated"
    else
        log_info "Creating role '$TERRAFORM_ROLE_NAME'..."
        aws iam create-role \
            --role-name "$TERRAFORM_ROLE_NAME" \
            --assume-role-policy-document file://terraform-trust-policy.json \
            --description "Role for GitHub Actions to run Terraform and manage K8s infrastructure"
        log_info "✅ Terraform role created"
    fi

    # 10. Create Terraform permissions policy
    # Covers the full infrastructure stack managed by the Terraform workspaces:
    # network (VPC, CloudFront, Route53, S3), eks (EKS cluster), platform (IAM/IRSA,
    # Grafana, Prometheus), and app (Kubernetes resources, Secrets Manager, Lambda, RDS).
    # Broad service permissions are required because Terraform creates resources whose
    # ARNs are not known at policy-authoring time. A final Deny statement guards against
    # privilege escalation by preventing modification of the OIDC roles and provider.
    cat > terraform-permissions-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "EC2AndVPC",
            "Effect": "Allow",
            "Action": ["ec2:*"],
            "Resource": "*"
        },
        {
            "Sid": "EKS",
            "Effect": "Allow",
            "Action": ["eks:*"],
            "Resource": "*"
        },
        {
            "Sid": "IAM",
            "Effect": "Allow",
            "Action": ["iam:*"],
            "Resource": "*"
        },
        {
            "Sid": "CloudFront",
            "Effect": "Allow",
            "Action": ["cloudfront:*"],
            "Resource": "*"
        },
        {
            "Sid": "S3",
            "Effect": "Allow",
            "Action": ["s3:*"],
            "Resource": "*"
        },
        {
            "Sid": "Route53",
            "Effect": "Allow",
            "Action": ["route53:*", "route53domains:*"],
            "Resource": "*"
        },
        {
            "Sid": "SecretsManager",
            "Effect": "Allow",
            "Action": ["secretsmanager:*"],
            "Resource": "*"
        },
        {
            "Sid": "Lambda",
            "Effect": "Allow",
            "Action": ["lambda:*"],
            "Resource": "*"
        },
        {
            "Sid": "RDS",
            "Effect": "Allow",
            "Action": ["rds:*"],
            "Resource": "*"
        },
        {
            "Sid": "ELB",
            "Effect": "Allow",
            "Action": ["elasticloadbalancing:*"],
            "Resource": "*"
        },
        {
            "Sid": "AutoScaling",
            "Effect": "Allow",
            "Action": ["autoscaling:*"],
            "Resource": "*"
        },
        {
            "Sid": "CloudWatchAndLogs",
            "Effect": "Allow",
            "Action": ["logs:*", "cloudwatch:*"],
            "Resource": "*"
        },
        {
            "Sid": "ACM",
            "Effect": "Allow",
            "Action": ["acm:*"],
            "Resource": "*"
        },
        {
            "Sid": "KMS",
            "Effect": "Allow",
            "Action": ["kms:*"],
            "Resource": "*"
        },
        {
            "Sid": "SSM",
            "Effect": "Allow",
            "Action": ["ssm:*"],
            "Resource": "*"
        },
        {
            "Sid": "ECR",
            "Effect": "Allow",
            "Action": ["ecr:*"],
            "Resource": "*"
        },
        {
            "Sid": "Grafana",
            "Effect": "Allow",
            "Action": ["grafana:*"],
            "Resource": "*"
        },
        {
            "Sid": "AmazonManagedPrometheus",
            "Effect": "Allow",
            "Action": ["aps:*"],
            "Resource": "*"
        },
        {
            "Sid": "SSOAndIdentityStore",
            "Effect": "Allow",
            "Action": ["sso-admin:*", "sso:*", "identitystore:*"],
            "Resource": "*"
        },
        {
            "Sid": "STSAssumeRole",
            "Effect": "Allow",
            "Action": ["sts:AssumeRole", "sts:GetCallerIdentity", "sts:GetServiceBearerToken"],
            "Resource": "arn:aws:iam::*:role/*"
        },
        {
            "Sid": "DenyPrivilegeEscalation",
            "Effect": "Deny",
            "Action": [
                "iam:UpdateAssumeRolePolicy",
                "iam:DeleteRole",
                "iam:DetachRolePolicy",
                "iam:DeleteRolePolicy",
                "iam:PutRolePolicy",
                "iam:CreatePolicyVersion",
                "iam:SetDefaultPolicyVersion",
                "iam:DeletePolicy",
                "iam:DeletePolicyVersion",
                "iam:DeleteOpenIDConnectProvider",
                "iam:UpdateOpenIDConnectProviderThumbprint",
                "iam:CreateOpenIDConnectProvider"
            ],
            "Resource": [
                "arn:aws:iam::*:role/GitHubActions-Terraform-Role",
                "arn:aws:iam::*:role/GitHubActions-ECR-Role",
                "arn:aws:iam::*:policy/GitHubActions-Terraform-Deploy-Policy",
                "arn:aws:iam::*:policy/GitHubActions-ECR-PushPull-Policy",
                "arn:aws:iam::*:oidc-provider/token.actions.githubusercontent.com"
            ]
        }
    ]
}
EOF

    # 11. Check/Create/Update Terraform Policy
    local terraform_policy_arn="arn:aws:iam::${account_id}:policy/${TERRAFORM_POLICY_NAME}"

    if check_policy_exists "$TERRAFORM_POLICY_NAME"; then
        log_warn "Policy '$TERRAFORM_POLICY_NAME' already exists. Creating a new version to apply updates..."

        local terraform_policy_arn_to_update=$(aws iam get-policy --policy-arn "$terraform_policy_arn" --query 'Policy.Arn' --output text)

        aws iam create-policy-version \
            --policy-arn "$terraform_policy_arn_to_update" \
            --policy-document file://terraform-permissions-policy.json \
            --set-as-default >/dev/null

        local tf_versions=$(aws iam list-policy-versions --policy-arn "$terraform_policy_arn_to_update" --query 'Versions[?IsDefaultVersion==`false`].VersionId' --output text)
        for version_id in $tf_versions; do
            log_info "Deleting old Terraform policy version: $version_id"
            aws iam delete-policy-version --policy-arn "$terraform_policy_arn_to_update" --version-id "$version_id"
        done

        log_info "✅ Terraform policy updated with new version."
    else
        log_info "Creating policy '$TERRAFORM_POLICY_NAME'..."
        aws iam create-policy \
            --policy-name "$TERRAFORM_POLICY_NAME" \
            --policy-document file://terraform-permissions-policy.json \
            --description "Allows GitHub Actions to manage the full K8s infrastructure via Terraform"
        log_info "✅ Terraform policy created"
    fi

    # 12. Attach Terraform policy to Terraform role (idempotent)
    log_info "Attaching Terraform policy to Terraform role..."
    aws iam attach-role-policy \
        --role-name "$TERRAFORM_ROLE_NAME" \
        --policy-arn "$terraform_policy_arn" 2>/dev/null || {
        log_warn "Terraform policy might already be attached (this is OK)"
    }

    # 13. Display results for both roles
    local terraform_role_arn=$(aws iam get-role --role-name "$TERRAFORM_ROLE_NAME" --query 'Role.Arn' --output text)

    log_info "🎉 Setup complete!"
    echo ""
    echo "=== ECR Role (push-to-registry job) ==="
    echo "Role ARN: $ecr_role_arn"
    echo ""
    echo "=== Terraform Role (iac-execution job with environment: production) ==="
    echo "Role ARN: $terraform_role_arn"
    echo ""
    echo "Region: $AWS_REGION"

    # Cleanup
    rm -f github-trust-policy.json ecr-permissions-policy.json terraform-trust-policy.json terraform-permissions-policy.json
}

# Execute main function
main "$@"
