#!/bin/bash
set -e

# Configuration
GITHUB_USERNAME="evanchime"
GITHUB_REPO="me_website"
AWS_REGION="eu-west-2"
ECR_REPO_NAME="me_website"
ROLE_NAME="GitHubActions-ECR-Role"
POLICY_NAME="GitHubActions-ECR-PushPull-Policy"

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
    
    # 7. Display results
    local role_arn=$(aws iam get-role --role-name "$ROLE_NAME" --query 'Role.Arn' --output text)
    
    log_info "🎉 Setup complete!"
    echo ""
    echo "Role ARN: $role_arn"
    echo "Region: $AWS_REGION"
    echo ""
    echo "Add these to your GitHub workflow:"
    echo "  role-to-assume: $role_arn"
    echo "  aws-region: $AWS_REGION"
    
    # Cleanup
    rm -f github-trust-policy.json ecr-permissions-policy.json
}

# Execute main function
main "$@"
