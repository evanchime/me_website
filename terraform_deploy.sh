#!/usr/bin/env bash

# Force the script to crash immediately if any unhandled subcommand fails
set -euo pipefail

echo "▶️ Action = ${ACTION_TYPE} | Target Workspace = ${TARGET_WS}"

# Function to execute Terraform commands with retry logic
execute_terraform_with_retry() {
  local dir="$1"
  local TF_COMMAND="$2"

  local MAX_ATTEMPTS=3
  local ATTEMPT=1
  local SUCCESS=false
  local SLEEP_SECONDS=15
  local EXIT_CODE=0

  echo "🚀 EXECUTION: Entering directory $GITHUB_WORKSPACE/terraform/$dir"
  cd "$GITHUB_WORKSPACE/terraform/$dir" && terraform init

  while [ "$ATTEMPT" -le "$MAX_ATTEMPTS" ]; do
    echo "▶️ Running 'terraform $TF_COMMAND' (Attempt $ATTEMPT of $MAX_ATTEMPTS)..."

    if terraform $TF_COMMAND; then
        echo "✅ Successfully executed configuration changes inside /$dir!"
        SUCCESS=true
        break 
    else
        EXIT_CODE=$?
        echo "⚠️ Error: 'terraform $TF_COMMAND' failed with code $EXIT_CODE."

        if [ "$ATTEMPT" -lt "$MAX_ATTEMPTS" ]; then
            echo "⏳ Potential transient network lag detected. Backing off and pausing for $SLEEP_SECONDS seconds..."
            sleep "$SLEEP_SECONDS"
            SLEEP_SECONDS=$((SLEEP_SECONDS * 2))
            ATTEMPT=$((ATTEMPT + 1))
        else
            echo "🛑 Critical: Maximum attempts reached. The failure is persistent."
            break
        fi
    fi
  done

  if [ "$SUCCESS" != "true" ]; then
    echo "::error::Terraform execution permanently failed in $dir after $MAX_ATTEMPTS attempts."
    exit 1
  fi
}

wait_for_app_load_balancer_cleanup() {
  local ingress_file="$GITHUB_WORKSPACE/terraform/app/kubernetes.tf"
  local lb_name="${APP_INGRESS_LB_NAME:-}"
  local lb_arn=""
  local describe_exit=0
  local max_checks="${APP_INGRESS_LB_CLEANUP_MAX_CHECKS:-30}"
  local check=1
  local sleep_seconds="${APP_INGRESS_LB_CLEANUP_SLEEP_SECONDS:-20}"
  local total_wait_time=$((max_checks * sleep_seconds))

  if [[ -z "$lb_name" ]]; then
    if [[ ! -f "$ingress_file" ]]; then
      echo "::error::APP_INGRESS_LB_NAME is not set and '$ingress_file' is unavailable for discovery."
      exit 1
    fi

    # Extract the fixed ingress annotation value:
    # "alb.ingress.kubernetes.io/load-balancer-name" = "<name>"
    lb_name=$(sed -n 's/.*"alb\.ingress\.kubernetes\.io\/load-balancer-name"[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$ingress_file" | head -n 1)

    if [[ -z "$lb_name" ]]; then
      echo "::error::Unable to discover the app ingress load balancer name from '$ingress_file'."
      exit 1
    fi

    echo "ℹ️ APP_INGRESS_LB_NAME not set. Discovered '$lb_name' from terraform/app/kubernetes.tf."
  fi

  if lb_arn=$(aws elbv2 describe-load-balancers \
    --names "$lb_name" \
    --query 'LoadBalancers[0].LoadBalancerArn' \
    --output text 2>/dev/null); then
    describe_exit=0
  else
    describe_exit=$?
    lb_arn=""
  fi

  if [[ $describe_exit -ne 0 || -z "$lb_arn" || "$lb_arn" == "None" ]]; then
    echo "ℹ️ No remaining ALB named '$lb_name' detected after app destroy."
    return 0
  fi

  echo "🗑️ Requesting deletion of controller-managed ALB '$lb_name' before platform destroy removes the AWS Load Balancer Controller..."
  if ! aws elbv2 delete-load-balancer --load-balancer-arn "$lb_arn" >/dev/null 2>&1; then
    echo "⚠️ Unable to request ALB deletion for '$lb_name'. Continuing to poll in case cleanup is already in progress."
  fi

  while [[ $check -le $max_checks ]]; do
    if lb_arn=$(aws elbv2 describe-load-balancers \
      --names "$lb_name" \
      --query 'LoadBalancers[0].LoadBalancerArn' \
      --output text 2>/dev/null); then
      describe_exit=0
    else
      describe_exit=$?
      lb_arn=""
    fi

    if [[ $describe_exit -ne 0 || -z "$lb_arn" || "$lb_arn" == "None" ]]; then
      echo "✅ ALB '$lb_name' has been removed."
      return 0
    fi

    echo "⏳ ALB '$lb_name' still exists. Rechecking in ${sleep_seconds}s (${check}/${max_checks})..."
    sleep "$sleep_seconds"
    check=$((check + 1))
  done

  echo "::error::ALB '$lb_name' still exists after ${max_checks} checks (${total_wait_time}s). Manually verify it and, if needed, delete it with: aws elbv2 delete-load-balancer --load-balancer-arn <alb-arn>."
  exit 1
}

# Initialize the execution flags to false by default
RUN_NET=false 
RUN_EKS=false
RUN_PLAT=false
RUN_APP=false

if [[ "${ACTION_TYPE}" == "destroy" ]]; then
  TF_COMMAND="destroy -auto-approve -input=false -lock-timeout=3m"

  if [[ "${TARGET_WS}" == "all" ]]; then
    echo "⚠️ Full teardown initiated! Destroy order: app → platform → EKS → network."
    WORKSPACE_ORDER="app platform eks network"
    RUN_APP=true; RUN_PLAT=true; RUN_EKS=true; RUN_NET=true

  elif [[ "${TARGET_WS}" == "network" ]]; then
    echo "⚠️ Target Destroy: Network foundation. Cascading through app, platform, EKS, then network."
    WORKSPACE_ORDER="app platform eks network"
    RUN_APP=true; RUN_PLAT=true; RUN_EKS=true; RUN_NET=true

  elif [[ "${TARGET_WS}" == "eks" ]]; then
    echo "⚠️ Target Destroy: EKS. Must tear down downstream Platform and App layer first."
    WORKSPACE_ORDER="app platform eks"
    RUN_APP=true; RUN_PLAT=true; RUN_EKS=true

  elif [[ "${TARGET_WS}" == "platform" ]]; then
    echo "⚠️ Target Destroy: Platform. Must tear down downstream App layer first."
    WORKSPACE_ORDER="app platform"
    RUN_APP=true; RUN_PLAT=true
    
  elif [[ "${TARGET_WS}" == "app" ]]; then
    echo "⚠️ Target Destroy: App only."
    WORKSPACE_ORDER="app"
    RUN_APP=true
    
  else
    echo "🛑 Error: Invalid destroy target '${TARGET_WS}'. Valid targets are: all, network, eks, platform, app."
    exit 1
  fi

else
  TF_COMMAND="apply -auto-approve -input=false -lock-timeout=3m"
  WORKSPACE_ORDER="network eks platform app"

  if [[ "${TARGET_WS}" == "all" ]]; then
    echo "🔄 Standard CI/CD Run: Evaluating which directories contain modified files."
    if [[ "${CHG_NET}" == "true" ]]; then RUN_NET=true; fi
    if [[ "${CHG_EKS}" == "true" || "${RUN_NET}" == "true" ]]; then RUN_EKS=true; fi
    if [[ "${CHG_PLAT}" == "true" || "${RUN_EKS}" == "true" ]]; then RUN_PLAT=true; fi
    if [[ "${CHG_APP}" == "true" || "${RUN_PLAT}" == "true" ]]; then RUN_APP=true; fi
    
  else
    echo "🎯 Targeted Manual Override Apply: Executing starting from layer '${TARGET_WS}'."
    if [[ "${TARGET_WS}" == "network" ]];  then RUN_NET=true; RUN_EKS=true; RUN_PLAT=true; RUN_APP=true; fi
    if [[ "${TARGET_WS}" == "eks" ]];      then RUN_EKS=true; RUN_PLAT=true; RUN_APP=true; fi
    if [[ "${TARGET_WS}" == "platform" ]]; then RUN_PLAT=true; RUN_APP=true; fi
    if [[ "${TARGET_WS}" == "app" ]];      then RUN_APP=true; fi
  fi
fi

for dir in $WORKSPACE_ORDER; do
  SHOULD_RUN=false
  
  if [[ "$dir" == "network"  && "${RUN_NET}" == "true" ]];  then SHOULD_RUN=true; fi
  if [[ "$dir" == "eks"      && "${RUN_EKS}" == "true" ]];  then SHOULD_RUN=true; fi
  if [[ "$dir" == "platform" && "${RUN_PLAT}" == "true" ]]; then SHOULD_RUN=true; fi
  if [[ "$dir" == "app"      && "${RUN_APP}" == "true" ]];  then SHOULD_RUN=true; fi


  if [ "$SHOULD_RUN" == "true" ]; then
    # 1. SPECIAL CASE: Recreate Grafana token if skipping standard platform apply but running app
    if [[ "${ACTION_TYPE}" != "destroy" && "${RUN_PLAT}" == "false" && "${RUN_APP}" == "true" ]]; then
      echo "🔄 Special Trigger: App is running but Platform was bypassed. Force-refreshing Grafana Provider Token..."
      
      execute_terraform_with_retry "platform" "apply -auto-approve -input=false -lock-timeout=3m -replace=aws_grafana_workspace_service_account_token.grafana_provider_token"
      
      echo "✅ Grafana token refresh sequence complete. Proceeding to standard App deployment."
      execute_terraform_with_retry "$dir" "$TF_COMMAND"

    # 2. SPECIAL CASE: Refresh Grafana token before destroying app to avoid expired token 401 errors
    elif [[ "${ACTION_TYPE}" == "destroy" && "$dir" == "app" ]]; then
      echo "🔄 Pre-Destroy Token Refresh: Refreshing Grafana Provider Token before app destroy..."
      
      execute_terraform_with_retry "platform" "apply -auto-approve -input=false -lock-timeout=3m -replace=aws_grafana_workspace_service_account_token.grafana_provider_token"
      
      echo "✅ Grafana token refreshed. Proceeding with app destroy."
      execute_terraform_with_retry "$dir" "$TF_COMMAND"
      wait_for_app_load_balancer_cleanup

    # 3. STANDARD CASE: Run the folder normally
    else
      execute_terraform_with_retry "$dir" "$TF_COMMAND"
    fi

    if [[ "$dir" == "network" && "${ACTION_TYPE}" != "destroy" ]]; then
      echo "🔄 network apply complete. Syncing CDN HTML Error Pages..."
      CDN_BUCKET_NAME=$(terraform output -raw s3_error_pages_bucket)
      aws s3 sync ./errors/ s3://"$CDN_BUCKET_NAME"/errors/ --delete --cache-control "max-age=31536000, public"
    fi

    cd "$GITHUB_WORKSPACE"
  else
    echo ">>>> ⏭️ BYPASS: Skipping folder terraform/$dir <<<<"
  fi
done
