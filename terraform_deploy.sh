#!/usr/bin/env bash

# Force the script to crash immediately if any unhandled subcommand fails
set -euo pipefail

echo "▶️ Action = ${ACTION_TYPE} | Target Workspace = ${TARGET_WS}"

# Initialize the execution flags to false by default
RUN_NET=false 
RUN_EKS=false
RUN_PLAT=false
RUN_APP=false

if [[ "${ACTION_TYPE}" == "destroy" ]]; then
  TF_COMMAND="destroy -auto-approve -input=false -lock-timeout=3m"

  if [[ "${TARGET_WS}" == "all" || "${TARGET_WS}" == "network" ]]; then
    echo "⚠️ Full teardown initiated! Reversing sequence order."
    WORKSPACE_ORDER="app platform eks network"
    RUN_APP=true; RUN_PLAT=true; RUN_EKS=true; RUN_NET=true

  elif [[ "${TARGET_WS}" == "eks" ]]; then
    echo "⚠️ Target Destroy: Eks. Must tear down downstream Platform and App layer first."
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
    echo "🛑 Error: Destroying '${TARGET_WS}' directly is blocked. You must destroy 'all', 'network', 'platform', or 'app'."
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
    echo "🚀 EXECUTION: Entering directory $GITHUB_WORKSPACE/terraform/$dir"
    cd "$GITHUB_WORKSPACE/terraform/$dir" && terraform init
    
    MAX_ATTEMPTS=3
    ATTEMPT=1
    SUCCESS=false
    SLEEP_SECONDS=15 

    while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
      echo "▶️ Running 'terraform $TF_COMMAND' (Attempt $ATTEMPT of $MAX_ATTEMPTS)..."
      
      set +e 
      terraform $TF_COMMAND
      EXIT_CODE=$?
      set -e 
      
      if [ $EXIT_CODE -eq 0 ]; then
        echo "✅ Successfully applied configuration state changes inside /$dir!"
        SUCCESS=true
        break 
      else
        echo "⚠️ Error: 'terraform $TF_COMMAND' failed with code $EXIT_CODE."
        
        if [ $ATTEMPT -lt $MAX_ATTEMPTS ]; then
          echo "⏳ Potential transient network lag detected. Backing off and pausing for $SLEEP_SECONDS seconds..."
          sleep $SLEEP_SECONDS
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
