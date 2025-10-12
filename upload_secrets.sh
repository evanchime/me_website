#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
# The repository where you want to set the secrets (e.g., "owner/repo-name")
REPO="evanchime/me_website"

# Use the first argument ($1) as the secrets file.
# If $1 is not provided (is empty), default to "secrets.env".
SECRETS_FILE=${1:-"secrets.env"}

# --- Script Logic ---

# Check if the secrets file exists
if [ ! -f "$SECRETS_FILE" ]; then
    echo "Error: Secrets file not found at '$SECRETS_FILE'"
    echo "Usage: $0 [path_to_secrets_file]"
    exit 1
fi

echo "Setting secrets for repository: $REPO from file: $SECRETS_FILE"

# Read the file line by line, ignoring comments and empty lines
while IFS= read -r line || [[ -n "$line" ]]; do
    # Trim leading/trailing whitespace
    line=$(echo "$line" | xargs)

    # Ignore comments and empty lines
    if [[ "$line" == \#* ]] || [[ -z "$line" ]]; then
        continue
    fi

    # Split the line into KEY and VALUE at the first '='
    key="${line%%=*}"
    value="${line#*=}"

    echo "Setting secret: $key..."

    # Use 'gh secret set' to upload the secret.
    # The value is passed via standard input for better security.
    echo "$value" | gh secret set "$key" --repo "$REPO"
done < "$SECRETS_FILE"

echo "✅ All secrets have been set successfully for $REPO."
