# lambda_function.py
import base64
import boto3
import logging
import os
import json
import requests
from datetime import time
from botocore.signers import RequestSigner
from kubernetes import client
from kubernetes.client import V1ObjectMeta, ApiClient
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
secrets_client = boto3.client('secretsmanager')
cloudfront_client = boto3.client('cloudfront')

# Global cache
_cached_k8s_client = None
_cached_token = None
_cached_token_timestamp = None
_cached_cluster_name = None

# Refresh slightly before the 15‑minute expiry
TOKEN_TTL_SECONDS = 14 * 60  

# --- Helper Functions ---
def get_pending_secret(service_client, arn, token):
    """Retrieve the value of the AWSPENDING secret."""
    get_secret_value_response = service_client.get_secret_value(
        SecretId=arn,
        VersionId=token,
        VersionStage='AWSPENDING'
    )
    return get_secret_value_response['SecretString']

def update_cloudfront_header(secret_value):
    """
    Updates the custom header in the CloudFront distribution.
    Based on your bash script logic.
    """
    distribution_id = os.environ['CLOUDFRONT_DISTRIBUTION_ID']
    origin_domain = os.environ['CLOUDFRONT_ORIGIN_DOMAIN']
    header_name = os.environ.get('CUSTOM_HEADER_NAME', 'X-Secret')

    logger.info(
        f"Updating CloudFront {distribution_id}, origin {origin_domain}"
    )

    # Get current config and ETag
    try:
        dist_response = cloudfront_client.get_distribution(Id=distribution_id)
    except Exception as e:
        logger.error(f"Failed to get CloudFront config: {e}")
        raise

    etag = dist_response['ETag']
    config = dist_response['Distribution']['DistributionConfig']

    # Find the target origin and update/add the custom header
    origin_updated = False
    for item in config['Origins']['Items']:
        if item['DomainName'] == origin_domain:
            logger.info(f"Found matching origin: {item['Id']}")

            # Ensure CustomHeaders structure exists
            if 'CustomHeaders' not in item:
                item['CustomHeaders'] = {'Quantity': 0, 'Items': []}

            headers = item['CustomHeaders']
            header_items = headers.get('Items', [])

            # Check if our header already exists
            header_found = False
            for header in header_items:
                if header['HeaderName'] == header_name:
                    header['HeaderValue'] = secret_value
                    header_found = True
                    logger.info(f"Updated existing header '{header_name}'")
                    break

            # If header doesn't exist, add it
            if not header_found:
                header_items.append({
                    'HeaderName': header_name,
                    'HeaderValue': secret_value
                })
                logger.info(f"Added new header '{header_name}'")

            # Update counts
            headers['Items'] = header_items
            headers['Quantity'] = len(header_items)
            origin_updated = True
            break

    if not origin_updated:
        error_msg = f"Could not find origin with domain: {origin_domain}"
        logger.error(error_msg)
        raise ValueError(error_msg)

    # Apply the updated configuration
    try:
        cloudfront_client.update_distribution(
            Id=distribution_id,
            IfMatch=etag,
            DistributionConfig=config
        )
        logger.info("CloudFront distribution update initiated successfully")
    except Exception as e:
        logger.error(f"Failed to update CloudFront: {e}")
        # Specific handling for precondition failure
        if "PreconditionFailed" in str(e):
            logger.error("ETag mismatch - configuration changed concurrently")
        raise

    # 4. Wait for deployment (optional but recommended)
    logger.info("Waiting for CloudFront deployment...")
    waiter = cloudfront_client.get_waiter('distribution_deployed')
    waiter.wait(
        Id=distribution_id, WaiterConfig={'Delay': 30, 'MaxAttempts': 60}
    )
    logger.info("CloudFront deployment complete")
    
class EKSClientCache:
    TOKEN_TTL_SECONDS = 14 * 60  # refresh before 15‑minute expiry

    def __init__(self):
        self.k8s_client = None
        self.token = None
        self.token_timestamp = None
        self.cluster_name = None

    def get_cluster_info(self, cluster_name):
        eks = boto3.client("eks")
        cluster = eks.describe_cluster(name=cluster_name)["cluster"]

        endpoint = cluster["endpoint"]
        ca_data = cluster["certificateAuthority"]["data"]
        ca_cert = base64.b64decode(ca_data)

        return endpoint, ca_cert, cluster["name"]

    def generate_token(self):
        session = boto3.session.Session()
        sts = session.client("sts")

        signer = RequestSigner(
            sts.meta.service_model.service_name,
            session.region_name,
            sts._request_signer._credentials,
            sts._request_signer._event_emitter
        )

        url = signer.generate_presigned_url(
            request_dict={
                "method": "GET",
                "url": f"https://sts.{session.region_name}.amazonaws.com/",
                "headers": {},
                "body": ""
            },
            operation_name="GetCallerIdentity",
            expires_in=60,
            region_name=session.region_name
        )

        return (
            "k8s-aws-v1." + 
            base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        )

    def token_expired(self):
        if self.token_timestamp is None:
            return True
        return (time.time() - self.token_timestamp) > self.TOKEN_TTL_SECONDS

    def get_client(self, cluster_name):
        # Reuse if valid
        if (
            self.k8s_client
            and self.cluster_name == cluster_name
            and not self.token_expired()
        ):
            return self.k8s_client

        # Otherwise rebuild
        endpoint, ca_cert, _ = self.get_cluster_info(cluster_name)
        token = self.generate_token()

        ca_path = "/tmp/ca.crt"
        if not os.path.exists(ca_path):
            with open(ca_path, "wb") as f:
                f.write(ca_cert)

        cfg = client.Configuration()
        cfg.host = endpoint
        cfg.verify_ssl = True
        cfg.ssl_ca_cert = ca_path
        cfg.api_key = {"authorization": "Bearer " + token}

        api_client = ApiClient(cfg)

        # Update cache
        self.k8s_client = client.NetworkingV1Api(api_client)
        self.token = token
        self.token_timestamp = time.time()
        self.cluster_name = cluster_name

        return self.k8s_client

eks_cache = EKSClientCache()


def update_kubernetes_ingress(secret_value):
    """
    Patches the Kubernetes Ingress annotation with the new secret value.
    """
    ingress_name = os.environ['K8S_INGRESS_NAME']
    ingress_namespace = os.environ['K8S_INGRESS_NAMESPACE']
    header_name = os.environ.get('CUSTOM_HEADER_NAME', 'X-Secret')
    
    k8s_api = eks_cache.get_client(os.environ["CLUSTER_NAME"])

    annotation_key = "alb.ingress.kubernetes.io/conditions.secure-rule"

    # Build the new condition JSON
    new_condition = json.dumps([{
        "field": "http-header",
        "httpHeaderConfig": {
            "httpHeaderName": header_name,
            "values": [secret_value]
        }
    }])

    try:
        # Read the existing ingress
        ingress = k8s_api.read_namespaced_ingress(
            name=ingress_name,
            namespace=ingress_namespace
        )

        # Ensure metadata and annotations exist
        if ingress.metadata is None:
            ingress.metadata = V1ObjectMeta()

        if ingress.metadata.annotations is None:
            ingress.metadata.annotations = {}

        # Modify only the annotation we care about
        ingress.metadata.annotations[annotation_key] = new_condition

        # Patch the ingress with the updated metadata
        patch_body = {
            "metadata": {
                "annotations": ingress.metadata.annotations
            }
        }

        k8s_api.patch_namespaced_ingress(
            name=ingress_name,
            namespace=ingress_namespace,
            body=patch_body
        )

        logger.info(
            f"Successfully patched Ingress {ingress_namespace}/{ingress_name}"
        )

    except Exception as e:
        logger.error(
            f"Failed to patch Ingress {ingress_namespace}/{ingress_name}: {e}"
        )
        raise

# --- Secrets Manager Template Functions ---
def create_secret(service_client, arn, token):
    """Generate a new secret (if not already created)."""
    # Make sure the current secret exists
    service_client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")
    # Now try to get the secret version, if that fails, put a new secret
    try:
        # Only do VersionId validation against the stage if a token is 
        # passed in
        if token:
            service_client.get_secret_value(
                SecretId=arn, VersionId=token, VersionStage='AWSPENDING'
            )
        else:
            service_client.get_secret_value(
                SecretId=arn, VersionStage='AWSPENDING'
            )
            logger.info(
                f"createSecret: Successfully retrieved secret for {arn}"
            )
    except service_client.exceptions.ResourceNotFoundException:
        # Generate new password (preserving your existing character exclusion)
        exclude_chars = os.environ.get('EXCLUDE_CHARACTERS', '/@"\'\\')
        random_pwd = service_client.get_random_password(
            PasswordLength=32,
            ExcludeCharacters=exclude_chars
        )

        # Put the new secret as AWSPENDING
        service_client.put_secret_value(
            SecretId=arn,
            ClientRequestToken=token,
            SecretString=random_pwd['RandomPassword'],
            VersionStages=['AWSPENDING']
        )
        logger.info(
            f"createSecret: Successfully put secret for {arn} and "
            f"version {token}."
        )

def set_secret(service_client, arn, token):
    """THE CORE FUNCTION: Update both CloudFront and Kubernetes."""
    logger.info(f"setSecret: Starting deployment of new secret for {arn}")
    
    #Get the new secret value
    new_secret_value = get_pending_secret(service_client, arn, token)
    
    # Update CloudFront
    update_cloudfront_header(new_secret_value)
    
    # Update Kubernetes Ingress
    update_kubernetes_ingress(new_secret_value)
    
    logger.info("setSecret: Successfully deployed new secret to all systems")


def test_secret(service_client, arn, token):
    """
    Validation that the new secret works. CloudFront Distribution is 
    reachable and using the new header.
    """
    logger.info(f"testSecret: Starting comprehensive validation for {arn}")
    
    # 1. Retrieve the new secret value and configuration
    new_secret_value = get_pending_secret(service_client, arn, token)
    distribution_id = os.environ['CLOUDFRONT_DISTRIBUTION_ID']
    header_name = os.environ.get('CUSTOM_HEADER_NAME', 'X-Secret')
    
    # Get CloudFront distribution details to find its domain name
    try:
        dist_detail = cloudfront_client.get_distribution(Id=distribution_id)
        cloudfront_domain = dist_detail['Distribution']['DomainName']
        logger.info(
            f"testSecret: "
            f"Testing against CloudFront domain: {cloudfront_domain}"
        )
    except Exception as e:
        logger.error(
            f"testSecret: Failed to get CloudFront distribution details: {e}"
        )
        raise

    # Test CloudFront with the New Secret
    logger.info("testSecret: Testing CloudFront endpoint with new secret...")
    
    # Configure a retry strategy for transient network issues
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session = requests.Session()
    session.mount("https://", adapter)

    try:
        ssm_client = boto3.client('ssm')
        param = ssm_client.get_parameter(
            Name='/me_website/prod/HEALTH_CHECK_SECRET', WithDecryption=True
        )
        health_check_secret = param['Parameter']['Value']
    except Exception as e:
        logger.error(
            f"FAILED to retrieve HEALTH_CHECK_SECRET "
            f"from SSM Parameter Store: {e}")
        raise e 
   
    test_headers = {
        header_name: new_secret_value,
        'X-Health-Check-Secret': health_check_secret,
        'User-Agent': 'AWS-Secrets-Manager-Rotation-Test/1.0'
    }
    
    # Try to reach a known, lightweight endpoint (e.g., health check)
    # Use the CloudFront domain, not the ALB domain directly.
    test_url = f"https://{cloudfront_domain}/ht/"
    
    try:
        # Use a relatively short timeout; we will retry
        response = session.get(test_url, headers=test_headers, timeout=10)
        # Raises an HTTPError for bad status (4xx or 5xx)
        response.raise_for_status()  

        # Parse the JSON and check the status field
        health_data = response.json()
        if health_data.get("status") == "healthy":
            logger.info(
                f"testSecret: SUCCESS - CloudFront & ALB responded "
                f"with status {response.status_code}. Application health "
                f"check PASSED. Status is 'healthy'."
            )
            return True
        else:
            status_received = health_data.get("status", "Status key not found")
            raise ValueError(
                f"Application health check FAILED. "
                f"Status was '{status_received}'."
            )
        
    except requests.exceptions.HTTPError as e:
        # Specific handling for 403/404 which likely indicates header 
        # rejection
        if e.response.status_code in [403, 404]:
            error_msg = (
                f"CloudFront/ALB rejected the request "
                f"(HTTP {e.response.status_code}). This strongly indicates "
                f"the new secret '{header_name}' header value was not accepted. "
                f"Check: 1) ALB listener rules, 2) Header name spelling."
            )
            logger.error(f"testSecret: {error_msg}")
            # Log the response body for more clues if safe
            logger.error(f"testSecret: Response body: {e.response.text[:500]}")
        else:
            error_msg = f"HTTP error testing CloudFront: {e}"
            logger.error(f"testSecret: {error_msg}")
        raise
    except requests.exceptions.ConnectionError as e:
        error_msg = (
            f"Failed to connect to CloudFront domain {cloudfront_domain}. "
            f"Check: 1) Distribution is deployed, 2) DNS is resolving."
        )
        logger.error(f"testSecret: {error_msg}. Underlying error: {e}")
        raise
    except requests.exceptions.Timeout as e:
        error_msg = (
            "Request to CloudFront timed out. "
            "The ALB or application might be unreachable or slow."
        )
        logger.error(f"testSecret: {error_msg}")
        raise
    except requests.exceptions.RequestException as e:
        error_msg = f"Unexpected network error testing CloudFront: {e}"
        logger.error(f"testSecret: {error_msg}")
        raise


def finish_secret(service_client, arn, token):
    """Finalize rotation by marking new version as AWSCURRENT."""
    # First describe the secret to get current version
    metadata = service_client.describe_secret(SecretId=arn)
    
    # Check if already current
    if "AWSCURRENT" in metadata['VersionIdsToStages'].get(token, []):
        logger.info(f"finishSecret: Version {token} already AWSCURRENT")
        return
    
    # Find current version to remove
    current_version = None
    for version, stages in metadata['VersionIdsToStages'].items():
        if "AWSCURRENT" in stages and version != token:
            current_version = version
            break
    
    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(
        SecretId=arn,
        VersionStage='AWSCURRENT',
        MoveToVersionId=token,
        RemoveFromVersionId=current_version
    )
    logger.info(
        f"finishSecret: Successfully set AWSCURRENT stage to "
        f"version {token} for secret {arn}."
    )

# --- Main Handler (AWS Template) ---
def lambda_handler(event, context):
    """Main Lambda handler - follows AWS Secrets Manager template."""
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']
    
    logger.info(f"Starting step '{step}' for secret {arn}")
    
    # Validate rotation is enabled and token is at correct stage
    metadata = secrets_client.describe_secret(SecretId=arn)
    if "RotationEnabled" in metadata and not metadata['RotationEnabled']:
        logger.error(f"Secret {arn} is not enabled for rotation")
        raise ValueError(f"Secret {arn} is not enabled for rotation")
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        logger.error(
            f"Secret version {token} has no stage for rotation of "
            f"secret {arn}."
        )
        raise ValueError(
            f"Secret version {token} has no stage for rotation of "
            f"secret {arn}."
        )
    if "AWSCURRENT" in versions[token]:
        logger.info(
            f"Secret version {token} already set as AWSCURRENT "
            f"for secret {arn}."
        )
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error(
            f"Secret version {token} not set as AWSPENDING for "
            f"rotation of secret {arn}."
        )
        raise ValueError(
            f"Secret version {token} not set as AWSPENDING for "
            f"rotation of secret {arn}."
        )
    
    # Route to appropriate step
    if step == "createSecret":
        create_secret(secrets_client, arn, token)
    elif step == "setSecret":
        set_secret(secrets_client, arn, token)
        # Wait for 10s to allow propagation of the newly set AWSPENDING 
        # secret as the new secret
        time.sleep(10)
    elif step == "testSecret":
        test_secret(secrets_client, arn, token)
    elif step == "finishSecret":
        finish_secret(secrets_client, arn, token)
    else:
        raise ValueError(f"Invalid step: {step}")
    
    return {
        "statusCode": 200, 
        "body": json.dumps(f"Step {step} completed successfully")
    }