import boto3 #type: ignore
import os
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

cloudfront = boto3.client("cloudfront")

TARGET_ORIGIN_ID = os.environ["ALB_TARGET_ORIGIN_ID"]
DISTRIBUTION_ID = os.environ["CLOUDFRONT_DISTRIBUTION_ID"]
PLACEHOLDER_DOMAIN = os.environ.get(
    "ALB_TARGET_PLACEHOLDER_DOMAIN", "placeholder.example.com"
)

def lambda_handler(event, context):
    # Extract ALB DNS from EventBridge event
    try:
        lb = (
            event.get("detail", {})
            .get("responseElements", {})
            .get("loadBalancers", [])[0]
        )
        alb_dns = lb["DNSName"]

        logger.info(
            "Extracted ALB DNS",
            extra={"alb_dns": alb_dns, "event": event}
        )

    except Exception as e:
        logger.error(
            "Failed to extract ALB DNS", 
            extra={"error": str(e), "event": event}
        )
        raise

    # Fetch current CloudFront config
    response = cloudfront.get_distribution_config(Id=DISTRIBUTION_ID)
    etag = response["ETag"]
    config = response["DistributionConfig"]

    origins = config["Origins"]["Items"]

    # Find the target origin
    origin = next((o for o in origins if o["Id"] == TARGET_ORIGIN_ID), None)

    if not origin:
        origin_ids = [o["Id"] for o in origins]
        logger.error(
            "Target origin not found",
            extra={"expected": TARGET_ORIGIN_ID, "available": origin_ids}
        )
        raise ValueError(f"Origin '{TARGET_ORIGIN_ID}' not found")

    old_domain = origin["DomainName"]

    # Determine if update is needed
    if old_domain == alb_dns:
        logger.info(
            "No update needed; ALB DNS unchanged", 
            extra={"alb_dns": alb_dns}
        )
        return {"statusCode": 200, "body": "No update needed"}

    # First-time update (placeholder → real ALB DNS)
    if old_domain == PLACEHOLDER_DOMAIN:
        logger.info(
            "Performing first-time ALB origin update",
            extra={"old_domain": old_domain, "new_domain": alb_dns}
        )
    else:
        logger.info(
            "Updating ALB origin DNS",
            extra={"old_domain": old_domain, "new_domain": alb_dns}
        )

    # Apply update
    origin["DomainName"] = alb_dns

    cloudfront.update_distribution(
        Id=DISTRIBUTION_ID,
        IfMatch=etag,
        DistributionConfig=config
    )

    logger.info("CloudFront distribution updated successfully")

    return {
        "statusCode": 200,
        "body": f"Updated CloudFront origin to {alb_dns}"
    }