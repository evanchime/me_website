import boto3  # type: ignore
import os
import logging

logger = logging.getLogger()

CloudfrontClient = boto3.client('cloudfront')


def lambda_handler(event, context):
    # Extract load balancer information
    try:
        load_balancers = (
            event.get('detail', {})
            .get('responseElements', {})
            .get('loadBalancers', [])
        )
        
        if not load_balancers:
            logger.error(
                "No load balancers found in event", 
                extra={"event": event}
            )
            raise ValueError("No load balancers found in event")
        
        first_load_balancer = load_balancers[0]
        load_balancer_name = first_load_balancer['loadBalancerName']
        load_balancer_dns_name = first_load_balancer['DNSName']
        
        logger.info(
            "Successfully extracted load balancer details",
            extra={
                "loadBalancerName": load_balancer_name,
                "DNSName": load_balancer_dns_name
            }
        )
        
    except KeyError as e:
        logger.error(
            f"Missing expected key in load balancer data: {e}", 
            extra={"event": event}
        )
        raise
    except (IndexError, TypeError, ValueError) as e:
        logger.error(
            f"Error processing event structure: {e}", 
            extra={"event": event}
        )
        raise
    
    # Get CloudFront distribution ID from environment variable
    distribution_id = os.environ['cloudfront_distribution_id']
    
    # Get current CloudFront distribution configuration
    try:
        response = CloudfrontClient.get_distribution_config(
            Id=distribution_id
        )
        etag = response["ETag"]
        distribution_config = response["DistributionConfig"]
        
        # Directly access the origins list
        origins = distribution_config["Origins"]["Items"]
        
        # Look for the origin with exact match to load balancer name
        origin_found = False
        for origin in origins:
            origin_id = origin["Id"]
            
            if origin_id == load_balancer_name:
                logger.info(
                    f"Found exact match for origin: {origin_id}",
                    extra={
                        "loadBalancerName": load_balancer_name,
                        "originId": origin_id
                    }
                )
                
                # Check if update is actually needed
                if origin["DomainName"] == load_balancer_dns_name:
                    logger.info(
                        f"No update needed. Domain already set to "
                        f"{load_balancer_dns_name}"
                    )
                    return {
                        'statusCode': 200,
                        'body': (
                            f'No update needed for CloudFront distribution '
                            f'"{distribution_id}"'
                        )
                    }
                
                # Store old domain name for logging
                old_domain = origin["DomainName"]
                
                # Update the domain name in the origin
                origin["DomainName"] = load_balancer_dns_name
                
                logger.info(
                    f"Updating origin domain from {old_domain} to "
                    f"{load_balancer_dns_name}"
                )
                
                # Update the distribution
                CloudfrontClient.update_distribution(
                    DistributionConfig=distribution_config,
                    Id=distribution_id,
                    IfMatch=etag
                )
                
                logger.info(
                    f"Successfully updated CloudFront distribution "
                    f"{distribution_id}"
                )
                origin_found = True
                break
        
        if not origin_found:
            # Log all available origins for debugging
            origin_ids = [origin["Id"] for origin in origins]
            logger.error(
                f"No origin found with ID exactly matching "
                f"'{load_balancer_name}'",
                extra={
                    "expectedOriginId": load_balancer_name,
                    "availableOriginIds": origin_ids,
                    "distributionId": distribution_id
                }
            )
            raise ValueError(
                f"No origin found with ID '{load_balancer_name}'. "
                f"Available origin IDs: {', '.join(origin_ids)}"
            )
            
    except CloudfrontClient.exceptions.NoSuchDistribution:
        logger.error(f"CloudFront distribution {distribution_id} not found")
        raise
    except CloudfrontClient.exceptions.PreconditionFailed:
        logger.error(
            f"ETag mismatch for distribution {distribution_id}. "
            f"Configuration was modified concurrently."
        )
        raise
    except Exception as e:
        logger.error(
            f"Error updating CloudFront distribution: {str(e)}",
            extra={"distributionId": distribution_id}
        )
        raise
    
    return {
        'statusCode': 200,
        'body': f'Successfully updated CloudFront distribution {distribution_id}'
    }