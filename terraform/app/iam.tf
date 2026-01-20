data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    effect = "Allow"
  }
}

data "aws_iam_policy_document" "specific_cloudfront_updates" {
  statement {
    sid       = "ReadOnlyAccess"
    effect    = "Allow"
    actions   = [
      "cloudfront:List*",
      "cloudfront:Get*"
    ]
    resources = ["*"]
  }
  
  # Restrict WRITE access to our distribution only
  statement {
    sid    = "WriteToOurDistribution"
    effect = "Allow"
    actions = [
      "cloudfront:UpdateDistribution",
      "cloudfront:UpdateCloudFrontOriginAccessIdentity"
      ]
      resources = ["arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:distribution/${aws_cloudfront_distribution.me_website.id}"]
  }
}

resource "aws_iam_role" "lambda_cloudfront_updater_role" {
  name               = "lambda-cloudfront-updater-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_policy" "specific_cloudfront_updates" {
  name        = "SpecificCloudFrontUpdatesPolicy"
  description = "Allows updating only a specific CloudFront distribution"
  policy      = data.aws_iam_policy_document.specific_cloudfront_updates.json
}

resource "aws_iam_role_policy_attachment" "attach_custom_policy" {
  role       = aws_iam_role.lambda_cloudfront_updater_role.name
  policy_arn = aws_iam_policy.specific_cloudfront_updates.arn
}

resource "aws_iam_role_policy_attachment" "additional-necessary-policies" {
  role       = aws_iam_role.lambda_cloudfront_updater_role.name
  count      = length(var.iam_policy_arn)
  policy_arn = var.iam_policy_arn[count.index]
}