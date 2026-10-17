"""
Service AWS .
Emet des credentials AWS temporaires via STS AssumeRole, en fonction
du role demande par l'utilisateur .

"""
import os
import boto3

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
AWS_BUCKET_NAME = os.getenv("AWS_BUCKET_NAME")

# Correspondance : role demande par l'app JIT -> ARN du role IAM a endosser
ROLE_ARN_MAP = {
    "s3-write-access": os.getenv("AWS_ROLE_ARN_S3_WRITE"),
    "s3-read-access": os.getenv("AWS_ROLE_ARN_S3_READ"),
}


def _sts_client():
    return boto3.client(
        "sts",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION,
    )


def assume_role_for_request(requested_role: str, ticket_id: str, duration_minutes: int) -> dict:
    """
    Endosse le role IAM correspondant au requested_role.

    Renvoie les credentials temporaires (access_key, secret_key,
    session_token, expiration) a transmettre a l'utilisateur.
    """
    role_arn = ROLE_ARN_MAP.get(requested_role)
    if role_arn is None:
        raise ValueError(f"Aucun role IAM associe a '{requested_role}'")

    duration_seconds = max(duration_minutes * 60, 900)  # 900s = minimum impose par AWS STS

    response = _sts_client().assume_role(
        RoleArn=role_arn,
        RoleSessionName=f"jit-{ticket_id}",
        DurationSeconds=duration_seconds,
    )

    creds = response["Credentials"]
    return {
        "access_key": creds["AccessKeyId"],
        "secret_key": creds["SecretAccessKey"],
        "session_token": creds["SessionToken"],
        "expiration": creds["Expiration"].isoformat(),
    }