from enum import Enum
from pydantic import BaseModel


class RequestedRole(str, Enum):
    """
    Liste fermee des roles temporaires que l'on peut demander
    via l'app JIT. Chaque valeur correspond exactement a un
    role IAM AWS precis.
    """
    S3_WRITE = "s3-write-access"
    S3_READ = "s3-read-access"
    


class AccessRequest(BaseModel):
    requested_role: RequestedRole   
    resource_name: str               
    ticket_id: str                    
    duration_minutes: int             


class MfaVerification(BaseModel):
    request_id: str
    otp_code: str