from typing import List

# Node Labels
class NodeLabel:
    FILE = "File"
    SANDBOX_JOB = "SandboxJob"
    PROCESS = "Process"
    IP_ADDRESS = "IPAddress"
    YARA_RULE = "YARARule"
    ATTACK_TECHNIQUE = "AttackTechnique"
    DOMAIN = "Domain"
    HASH = "Hash"
    TIMELINE_STAGE = "TimelineStage"
    REGISTRY_KEY = "RegistryKey"
    PERSISTENCE_MECHANISM = "PersistenceMechanism"

# Relationship Types
class RelType:
    ANALYZES = "ANALYZES"
    SPAWNED_PROCESS = "SPAWNED_PROCESS"
    SPAWNED = "SPAWNED"
    CONNECTED_TO = "CONNECTED_TO"
    EXHIBITS_TECHNIQUE = "EXHIBITS_TECHNIQUE"
    DROPPED = "DROPPED"
    DOWNLOADED = "DOWNLOADED"
    CREATED = "CREATED"
    EXTRACTED = "EXTRACTED"
    FOLLOWED_BY = "FOLLOWED_BY"
    
    # Other observed relationships in the codebase
    MATCHES_YARA = "MATCHES_YARA"
    RESOLVED = "RESOLVED"
    QUERIED_DNS = "QUERIED_DNS"
    PRODUCED_IOC = "PRODUCED_IOC"
    HAS_STAGE = "HAS_STAGE"
    MODIFIED_REGISTRY = "MODIFIED_REGISTRY"
    INJECTED_INTO = "INJECTED_INTO"
    PERSISTED_VIA = "PERSISTED_VIA"

    @classmethod
    def all(cls) -> List[str]:
        """Returns all defined relationship type constants."""
        return [
            v for k, v in cls.__dict__.items()
            if not k.startswith("_") and isinstance(v, str)
        ]

# Accepted Artifact relationships
ARTIFACT_RELS = [
    RelType.DROPPED, 
    RelType.DOWNLOADED, 
    RelType.EXTRACTED, 
    RelType.CREATED
]
