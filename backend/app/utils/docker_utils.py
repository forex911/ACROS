"""
DEPRECATED — Docker socket access has been removed from Sentinel-AI.

All sandbox execution now uses Kubernetes-native Jobs via the
``kubernetes_job_manager`` module.  This file exists only to prevent
import errors in any legacy code paths still referencing ``docker_utils``.

Calling any function in this module raises RuntimeError.
"""

import warnings

warnings.warn(
    "docker_utils is deprecated. Use app.services.kubernetes_job_manager instead.",
    DeprecationWarning,
    stacklevel=2,
)


def create_container(*args, **kwargs):
    raise RuntimeError(
        "Docker socket access has been removed. "
        "Use app.services.kubernetes_job_manager.create_sandbox_job() instead."
    )


def get_seccomp_profile(*args, **kwargs):
    raise RuntimeError(
        "Docker socket access has been removed. "
        "Seccomp profiles are now applied via Kubernetes PodSecurityContext."
    )