# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Configuration system for SBOM-Check."""

from sbom_check.config.loader import ConfigLoader
from sbom_check.config.models import SbomCheckConfig

__all__ = [
    "ConfigLoader",
    "SbomCheckConfig",
]
