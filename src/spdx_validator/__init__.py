# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""SPDX 2.3 JSON validator with JSON Schema and optimized semantic validation.

This package provides comprehensive validation for SPDX 2.3 JSON documents
including both syntactic validation against the JSON schema and semantic
validation using optimized constraint checking.
"""

from spdx_validator.engine import ValidationEngine
from spdx_validator.models import SpdxDocument, ValidationResult
from spdx_validator.validators import JsonSchemaValidator, SemanticValidator

__version__ = "0.1.0"
__all__ = [
    "JsonSchemaValidator",
    "SemanticValidator",
    "SpdxDocument",
    "ValidationEngine",
    "ValidationResult",
]
