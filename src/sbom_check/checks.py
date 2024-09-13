# Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

"""SBOM Check library."""

import json
import logging
from dataclasses import dataclass
from typing import Any

from license_expression import LicenseExpression
from spdx_tools.spdx.model.document import CreationInfo, Document
from spdx_tools.spdx.model.file import File
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.parser.error import SPDXParsingError
from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import (
    JsonLikeDictParser,
)
from spdx_tools.spdx.validation.document_validator import (
    SpdxElementType,
    ValidationContext,
    ValidationMessage,
    validate_full_spdx_document,
)

logger = logging.getLogger(__name__)

COMPLETENESS_EXCEPTION = "\n*** completeness exception ***\n"
SPDX_VERSIONS = ["SPDX-2.3"]

# CSV header fields
SPDX_ID = "spdx_id"
PARENT_ID = "parent_id"
ELEMENT_TYPE = "element_type"
MESSAGE = "message"

CSV_HEADER = [SPDX_ID, PARENT_ID, ELEMENT_TYPE, MESSAGE]


@dataclass(frozen=True, slots=True)
class CheckResult:
    """SBOM check results for an SPDX document."""

    _validation_messages: list[ValidationMessage]
    errors: list[str]

    @property
    def is_valid(self) -> bool:
        """
        Return true if any errors or validation issues were detected.
        """
        return any([self._validation_messages, self.errors])

    @property
    def validation_messages(self) -> list[dict[str, str]]:
        """
        Return a list of validation message dicts.
        """
        return [
            _validation_message_to_dict(message)
            for message in self._validation_messages
        ]

    @property
    def csv_rows(self) -> list[list[str]]:
        """Returns csv header and rows populated with SBOM check results."""
        return [CSV_HEADER] + [
            [
                message[SPDX_ID],
                message[PARENT_ID],
                message[ELEMENT_TYPE],
                message[MESSAGE].replace("\n", ""),
            ]
            for message in self.validation_messages
        ]


def _validation_message_to_dict(message: ValidationMessage) -> dict[str, str]:
    """
    Returns dict representation of provided ValidationMessage's contents.
    """
    return {
        SPDX_ID: message.context.spdx_id or "",
        PARENT_ID: message.context.parent_id or "",
        ELEMENT_TYPE: str(message.context.element_type),
        MESSAGE: message.validation_message,
    }


def check_sbom(spdx_json: str) -> CheckResult:
    """
    Validates provided SPDX JSON string for adherence to official specification
    and for completeness.
    """
    spdx_dict = json.loads(spdx_json)
    try:
        spdx_document = _parse_spdx(spdx_dict)
    except SPDXParsingError as error:
        logger.warning("Failed to parse the provided JSON.")
        error_messages = error.get_messages()  # type: ignore[no-untyped-call]
        return CheckResult([], error_messages)

    logger.info("JSON parsed. Beginning validation.")

    validation_messages = validate_full_spdx_document(spdx_document)
    logger.info("Completed standard SDPX Validation.")

    validation_messages += check_completeness(spdx_document)
    logger.info("Completed configured completeness SDPX Validation.")

    return CheckResult(validation_messages, [])


def _parse_spdx(spdx_dict: dict[str, Any]) -> Document:
    """Converts dictionary into SPDX Document for verification."""
    return JsonLikeDictParser().parse(json_like_dict=spdx_dict)  # type: ignore


def check_completeness(document: Document) -> list[ValidationMessage]:
    """
    Runs completeness check to catch issues that the standard SPDX validator
    doesn't recognize.
    """
    messages = []

    # check document's creation_info values
    messages += _check_creation_info(document.creation_info)

    # check that document includes at least one package
    if has_packages_msg := _check_has_packages(document):
        messages.append(has_packages_msg)
        return messages

    # check the document's primary package
    if primary_package_msg := _check_primary_package(document):
        messages.append(primary_package_msg)

    # check the document's dependency packages
    messages += _check_packages(document.packages)

    # check that the document includes at least one file
    if has_files_msg := _check_has_files(document):
        messages.append(has_files_msg)
        return messages

    # check the document's files
    messages += _check_files(document.files)

    return messages


def _check_creation_info(
    creation_info: CreationInfo,
) -> list[ValidationMessage]:
    messages = []
    # check that the SPDX version is what we are expecting
    if creation_info.spdx_version not in SPDX_VERSIONS:
        messages.append(
            _create_custom_validation_message(
                message="The Document uses an invalid version. Valid "
                f"versions include: {SPDX_VERSIONS}.",
                element_type=SpdxElementType.CREATION_INFO,
            )
        )
    # check the SPDX document has a name value
    if not creation_info.name:
        messages.append(
            _create_custom_validation_message(
                message="The Document has no name.",
                element_type=SpdxElementType.CREATION_INFO,
            )
        )
    # check that the SPDX document has a license list version
    if not creation_info.license_list_version:
        messages.append(
            _create_custom_validation_message(
                message="The Document does not have a license list version.",
                element_type=SpdxElementType.CREATION_INFO,
            )
        )
    return messages


def _check_has_packages(document: Document) -> ValidationMessage | None:
    # check that the document contains at least one package
    if not document.packages:
        return _create_custom_validation_message(
            message="The Document contains no packages.",
            element_type=SpdxElementType.DOCUMENT,
        )
    return None


def _check_primary_package(document: Document) -> ValidationMessage | None:
    primary_package_id = document.packages[0].spdx_id
    document_id = document.creation_info.spdx_id
    expected_describes_relationship = Relationship(
        document_id, RelationshipType.DESCRIBES, primary_package_id
    )
    actual_describes_relationships = [
        relationship
        for relationship in document.relationships
        if relationship.relationship_type == RelationshipType.DESCRIBES
    ]

    # check that there is only one describes relationship in the document
    if len(actual_describes_relationships) != 1:
        return _create_custom_validation_message(
            message="This SPDX Document has an incorrect number of DESCRIBES "
            "relationships. An SPDX document must directly describe one "
            "top-level package. This document describes "
            "f{len(actual_describes_relationships)} packages.",
            element_type=SpdxElementType.DOCUMENT,
        )

    # check that the primary package is the first package entry
    if expected_describes_relationship != actual_describes_relationships[0]:
        return _create_custom_validation_message(
            message="This SPDX Document's DESCRIBES relationship is to a "
            "a package other than the first in the package info section. "
            "Either the relationship is incorrect or the top-level package "
            "that the document is describing is not first in the packages "
            "collection.",
            element_type=SpdxElementType.DOCUMENT,
        )

    return None


def _check_packages(packages: list[Package]) -> list[ValidationMessage]:
    messages = []
    for package in packages:
        # check that a supplier is provided for the package
        if not package.supplier or isinstance(
            package.supplier, SpdxNoAssertion
        ):
            messages.append(
                _create_custom_validation_message(
                    message="This package has no supplier populated.",
                    element_type=SpdxElementType.PACKAGE,
                    spdx_id=package.spdx_id,
                )
            )
        # check that the package's files have been analyzed
        if not package.files_analyzed:
            messages.append(
                _create_custom_validation_message(
                    message="The files have not been analyzed for this "
                    "package.",
                    element_type=SpdxElementType.PACKAGE,
                    spdx_id=package.spdx_id,
                )
            )
        # check that at least one package license has been provided
        if _has_licenses(package.license_concluded, package.license_declared):
            if not package.copyright_text:
                messages.append(
                    _create_custom_validation_message(
                        message="This package has declared licenses but no "
                        "copyright text populated.",
                        element_type=SpdxElementType.PACKAGE,
                        spdx_id=package.spdx_id,
                    )
                )
    return messages


def _has_licenses(license_concluded: Any, license_declared: Any) -> bool:
    return any(
        [
            isinstance(license_concluded, LicenseExpression),
            isinstance(license_declared, LicenseExpression),
        ]
    )


def _check_has_files(document: Document) -> ValidationMessage | None:
    # check that the document contains at least one file
    if not document.files:
        return _create_custom_validation_message(
            message="The Document contains no files.",
            element_type=SpdxElementType.DOCUMENT,
        )
    return None


def _check_files(files: list[File]) -> list[ValidationMessage]:
    messages = []
    for file in files:
        # check if each file has a name
        if not file.name:
            messages.append(
                _create_custom_validation_message(
                    message="This file has no name.",
                    element_type=SpdxElementType.FILE,
                    spdx_id=file.spdx_id,
                )
            )

        # remaining checks only relevant if file has concluded license
        if not isinstance(file.license_concluded, LicenseExpression):
            continue

        # check if license_info_in_file is populated
        if not file.license_info_in_file:
            messages.append(
                _create_custom_validation_message(
                    message="This file has a concluded license but "
                    "license_info_in_file is not populated.",
                    element_type=SpdxElementType.FILE,
                    spdx_id=file.spdx_id,
                )
            )

        # check if file has copyright_text populated
        if not file.copyright_text:
            messages.append(
                _create_custom_validation_message(
                    message="This file has a concluded license but "
                    "no copyright text.",
                    element_type=SpdxElementType.FILE,
                    spdx_id=file.spdx_id,
                )
            )

    return messages


def _create_custom_validation_message(
    message: str,
    element_type: SpdxElementType | None = None,
    spdx_id: str = "",
    element: Any = None,
) -> ValidationMessage:
    context = ValidationContext(spdx_id, None, element_type, element)
    return ValidationMessage(COMPLETENESS_EXCEPTION + message, context)
