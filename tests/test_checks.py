# Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

import json

import pytest

from sbom_check import check_sbom


@pytest.fixture
def spdx_json_no_packages():
    document = {
        "spdxVersion": "SPDX-2.3",
        "documentNamespace": "http://spdx.org/spdxdocs/la.vendor.13."
        "2.0.r1-42c814b1-0331-4e6f-858d-37b9077e860a",
        "creationInfo": {
            "creators": [
                "Organization: Qualcomm",
                "Tool: qcom-sbom-tools-0.11.2.dev0+gf9e050f.d20230906",
            ],
            "created": "2023-09-07T20:33:12Z",
            "licenseListVersion": "3.20",
        },
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Fake name",
        "packages": [],
    }
    return json.dumps(document)


@pytest.fixture
def spdx_json1():
    document = {
        "spdxVersion": "SPDX-2.3",
        "documentNamespace": "http://spdx.org/spdxdocs/la.vendor.13."
        "2.0.r1-42c814b1-0331-4e6f-858d-37b9077e860a",
        "creationInfo": {
            "creators": [
                "Organization: Qualcomm",
                "Tool: qcom-sbom-tools-0.11.2.dev0+gf9e050f.d20230906",
            ],
            "created": "2023-09-07T20:33:12Z",
        },
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "",
        "packages": [
            {
                "SPDXID": "SPDXRef-LA.VENDOR.13.2.0.r1",
                "name": "LA.VENDOR",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "versionInfo": "13.2.0.r1",
                "supplier": "Organization: Qualcomm",
            }
        ],
    }
    return json.dumps(document)


@pytest.fixture
def spdx_json2():
    document = {
        "spdxVersion": "SPDX-2.3",
        "documentNamespace": "http://spdx.org/spdxdocs/la.vendor.13."
        "2.0.r1-42c814b1-0331-4e6f-858d-37b9077e860a",
        "creationInfo": {
            "creators": [
                "Organization: Qualcomm",
                "Tool: qcom-sbom-tools-0.11.2.dev0+gf9e050f.d20230906",
            ],
            "created": "2023-09-07T20:33:12Z",
            "licenseListVersion": "3.20",
        },
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Fake name",
        "packages": [
            {
                "SPDXID": "SPDXRef-test.2",
                "name": "LA.VENDOR",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "FAKE",
                "licenseDeclared": "FAKE",
                "versionInfo": "13.2.0.r1",
                "supplier": "",
            }
        ],
        "comment": "fake-comment",
        "documentDescribes": ["SPDXRef-test.2"],
        "files": [
            {
                "fileName": "fakepath",
                "SPDXID": "SPDXRef-fakepath",
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": "NOASSERTION"}
                ],
                "licenseConcluded": "BSD-3-Clause",
                "licenseInfoInFiles": ["BSD-3-Clause"],
            }
        ],
    }
    return json.dumps(document)


@pytest.fixture
def spdx_json3():
    document = {
        "spdxVersion": "SPDX-2.3",
        "documentNamespace": "http://spdx.org/spdxdocs/la.vendor.13."
        "2.0.r1-42c814b1-0331-4e6f-858d-37b9077e860a",
        "creationInfo": {
            "creators": [
                "Organization: Qualcomm",
                "Tool: qcom-sbom-tools-0.11.2.dev0+gf9e050f.d20230906",
            ],
            "created": "2023-09-07T20:33:12Z",
            "licenseListVersion": "3.20",
        },
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Fake name",
        "packages": [
            {
                "SPDXID": "SPDXRef-test.2",
                "name": "LA.VENDOR",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "versionInfo": "13.2.0.r1",
                "supplier": "Organization: Qualcomm",
            }
        ],
        "comment": "fake-comment",
        "documentDescribes": ["SPDXRef-test.2"],
        "files": [
            {
                "fileName": "fakepath",
                "SPDXID": "SPDXRef-fakepath",
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": "NOASSERTION"}
                ],
                "licenseConcluded": "BSD-3-Clause",
                "licenseInfoInFiles": [],
            }
        ],
    }
    return json.dumps(document)


def test_check_empty_document():
    result = check_sbom("{}")
    assert result.errors == [
        "Error while parsing document None: ['CreationInfo does not exist.']"
    ]


def test_check_creation_info(spdx_json1):
    result = check_sbom(spdx_json1)

    assert result.validation_messages[0]["message"] == (
        "\n*** completeness exception ***\nThe Document has no name."
    )
    assert result.validation_messages[1]["message"] == (
        "\n*** completeness exception ***\n"
        "The Document does not have a license list version."
    )


def test_check_no_packages(spdx_json_no_packages):
    result = check_sbom(spdx_json_no_packages)

    assert result.validation_messages[0]["message"] == (
        'there must be at least one relationship "SPDXRef-DOCUMENT DESCRIBES ..." '
        'or "... DESCRIBED_BY SPDXRef-DOCUMENT" when there is not only a '
        "single package present"
    )
    assert result.validation_messages[1]["message"] == (
        "\n*** completeness exception ***\nThe Document contains no packages."
    )


def test_check_packages(spdx_json2):
    result = check_sbom(spdx_json2)

    assert result.validation_messages[3]["message"] == (
        "\n*** completeness exception ***\n"
        "This package has no supplier populated."
    )
    assert result.validation_messages[4]["message"] == (
        "\n*** completeness exception ***\n"
        "The files have not been analyzed for this package."
    )
    assert result.validation_messages[5]["message"] == (
        "\n*** completeness exception ***\n"
        "This package has declared licenses but no copyright text populated."
    )


def test_check_files(spdx_json3):
    result = check_sbom(spdx_json3)

    assert result.validation_messages[1]["message"] == (
        "\n*** completeness exception ***\n"
        "This file has a concluded license but license_info_in_file is not populated."
    )
    assert result.validation_messages[2]["message"] == (
        "\n*** completeness exception ***\n"
        "This file has a concluded license but no copyright text."
    )
