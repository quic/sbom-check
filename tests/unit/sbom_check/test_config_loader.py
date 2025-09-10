# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for configuration loader."""

import pytest

from sbom_check.config.loader import ConfigLoader
from sbom_check.config.models import SbomCheckConfig


def test_config_loader_initialization():
    """Test that ConfigLoader initializes correctly."""
    loader = ConfigLoader()
    assert loader is not None
    assert len(loader.list_profiles()) >= 2  # At least basic_spdx and default


def test_list_profiles():
    """Test listing available profiles."""
    loader = ConfigLoader()
    profiles = loader.list_profiles()

    assert "basic_spdx" in profiles
    assert "default" in profiles
    assert isinstance(profiles, list)


def test_load_basic_spdx_profile():
    """Test loading the basic SPDX profile."""
    loader = ConfigLoader()
    config = loader.load_profile("basic_spdx")

    assert isinstance(config, SbomCheckConfig)
    assert config.metadata.name == "Basic SPDX 2.3 Compliance"
    assert config.spdx_validation.enable_schema_validation is True
    assert config.spdx_validation.enable_semantic_validation is True


def test_load_default_profile():
    """Test loading the default profile."""
    loader = ConfigLoader()
    config = loader.load_profile("default")

    assert isinstance(config, SbomCheckConfig)
    assert config.metadata.name == "Default SBOM Requirements"
    assert config.package_requirements.build_tools.require_build_tools is True
    assert len(config.document_requirements.required_fields) > 0


def test_load_nonexistent_profile():
    """Test loading a non-existent profile raises ValueError."""
    loader = ConfigLoader()

    with pytest.raises(ValueError, match="Unknown profile"):
        loader.load_profile("nonexistent")


def test_generate_template():
    """Test generating configuration template."""
    loader = ConfigLoader()
    template = loader.generate_template("basic_spdx", include_comments=True)

    assert isinstance(template, str)
    assert "SBOM-Check Configuration Template" in template
    assert "metadata:" in template
    assert "spdx_validation:" in template


def test_generate_template_without_comments():
    """Test generating configuration template without comments."""
    loader = ConfigLoader()
    template = loader.generate_template("basic_spdx", include_comments=False)

    assert isinstance(template, str)
    assert "SBOM-Check Configuration Template" not in template
    assert "metadata:" in template


def test_save_and_load_config(tmp_path):
    """Test saving and loading configuration."""
    loader = ConfigLoader()
    config = loader.load_profile("basic_spdx")

    # Save config
    config_file = tmp_path / "test_config.yaml"
    loader.save_to_file(config, config_file, "yaml")

    assert config_file.exists()

    # Load config back
    loaded_config = loader.load_from_file(config_file)

    assert loaded_config.metadata.name == config.metadata.name
    assert loaded_config.metadata.version == config.metadata.version


def test_load_from_nonexistent_file():
    """Test loading from non-existent file raises FileNotFoundError."""
    loader = ConfigLoader()

    with pytest.raises(FileNotFoundError):
        loader.load_from_file("nonexistent.yaml")


def test_validate_config_file_valid(tmp_path):
    """Test validating a valid configuration file."""
    loader = ConfigLoader()
    config = loader.load_profile("basic_spdx")

    # Save valid config
    config_file = tmp_path / "valid_config.yaml"
    loader.save_to_file(config, config_file, "yaml")

    # Validate it
    is_valid, errors = loader.validate_config_file(config_file)

    assert is_valid is True
    assert len(errors) == 0


def test_validate_config_file_invalid(tmp_path):
    """Test validating an invalid configuration file."""
    loader = ConfigLoader()

    # Create invalid config file (missing required fields)
    config_file = tmp_path / "invalid_config.yaml"
    with config_file.open("w") as f:
        f.write("metadata:\n  name: ''\n  version: ''")

    # Validate it
    is_valid, errors = loader.validate_config_file(config_file)

    assert is_valid is False
    assert len(errors) > 0
    assert "Configuration metadata.name is required" in errors[0]


def test_load_with_profile_basic():
    """Test loading with profile only."""
    loader = ConfigLoader()
    config = loader.load_with_profile("basic_spdx")

    assert config.metadata.name == "Basic SPDX 2.3 Compliance"


def test_load_with_profile_and_overrides():
    """Test loading with profile and overrides."""
    loader = ConfigLoader()

    overrides = {"spdx_validation": {"require_zero_validation_warnings": True}}

    config = loader.load_with_profile("basic_spdx", overrides=overrides)

    assert config.metadata.name == "Basic SPDX 2.3 Compliance"
    assert config.spdx_validation.require_zero_validation_warnings is True
