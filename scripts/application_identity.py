"""Persistent identities shared by the signing and installation commands."""

from typing import NamedTuple


class ApplicationIdentity(NamedTuple):
    edition: str
    bundle_identifier: str
    application_name: str
    file_system_type: str

    @property
    def extension_identifier(self):
        return self.bundle_identifier + ".FileSystem"

    @property
    def keychain_group_suffix(self):
        return self.bundle_identifier + ".shared"

    @property
    def configuration(self):
        """The Xcode configuration (project.yml) that builds this edition."""
        return "Release" if self.edition == "release" else "Debug"

    @property
    def signed_derived_data(self):
        """Derived data of the locally signed build, relative to the repository root."""
        return "build/SignedRelease" if self.edition == "release" else "build/Signed"

    @property
    def signed_product(self):
        """The signed app that scripts/build-signed-app.sh writes, relative to the repository root."""
        return f"{self.signed_derived_data}/Build/Products/{self.configuration}/{self.application_name}.app"


RELEASE = ApplicationIdentity("release", "dev.soba.iscsi.kurazuna", "Kurazuna", "kurazuna")
DEVELOPMENT = ApplicationIdentity(
    "development", "dev.soba.iscsi.kurazuna.development", "Kurazuna Development", "kurazunadev")
IDENTITIES = {value.edition: value for value in (RELEASE, DEVELOPMENT)}

# The mounted harness (scripts/test-fskit.py and the scripts built on it) targets the
# development app unless this variable names another edition.
TEST_APPLICATION_VARIABLE = "ISCSI_TEST_APP"


def identity_for_bundle(identifier):
    for value in IDENTITIES.values():
        if value.bundle_identifier == identifier:
            return value
    raise ValueError("Unknown Kurazuna application identifier")


def identity_under_test(environment):
    """The edition the mounted harness tests: ISCSI_TEST_APP, the development app by default."""
    value = environment.get(TEST_APPLICATION_VARIABLE, DEVELOPMENT.edition)
    if value not in IDENTITIES:
        raise ValueError(f"{TEST_APPLICATION_VARIABLE} must be one of {', '.join(sorted(IDENTITIES))}")
    return IDENTITIES[value]
