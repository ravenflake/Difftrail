"""Difftrail: a local-first Windows change journal and investigator."""

__version__ = "0.1.3"

# Development CI may add this ignored module to the build workspace. Stable
# source and release metadata continue to use the plain version above when absent.
try:
    from ._build_version import BUILD_VERSION as _BUILD_VERSION
except ModuleNotFoundError:
    pass
else:
    __version__ = _BUILD_VERSION
