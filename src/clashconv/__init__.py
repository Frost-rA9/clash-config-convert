"""Build Mihomo configurations from local Clash nodes and declarative templates."""

from .artifacts import Artifact, Profile, load_artifact, load_profile
from .loader import LoadError, load
from .merge import MergeError, merge

__all__ = ["Artifact", "Profile", "LoadError", "MergeError", "load", "load_artifact", "load_profile", "merge"]
