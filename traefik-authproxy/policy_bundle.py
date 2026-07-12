"""Signed-bundle policy source for the traefik-authproxy (RFC-05 P0 — Provenance).

This is the provenance-safe alternative to live-pod discovery (policy_sync.py).
Instead of fetching each module's /.well-known/auth-policy over unauthenticated
in-cluster HTTP *from the very pod it authorizes* (F2 — self-authored runtime
policy), the ACS loads a bundle that CI generated from the modules' OpenAPI
specs, cosign-signed, and pushed to an OCI registry. An init container pulls the
bundle *by digest* and cosign-verifies it before the ACS starts; this module
just reads the verified directory off disk.

Bundle layout on disk (POLICY_BUNDLE_DIR):

    manifest.json              # {version, generatedAt, modules:[{name, basePath, file}]}
    modules/<name>.json        # one module auth-policy document (same schema as
                               # /.well-known/auth-policy, version 1)

When a bundle dir is configured the live PolicySync is never started, so the
authorized pod can no longer author the policy that governs it — F2 is closed
by construction, not by convention.
"""
import json
import logging
import os
from typing import Dict, List

from policy_store import PolicyStore, PolicyValidationError, parse_policy_document

logger = logging.getLogger("traefik_authproxy.policy_bundle")

MANIFEST_NAME = "manifest.json"
SUPPORTED_BUNDLE_VERSION = 1


class BundleError(RuntimeError):
    """Raised when the on-disk policy bundle is missing or malformed."""


class PolicyBundleLoader:
    """Loads module auth policies from a verified on-disk bundle directory.

    Mirrors the PolicySync surface the app depends on (``ready()``,
    ``refresh_once()``) so the app wiring is a drop-in swap, but there is no
    Kubernetes client, no network fetch, and no background thread: the bundle is
    immutable for the pod's lifetime (a new bundle ⇒ a new digest ⇒ a new
    rollout).
    """

    def __init__(self, store: PolicyStore, bundle_dir: str) -> None:
        self.store = store
        self.bundle_dir = bundle_dir
        self._ready = False
        self.loaded_modules: List[str] = []
        self.bundle_meta: Dict[str, object] = {}
        # RFC-05 P2: generated Tier-1 edge Cedar policy text per module (from
        # the manifest's optional "cedar" field). Older bundles have none.
        self.cedar_policies: Dict[str, str] = {}

    # -- lifecycle (mirrors PolicySync) --------------------------------------
    def start(self) -> None:
        """Load the bundle once. Fails closed: a bad bundle leaves an empty
        table (deny-all) and the ACS never reports ready."""
        try:
            self.load()
            self._ready = True
        except BundleError:
            # Do NOT set ready — readiness gate keeps the ACS out of rotation
            # rather than serving with no/partial policy.
            logger.exception("Policy bundle load failed — ACS will not become ready")

    def stop(self) -> None:  # symmetry with PolicySync; nothing to tear down
        pass

    def ready(self) -> bool:
        return self._ready

    def trigger_refresh(self) -> None:
        """Bundles are immutable per digest; /reload re-reads the same dir so an
        init-container hot-swap (new digest, same path) is still picked up."""
        try:
            self.load()
        except BundleError:
            logger.exception("Policy bundle reload failed — keeping current table")

    def refresh_once(self) -> Dict[str, str]:
        result: Dict[str, str] = {}
        try:
            self.load(result)
        except BundleError as e:
            logger.error("Bundle refresh failed: %s", e)
        return result

    # -- core ----------------------------------------------------------------
    def load(self, result: Dict[str, str] | None = None) -> None:
        manifest_path = os.path.join(self.bundle_dir, MANIFEST_NAME)
        if not os.path.isfile(manifest_path):
            raise BundleError(f"no {MANIFEST_NAME} in bundle dir {self.bundle_dir!r}")
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
        except (OSError, ValueError) as e:
            raise BundleError(f"unreadable manifest: {e}") from e

        version = manifest.get("version")
        if version != SUPPORTED_BUNDLE_VERSION:
            raise BundleError(
                f"unsupported bundle version {version!r} "
                f"(supported: {SUPPORTED_BUNDLE_VERSION})"
            )
        modules = manifest.get("modules")
        if not isinstance(modules, list):
            raise BundleError("manifest 'modules' must be a list")

        loaded: List[str] = []
        cedar_policies: Dict[str, str] = {}
        for entry in modules:
            if not isinstance(entry, dict):
                raise BundleError(f"malformed module entry: {entry!r}")
            name = entry.get("name")
            base_path = entry.get("basePath")
            rel_file = entry.get("file")
            if not name or not base_path or not rel_file:
                raise BundleError(f"module entry missing name/basePath/file: {entry!r}")
            doc_path = os.path.join(self.bundle_dir, rel_file)
            try:
                with open(doc_path) as f:
                    doc = json.load(f)
            except (OSError, ValueError) as e:
                raise BundleError(f"{name}: unreadable policy doc {rel_file!r}: {e}") from e
            try:
                # PolicyValidationError subclasses ValueError — catch it first.
                routes = parse_policy_document(name, base_path, doc)
            except PolicyValidationError as e:
                raise BundleError(f"{name}: invalid policy: {e}") from e
            rel_cedar = entry.get("cedar")
            if rel_cedar:
                cedar_path = os.path.join(self.bundle_dir, rel_cedar)
                try:
                    with open(cedar_path) as f:
                        cedar_policies[name] = f.read()
                except OSError as e:
                    raise BundleError(f"{name}: unreadable cedar policy {rel_cedar!r}: {e}") from e
            self.store.set_module(name, routes)
            loaded.append(name)
            if result is not None:
                result[name] = "ok"
            logger.info("Bundle policy loaded for %s: %d routes%s", name, len(routes),
                        ", cedar" if name in cedar_policies else "")

        # Drop any module that vanished from a newer bundle (hot-swap hygiene).
        for module in self.store.modules():
            if module not in loaded:
                self.store.drop_module(module)
                logger.info("Module %s absent from bundle — dropping its routes", module)

        self.loaded_modules = loaded
        self.cedar_policies = cedar_policies
        self.bundle_meta = {
            "version": version,
            "generatedAt": manifest.get("generatedAt"),
            "digest": os.getenv("POLICY_BUNDLE_DIGEST", "unknown"),
            "modules": loaded,
        }
        logger.info("Policy bundle loaded: %d module(s) — %s", len(loaded), ", ".join(loaded))

    def combined_cedar(self) -> str:
        """All modules' generated edge Cedar policies as one policy-set text
        (the edge PDP evaluates a single set; @id annotations stay unique
        because they are prefixed with the module name)."""
        return "\n".join(self.cedar_policies[m] for m in sorted(self.cedar_policies))
