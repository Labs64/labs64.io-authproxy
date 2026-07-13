"""Kubernetes-native discovery + fetch of module auth policies.

Watches Services labeled labs64.io/auth-policy=true in the ACS's own
namespace, fetches each module's /.well-known/auth-policy in-cluster, and
feeds the PolicyStore. Per-module failures keep the last-known-good routes;
a module whose Service disappears is dropped. Readiness = the first refresh
pass has completed (success or not), so a cold-started ACS never serves
before it has at least attempted to build its table.

RFC-05 P2: alongside the JSON document, each module's generated Tier-1 edge
Cedar policy set is fetched from /.well-known/auth-policy.cedar — the same
distribution model as auth-policy.json. Modules are keyed by the first
segment of their gateway base path (e.g. /payment-gateway/api/v1 →
``payment-gateway``), which is the same module name the build bakes into the
Cedar resource ids and bundle-sources.yaml uses — so the live-discovery and
signed-bundle paths agree on identity.
"""
import logging
import os
import threading
from typing import Callable, Dict, Optional

import requests

from cedar_edge import validate_policy_text
from policy_store import PolicyStore, PolicyValidationError, parse_policy_document

logger = logging.getLogger("traefik_authproxy.policy_sync")

WELL_KNOWN_PATH = "/.well-known/auth-policy"
WELL_KNOWN_CEDAR_PATH = "/.well-known/auth-policy.cedar"
AUTH_POLICY_LABEL_SELECTOR = "labs64.io/auth-policy=true"
ANNOTATION_BASE_PATH = "labs64.io/auth-policy-base-path"
ANNOTATION_PORT = "labs64.io/auth-policy-port"


def module_name_from_base_path(base_path: str, fallback: str) -> str:
    """Derive the canonical module name from the gateway base path.

    The first path segment IS the module identity platform-wide (the same
    invariant bundle-sources.yaml documents); the Service name is a Helm
    release artifact (e.g. ``labs64io-payment-gateway``) and must not leak
    into Cedar resource ids.
    """
    segment = base_path.strip("/").split("/", 1)[0] if base_path else ""
    return segment or fallback

_NAMESPACE_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"


def detect_namespace() -> str:
    if os.getenv("POD_NAMESPACE"):
        return os.environ["POD_NAMESPACE"]
    if os.path.isfile(_NAMESPACE_FILE):
        with open(_NAMESPACE_FILE) as f:
            return f.read().strip()
    return "default"


class PolicySync:
    def __init__(self, store: PolicyStore, namespace: Optional[str] = None,
                 refresh_interval: int = 30, fetch_timeout: int = 5,
                 fetch_cedar: bool = True) -> None:
        self.store = store
        self.namespace = namespace or detect_namespace()
        self.refresh_interval = refresh_interval
        self.fetch_timeout = fetch_timeout
        # Whether to fetch the modules' generated edge Cedar policies at all
        # (the app disables this when CEDAR_MODE=off).
        self.fetch_cedar = fetch_cedar
        self.last_refresh: Dict[str, str] = {}
        # RFC-05 P2: generated Tier-1 edge Cedar policy text per module,
        # fetched from /.well-known/auth-policy.cedar (mirrors the bundle
        # loader's surface). Modules on an older starter simply have none.
        self.cedar_policies: Dict[str, str] = {}
        # Invoked (no args) after a refresh pass whenever the cedar set
        # changed, so the app can reload the edge engine.
        self.on_cedar_update: Optional[Callable[[], None]] = None
        self._core_v1 = None  # kubernetes.client.CoreV1Api, set in start() or tests
        self._refresh_event = threading.Event()
        self._initial_done = threading.Event()
        self._stopping = threading.Event()
        self._threads = []

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        """Load K8s config and start the refresh + watch threads.

        Outside a cluster (local dev / docker), discovery is disabled: the ACS
        serves static policies only and reports ready immediately.
        """
        self._stopping.clear()  # allow a restart to re-enter the loop bodies
        try:
            from kubernetes import client, config
            try:
                config.load_incluster_config()
            except Exception:
                config.load_kube_config()
            self._core_v1 = client.CoreV1Api()
        except Exception as e:
            logger.warning("Kubernetes API unavailable (%s) — dynamic auth-policy "
                           "discovery disabled, static policies only", e)
            self._initial_done.set()
            return

        refresher = threading.Thread(target=self._refresh_loop,
                                     name="auth-policy-refresh", daemon=True)
        watcher = threading.Thread(target=self._watch_loop,
                                   name="auth-policy-watch", daemon=True)
        self._threads = [refresher, watcher]
        refresher.start()
        watcher.start()

    def stop(self) -> None:
        self._stopping.set()
        self._refresh_event.set()

    def ready(self) -> bool:
        return self._initial_done.is_set()

    def trigger_refresh(self) -> None:
        self._refresh_event.set()

    # -- core ----------------------------------------------------------------
    def refresh_once(self) -> Dict[str, str]:
        """One discovery + fetch pass. Returns {module: ok|failed|invalid}."""
        result: Dict[str, str] = {}
        try:
            services = self._core_v1.list_namespaced_service(
                self.namespace, label_selector=AUTH_POLICY_LABEL_SELECTOR).items
        except Exception as e:
            logger.error("Service discovery failed: %s — keeping current table", e)
            self._initial_done.set()
            return result

        discovered = set()
        cedar_changed = False
        for svc in services:
            svc_name = svc.metadata.name
            annotations = svc.metadata.annotations or {}
            base_path = annotations.get(ANNOTATION_BASE_PATH)
            if not base_path:
                logger.error("Service %s has %s label but no %s annotation — skipping",
                             svc_name, AUTH_POLICY_LABEL_SELECTOR, ANNOTATION_BASE_PATH)
                continue
            module = module_name_from_base_path(base_path, svc_name)
            port = annotations.get(ANNOTATION_PORT) or str(svc.spec.ports[0].port)
            discovered.add(module)
            base_url = f"http://{svc_name}.{self.namespace}.svc.cluster.local:{port}"
            url = base_url + WELL_KNOWN_PATH
            try:
                response = requests.get(url, timeout=self.fetch_timeout)
                response.raise_for_status()
                routes = parse_policy_document(module, base_path, response.json())
            except PolicyValidationError as e:
                logger.error("Rejected auth-policy from %s: %s — keeping last known good",
                             module, e)
                result[module] = "invalid"
                continue
            except Exception as e:
                logger.error("Fetching auth-policy from %s failed: %s — keeping last known good",
                             url, e)
                result[module] = "failed"
                continue
            self.store.set_module(module, routes)
            result[module] = "ok"
            logger.info("Auth-policy loaded from %s: %d routes", module, len(routes))
            if self.fetch_cedar:
                cedar_changed |= self._fetch_cedar(module, base_url + WELL_KNOWN_CEDAR_PATH)

        for module in self.store.modules():
            if module not in discovered:
                logger.info("Module %s no longer labeled for auth-policy — dropping its routes",
                            module)
                self.store.drop_module(module)
                if self.cedar_policies.pop(module, None) is not None:
                    cedar_changed = True

        self.last_refresh = result
        self._initial_done.set()
        if cedar_changed and self.on_cedar_update is not None:
            try:
                self.on_cedar_update()
            except Exception:
                logger.exception("cedar update callback failed")
        return result

    def _fetch_cedar(self, module: str, url: str) -> bool:
        """Fetch one module's generated edge Cedar policies (best effort).

        Mirrors the JSON semantics: fetch/parse failures keep the last-known-good
        text; a 404 means the module does not serve Cedar (older starter) and any
        previously held text is dropped. Returns True when the stored cedar set
        changed.
        """
        try:
            response = requests.get(url, timeout=self.fetch_timeout)
            if response.status_code == 404:
                if self.cedar_policies.pop(module, None) is not None:
                    logger.info("Module %s no longer serves cedar policies — dropped", module)
                    return True
                return False
            response.raise_for_status()
            text = response.text
            if self.cedar_policies.get(module) == text:
                return False
            validate_policy_text(text)
        except ValueError as e:
            logger.error("Rejected cedar policy from %s: %s — keeping last known good", module, e)
            return False
        except Exception as e:
            logger.error("Fetching cedar policy from %s failed: %s — keeping last known good",
                         url, e)
            return False
        self.cedar_policies[module] = text
        logger.info("Cedar edge policy loaded from %s (%d chars)", module, len(text))
        return True

    def combined_cedar(self) -> str:
        """All modules' generated edge Cedar policies as one policy-set text
        (same surface as PolicyBundleLoader.combined_cedar)."""
        return "\n".join(self.cedar_policies[m] for m in sorted(self.cedar_policies))

    # -- threads -------------------------------------------------------------
    def _refresh_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                self.refresh_once()
            except Exception:
                logger.exception("Unexpected error in auth-policy refresh")
            self._refresh_event.wait(timeout=self.refresh_interval)
            self._refresh_event.clear()

    def _watch_loop(self) -> None:
        from kubernetes import watch
        while not self._stopping.is_set():
            try:
                stream = watch.Watch().stream(
                    self._core_v1.list_namespaced_service, self.namespace,
                    label_selector=AUTH_POLICY_LABEL_SELECTOR, timeout_seconds=60)
                for _event in stream:
                    self.trigger_refresh()
            except Exception as e:
                logger.warning("Service watch interrupted (%s) — reconnecting", e)
                self._stopping.wait(5)
