"""Kubernetes-native discovery + fetch of module auth policies.

Watches Services labeled labs64.io/auth-policy=true in the ACS's own
namespace, fetches each module's /.well-known/auth-policy in-cluster, and
feeds the PolicyStore. Per-module failures keep the last-known-good routes;
a module whose Service disappears is dropped. Readiness = the first refresh
pass has completed (success or not), so a cold-started ACS never serves
before it has at least attempted to build its table.
"""
import logging
import os
import threading
from typing import Dict, Optional

import requests

from policy_store import PolicyStore, PolicyValidationError, parse_policy_document

logger = logging.getLogger("traefik_authproxy.policy_sync")

WELL_KNOWN_PATH = "/.well-known/auth-policy"
AUTH_POLICY_LABEL_SELECTOR = "labs64.io/auth-policy=true"
ANNOTATION_BASE_PATH = "labs64.io/auth-policy-base-path"
ANNOTATION_PORT = "labs64.io/auth-policy-port"

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
                 refresh_interval: int = 30, fetch_timeout: int = 5) -> None:
        self.store = store
        self.namespace = namespace or detect_namespace()
        self.refresh_interval = refresh_interval
        self.fetch_timeout = fetch_timeout
        self.last_refresh: Dict[str, str] = {}
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
        for svc in services:
            name = svc.metadata.name
            annotations = svc.metadata.annotations or {}
            base_path = annotations.get(ANNOTATION_BASE_PATH)
            if not base_path:
                logger.error("Service %s has %s label but no %s annotation — skipping",
                             name, AUTH_POLICY_LABEL_SELECTOR, ANNOTATION_BASE_PATH)
                continue
            port = annotations.get(ANNOTATION_PORT) or str(svc.spec.ports[0].port)
            discovered.add(name)
            url = f"http://{name}.{self.namespace}.svc.cluster.local:{port}{WELL_KNOWN_PATH}"
            try:
                response = requests.get(url, timeout=self.fetch_timeout)
                response.raise_for_status()
                routes = parse_policy_document(name, base_path, response.json())
            except PolicyValidationError as e:
                logger.error("Rejected auth-policy from %s: %s — keeping last known good", name, e)
                result[name] = "invalid"
                continue
            except Exception as e:
                logger.error("Fetching auth-policy from %s failed: %s — keeping last known good",
                             url, e)
                result[name] = "failed"
                continue
            self.store.set_module(name, routes)
            result[name] = "ok"
            logger.info("Auth-policy loaded from %s: %d routes", name, len(routes))

        for module in self.store.modules():
            if module not in discovered:
                logger.info("Module %s no longer labeled for auth-policy — dropping its routes",
                            module)
                self.store.drop_module(module)

        self.last_refresh = result
        self._initial_done.set()
        return result

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
