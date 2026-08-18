"""Governed entrypoints and evidence builder for pinned prime-rl v0.8.0.

Imports from prime-rl are delayed so the core package and CPU tests do not require
the GPU training stack. The reference host patch must be applied first.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import stat
import uuid
from pathlib import Path

from .anchor import (
    AnchorStore,
    HeadAnchor,
    LocalEd25519HeadAnchor,
    load_private_key,
    load_public_key,
)
from .canonical import canonical_json
from .charter import Charter
from .freeze import FreezeController
from .gate import PromotionGate, PromotionRequest
from .ledger import Ledger
from .prime_rl import PrimeRLPromotionBarrier
from .shadow_eval import CandidateEvalPolicy, CandidateEvalRequest, ShadowEvaluator
from .store import ArtifactStore
from .witness import UnixSocketHeadAnchor


class PrimeRLIntegrationError(RuntimeError):
    pass


def _reject_symlink_components(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise PrimeRLIntegrationError(f"symlink component rejected: {current}")


class PrimeRLEvidenceBuilder:
    """Build the four-event evidence bundle for one filesystem-broadcast step."""

    def __init__(
        self,
        output_dir: str | Path,
        ledger: Ledger,
        store: ArtifactStore,
        *,
        shadow_evaluator: ShadowEvaluator | None = None,
        candidate_eval_policy: CandidateEvalPolicy | None = None,
        candidate_eval_assets: dict[str, Path] | None = None,
    ) -> None:
        if (shadow_evaluator is None) != (candidate_eval_policy is None):
            raise PrimeRLIntegrationError(
                "shadow evaluator and candidate evaluation policy must be configured together"
            )
        self.output_dir = Path(output_dir).resolve()
        self.ledger = ledger
        self.store = store
        expected_assets = {
            "candidate_evaluator_bundle",
            "candidate_eval_suite",
            "candidate_eval_config",
            "source_policy_manifest",
        }
        if shadow_evaluator is not None and (
            not isinstance(candidate_eval_assets, dict) or set(candidate_eval_assets) != expected_assets
        ):
            raise PrimeRLIntegrationError(
                "shadow evaluation requires exact evaluator, suite, and config artifacts"
            )
        if shadow_evaluator is None and candidate_eval_assets is not None:
            raise PrimeRLIntegrationError("shadow evaluation assets supplied without an evaluator")
        self.shadow_evaluator = shadow_evaluator
        self.candidate_eval_policy = candidate_eval_policy
        self.candidate_eval_assets = candidate_eval_assets
        self._config_seq: int | None = None
        self._candidate_eval_config_seq: int | None = None
        self._requests: dict[int, PromotionRequest] = {}
        self.derived_dir = self.ledger.path.parent / "derived"
        self.derived_dir.mkdir(parents=True, exist_ok=True)

    def _resolved_config(self) -> Path:
        path = self.output_dir / "control" / "orch.toml"
        if not path.is_file() or path.is_symlink():
            raise PrimeRLIntegrationError(f"resolved orchestrator config missing or unsafe: {path}")
        return path

    def _config_event(self) -> int:
        if self._config_seq is None:
            record = self.ledger.append(
                "config.resolved",
                actor="service:filiolae-prime-rl",
                data={"immutable": True, "host": "prime-rl@v0.8.0"},
                artifacts=[self.store.put("config", self._resolved_config())],
            )
            self._config_seq = record.seq
        return self._config_seq

    def _candidate_eval_config_event(self) -> int | None:
        if self.shadow_evaluator is None or self.candidate_eval_policy is None:
            return None
        if self._candidate_eval_config_seq is not None:
            return self._candidate_eval_config_seq
        assert self.candidate_eval_assets is not None
        artifacts = [
            self.store.put(name, self.candidate_eval_assets[name])
            for name in (
                "candidate_evaluator_bundle",
                "candidate_eval_suite",
                "candidate_eval_config",
                "source_policy_manifest",
            )
        ]
        expected = {
            "candidate_evaluator_bundle": self.candidate_eval_policy.evaluator_sha256,
            "candidate_eval_suite": self.candidate_eval_policy.suite_sha256,
            "candidate_eval_config": self.candidate_eval_policy.config_sha256,
            "source_policy_manifest": self.candidate_eval_policy.source_policy_sha256,
        }
        actual = {artifact.name: artifact.sha256 for artifact in artifacts}
        if actual != expected:
            raise PrimeRLIntegrationError(
                "candidate evaluator/suite/config artifacts contradict the Charter digests"
            )
        record = self.ledger.append(
            "candidate_eval.configured",
            actor="service:filiolae-prime-rl",
            data={"immutable": True, "authorization": "charter-pinned"},
            artifacts=artifacts,
        )
        self._candidate_eval_config_seq = record.seq
        return record.seq

    def request_for_step(self, step: int, pending_weights_path: Path | None) -> PromotionRequest:
        if step in self._requests:
            return self._requests[step]
        if step <= 0 or pending_weights_path is None:
            raise PrimeRLIntegrationError("step must be positive and filesystem weights are required")
        pending = Path(pending_weights_path)
        expected = self.output_dir / "broadcasts" / f"step_{step}"
        _reject_symlink_components(pending)
        if Path(os.path.abspath(pending)) != expected:
            raise PrimeRLIntegrationError(f"unexpected broadcast path: expected {expected}, got {pending}")
        stable = pending / "STABLE"
        if not stable.is_file() or stable.is_symlink():
            raise PrimeRLIntegrationError(f"stable broadcast marker missing or unsafe: {stable}")
        batch_path = self.output_dir / "rollouts" / f"step_{step}" / "train" / "effective" / "traces.jsonl"
        _reject_symlink_components(batch_path)
        if not batch_path.is_file() or batch_path.is_symlink():
            raise PrimeRLIntegrationError(f"effective rollout batch missing or unsafe: {batch_path}")

        source_version = step - 1
        attempt_id = uuid.uuid4().hex
        source_eval_path = self.derived_dir / f"source-eval-step-{step}.json"
        source_eval_path.write_bytes(
            canonical_json(
                {
                    "schema": "filiolae.source-eval.v1",
                    "step": step,
                    "source_policy_version": source_version,
                    "candidate_quality_evaluated": False,
                    "purpose": "source-policy/run lineage evidence only",
                }
            )
            + b"\n"
        )
        config_seq = self._config_event()
        candidate_eval_config_seq = self._candidate_eval_config_event()
        batch = self.ledger.append(
            "batch.committed",
            actor="service:filiolae-prime-rl",
            data={"step": step, "source_policy_version": source_version},
            artifacts=[self.store.put("rollout_batch", batch_path)],
        )
        source_eval = self.ledger.append(
            "source_eval.result",
            actor="service:filiolae-prime-rl",
            data={
                "step": step,
                "evaluated_policy_version": source_version,
                "candidate_quality_evaluated": False,
            },
            artifacts=[self.store.put("source_eval_result", source_eval_path)],
        )
        weights = self.ledger.append(
            "weights.published",
            actor="service:filiolae-prime-rl",
            data={
                "step": step,
                "source_policy_version": source_version,
                "attempt_id": attempt_id,
            },
            artifacts=[self.store.put("candidate_weights", pending)],
        )
        candidate_eval_seq = None
        if self.shadow_evaluator is not None and self.candidate_eval_policy is not None:
            evaluation_request = CandidateEvalRequest(
                run_id=weights.run_id,
                attempt_id=attempt_id,
                step=step,
                source_policy_version=source_version,
                candidate_sha256=weights.artifacts[0].sha256,
                evaluated_ledger_seq=weights.seq,
                evaluated_ledger_head_sha256=weights.hash,
                policy=self.candidate_eval_policy,
            )
            receipt_path = self.derived_dir / f"candidate-eval-step-{step}.json"
            evaluator_actor = "service:filiolae-shadow-evaluator"
            evaluator_returned_terminal = False
            try:
                receipt = self.shadow_evaluator.evaluate(
                    evaluation_request,
                    self.store.resolve(weights.artifacts[0]),
                )
                receipt_path.write_bytes(receipt.to_bytes())
                status = receipt.body["status"]
                evaluator_returned_terminal = True
            except Exception:
                # The evaluator may fail before it can sign a receipt. Preserve an honest,
                # bounded unavailable marker so Gate receives a complete request and commits
                # its permanent denial/freeze instead of aborting before authorization.
                receipt_path.write_bytes(
                    canonical_json(
                        {
                            "reason_code": "evaluator-unavailable",
                            "schema": "filiolae.candidate-eval-unavailable.v1",
                            "status": "error",
                        }
                    )
                    + b"\n"
                )
                evaluator_actor = "service:filiolae-prime-rl"
                status = "error"
            terminal_path = None
            terminal_evidence_root = getattr(
                self.shadow_evaluator,
                "terminal_evidence_root",
                None,
            )
            if callable(terminal_evidence_root) and evaluator_returned_terminal:
                try:
                    terminal_path = terminal_evidence_root(evaluation_request)
                except Exception:
                    receipt_path.write_bytes(
                        canonical_json(
                            {
                                "reason_code": "complete-terminal-evidence-unavailable",
                                "schema": "filiolae.candidate-eval-unavailable.v1",
                                "status": "error",
                            }
                        )
                        + b"\n"
                    )
                    evaluator_actor = "service:filiolae-prime-rl"
                    status = "error"
            candidate_eval_artifacts = [self.store.put("candidate_eval_receipt", receipt_path)]
            if terminal_path is not None:
                candidate_eval_artifacts.append(self.store.put("candidate_eval_terminal", terminal_path))
            candidate_eval = self.ledger.append(
                "candidate_eval.result",
                actor=evaluator_actor,
                data={
                    "step": step,
                    "source_policy_version": source_version,
                    "attempt_id": attempt_id,
                    "status": status,
                },
                artifacts=candidate_eval_artifacts,
                expected_head=weights.hash,
            )
            candidate_eval_seq = candidate_eval.seq
        request = PromotionRequest(
            attempt_id=attempt_id,
            step=step,
            source_policy_version=source_version,
            config_seq=config_seq,
            rollout_batch_seq=batch.seq,
            eval_result_seq=source_eval.seq,
            checkpoint_seq=weights.seq,
            candidate_eval_config_seq=candidate_eval_config_seq,
            candidate_eval_seq=candidate_eval_seq,
        )
        self._requests[step] = request
        return request


def _build_barrier(config: object) -> PrimeRLPromotionBarrier:
    weight_broadcast = getattr(config, "weight_broadcast", None)
    if getattr(weight_broadcast, "type", None) != "filesystem":
        raise PrimeRLIntegrationError("governed mode requires weight_broadcast.type='filesystem'")
    ckpt = getattr(config, "ckpt", None)
    if ckpt is not None and getattr(ckpt, "resume_step", None) is not None:
        raise PrimeRLIntegrationError("governed MVP supports fresh runs only; resume is not yet reconciled")
    charter_source = os.environ.get("FILIOLAE_CHARTER")
    if not charter_source:
        raise PrimeRLIntegrationError("FILIOLAE_CHARTER is required")
    source_charter = Charter.load(charter_source)
    if source_charter.candidate_eval_policy() is not None:
        raise PrimeRLIntegrationError(
            "candidate shadow-evaluation Charter requires an external evaluator; "
            "only the CPU mock control plane is implemented in this milestone"
        )
    output_dir = Path(config.output_dir).resolve()
    anchor_key_value = os.environ.get("FILIOLAE_LOCAL_ANCHOR_PRIVATE_KEY")
    anchor_dir_value = os.environ.get("FILIOLAE_LOCAL_ANCHOR_DIR")
    witness_values = {
        "socket": os.environ.get("FILIOLAE_ANCHOR_WITNESS_SOCKET"),
        "public_key": os.environ.get("FILIOLAE_ANCHOR_WITNESS_PUBLIC_KEY"),
        "mirror_dir": os.environ.get("FILIOLAE_ANCHOR_WITNESS_MIRROR_DIR"),
        "ledger_lock": os.environ.get("FILIOLAE_LEDGER_LOCK_PATH"),
        "ledger_gid": os.environ.get("FILIOLAE_LEDGER_SHARED_GID"),
        "run_id": os.environ.get("FILIOLAE_RUN_ID"),
        "enrollment_sha256": os.environ.get("FILIOLAE_WITNESS_ENROLLMENT_SHA256"),
    }
    local_configured = bool(anchor_key_value or anchor_dir_value)
    witness_configured = any(witness_values.values())
    if bool(anchor_key_value) != bool(anchor_dir_value):
        raise PrimeRLIntegrationError(
            "local anchoring requires both FILIOLAE_LOCAL_ANCHOR_PRIVATE_KEY and FILIOLAE_LOCAL_ANCHOR_DIR"
        )
    if witness_configured and not all(witness_values.values()):
        raise PrimeRLIntegrationError(
            "witness anchoring requires socket, public key, mirror directory, fixed Ledger lock, "
            "shared GID, an explicitly enrolled run ID, and its enrollment digest"
        )
    if local_configured and witness_configured:
        raise PrimeRLIntegrationError("local and witness anchor modes are mutually exclusive")

    head_anchor: HeadAnchor | None = None
    anchor_store: AnchorStore | None = None
    anchor_public_key = None
    ledger_lock_path: Path | None = None
    ledger_shared_gid: int | None = None
    if local_configured:
        assert anchor_key_value is not None and anchor_dir_value is not None
        anchor_key_input = Path(anchor_key_value).absolute()
        private_key = load_private_key(anchor_key_input)
        anchor_key_path = anchor_key_input.resolve(strict=True)
        anchor_dir = Path(anchor_dir_value).resolve()
        if anchor_key_path.is_relative_to(output_dir) or anchor_dir.is_relative_to(output_dir):
            raise PrimeRLIntegrationError("local anchor key/store must be outside the governed output")
        local_anchor = LocalEd25519HeadAnchor(AnchorStore(anchor_dir), private_key)
        head_anchor = local_anchor
        anchor_store = local_anchor.store
        anchor_public_key = private_key.public_key()
    elif witness_configured:
        socket_path = Path(os.path.abspath(witness_values["socket"] or ""))
        public_key_input = Path(os.path.abspath(witness_values["public_key"] or ""))
        mirror_dir = Path(os.path.abspath(witness_values["mirror_dir"] or ""))
        ledger_lock_path = Path(os.path.abspath(witness_values["ledger_lock"] or ""))
        try:
            ledger_shared_gid = int(witness_values["ledger_gid"] or "")
        except ValueError as exc:
            raise PrimeRLIntegrationError("shared Ledger GID must be a nonnegative integer") from exc
        if ledger_shared_gid < 0:
            raise PrimeRLIntegrationError("shared Ledger GID must be a nonnegative integer")
        enrolled_run_id = witness_values["run_id"] or ""
        if not enrolled_run_id or len(enrolled_run_id) > 256:
            raise PrimeRLIntegrationError("witness run ID must be a non-empty bounded string")
        enrollment_sha256 = witness_values["enrollment_sha256"] or ""
        if len(enrollment_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in enrollment_sha256
        ):
            raise PrimeRLIntegrationError("witness enrollment digest must be lowercase SHA-256")
        try:
            lock_info = ledger_lock_path.lstat()
        except OSError as exc:
            raise PrimeRLIntegrationError("witness Ledger lock is unavailable") from exc
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or ledger_lock_path.is_symlink()
            or lock_info.st_gid != ledger_shared_gid
            or lock_info.st_mode & 0o777 != 0o660
        ):
            raise PrimeRLIntegrationError(
                "witness Ledger lock must be a regular mode-0660 file in the configured shared GID"
            )
        for protected_path in (socket_path, public_key_input, mirror_dir, ledger_lock_path):
            _reject_symlink_components(protected_path)
            if protected_path.is_relative_to(output_dir):
                raise PrimeRLIntegrationError("witness paths must be outside the governed output")
        socket_info = socket_path.lstat()
        if not stat.S_ISSOCK(socket_info.st_mode):
            raise PrimeRLIntegrationError("witness socket path is not a Unix socket")
        public_key = load_public_key(public_key_input)
        try:
            timeout = float(os.environ.get("FILIOLAE_ANCHOR_WITNESS_TIMEOUT_SECONDS", "10"))
        except ValueError as exc:
            raise PrimeRLIntegrationError("witness timeout must be numeric") from exc
        if not 0 < timeout <= 300:
            raise PrimeRLIntegrationError("witness timeout must be in (0, 300] seconds")
        anchor_store = AnchorStore(mirror_dir)
        remote_anchor = UnixSocketHeadAnchor(
            socket_path,
            anchor_store,
            public_key,
            timeout=timeout,
        )
        head_anchor = remote_anchor
        anchor_public_key = public_key
    governance_dir = output_dir / "control" / "filiolae"
    governance_dir.mkdir(parents=True, exist_ok=False)
    if witness_configured:
        assert ledger_shared_gid is not None
        for shared_directory in (output_dir, output_dir / "control", governance_dir):
            os.chown(shared_directory, -1, ledger_shared_gid, follow_symlinks=False)
            os.chmod(shared_directory, 0o750, follow_symlinks=False)
    charter_copy = governance_dir / "charter.yaml"
    shutil.copyfile(charter_source, charter_copy, follow_symlinks=False)
    charter = Charter.load(charter_copy)
    if charter.sha256 != source_charter.sha256:
        raise PrimeRLIntegrationError("copied Charter digest changed during launcher setup")
    store = ArtifactStore(governance_dir / "artifacts")
    ledger = Ledger.create(
        governance_dir / "ledger.jsonl",
        artifact_root=store.root,
        run_id=(witness_values["run_id"] or "") if witness_configured else uuid.uuid4().hex,
        charter_sha256=charter.sha256,
        metadata={
            "host": "prime-rl@v0.8.0",
            "transport": "filesystem",
            "candidate_quality_evaluated": False,
            "head_anchors_required": head_anchor is not None,
            "anchor_kind": head_anchor and head_anchor.anchor_kind,
            "anchor_signer_key_id": head_anchor and head_anchor.signer_key_id,
            "witness_enrollment_sha256": (
                witness_values["enrollment_sha256"] if witness_configured else None
            ),
        },
        lock_path=ledger_lock_path,
        require_existing_lock=witness_configured,
    )
    if witness_configured:
        assert ledger_shared_gid is not None
        descriptor = os.open(ledger.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fchown(descriptor, -1, ledger_shared_gid)
            os.fchmod(descriptor, 0o640)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    freezer = FreezeController(governance_dir / "freeze.json")
    gate = PromotionGate(
        ledger,
        charter,
        freezer,
        head_anchor=head_anchor,
        anchor_store=anchor_store,
        anchor_public_key=anchor_public_key,
        require_head_anchor=head_anchor is not None,
    )
    if head_anchor is not None:
        try:
            gate.anchor_current_head()
        except BaseException as exc:
            freezer.freeze(f"initial Ledger-head anchoring failed: {exc}")
            raise
    builder = PrimeRLEvidenceBuilder(output_dir, ledger, store)
    return PrimeRLPromotionBarrier(gate, builder.request_for_step)


async def run_governed_orchestrator(config: object) -> None:
    from prime_rl.orchestrator.orchestrator import Orchestrator
    from prime_rl.utils.utils import clean_exit

    barrier = await asyncio.wait_for(asyncio.to_thread(_build_barrier, config), timeout=600)

    def record_exit_sync(status: str, error: BaseException | None = None) -> None:
        barrier.gate.ledger.append(
            "run.exited",
            actor="service:filiolae-prime-rl",
            data={"status": status, "error": repr(error) if error is not None else None},
        )
        barrier.gate.anchor_current_head()

    async def record_exit(status: str, error: BaseException | None = None) -> None:
        await asyncio.wait_for(
            asyncio.to_thread(record_exit_sync, status, error),
            timeout=600,
        )

    @clean_exit
    async def start() -> None:
        try:
            orchestrator = Orchestrator(config, promotion_barrier=barrier)
            await orchestrator.start()
        except BaseException as exc:
            try:
                await record_exit("failed", exc)
            except BaseException as record_error:
                barrier.gate.freezer.freeze(
                    f"could not record/anchor governed run exit: {record_error}",
                )
            raise
        else:
            try:
                await record_exit("success")
            except BaseException as record_error:
                barrier.gate.freezer.freeze(
                    f"could not record/anchor governed run exit: {record_error}",
                )
                raise

    await start()


def governed_orchestrator_main() -> None:
    from prime_rl.configs.orchestrator import OrchestratorConfig
    from prime_rl.utils.config import cli
    from prime_rl.utils.process import set_proc_title

    set_proc_title("Filiolae Governed Orchestrator")
    config = cli(OrchestratorConfig)
    import uvloop

    uvloop.install()
    asyncio.run(run_governed_orchestrator(config))


def filiolae_rl_main() -> None:
    os.environ["PRIME_RL_ORCHESTRATOR_ENTRYPOINT"] = "filiolae-prime-rl-orchestrator"
    from prime_rl.entrypoints.rl import main

    main()
