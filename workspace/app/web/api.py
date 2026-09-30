"""平台 REST API。

角色：
  technician  入库、重试、人工质检
  clinician   发起回链、提交分片 A、纠错、导出
  officer     双角色第二授权人、撤销
  admin       策略登记、审计导出
"""
from __future__ import annotations

import io
import json
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

from ..core import dicomutil, store
from ..services import (audit as audit_svc, ingest as ingest_svc,
                        policies as policies_svc, queue, reidentify,
                        versions as versions_svc)
from .auth import require_role

app = FastAPI(title="医学影像去标识化与受控回链平台", version="1.0.0")


@app.on_event("startup")
def _startup():
    store.init_db()
    # 默认项目策略 v1（不存在时播种）
    try:
        policies_svc.latest_policy("project-default")
    except store.NotFound:
        policies_svc.register_policy(
            "project-default", dicomutil.default_policy("strict"), "system")


@app.get("/health")
def health():
    return {"status": "ok"}


# ---------- 模型 ----------

class IngestBody(BaseModel):
    patient_id: str = "MRN-48213"
    patient_name: str = "ZHANG^WEI"
    accession: str = "ACC-77881"
    policy_id: Optional[str] = None
    fault_inject: Optional[str] = Field(
        None, description="redaction=遮盖子系统异常; qc_leak=跳过遮盖以验证质检门")


class PolicyBody(BaseModel):
    name: str = "project-default"
    level: str = "strict"
    content: Optional[dict] = None
    version: Optional[int] = None


class RequeueBody(BaseModel):
    job_id: str
    clear_fault: bool = True


class QCBody(BaseModel):
    version_id: str
    approve: bool
    note: str = ""


class DeriveBody(BaseModel):
    study_id: str
    policy_id: Optional[str] = None
    reason: str = "policy upgrade re-derivation"


class RelinkBody(BaseModel):
    study_id: str
    purpose: str = "clinical correction 2026-09"
    window_minutes: int = 30


class ShareBody(BaseModel):
    share: str


class CorrectionBody(BaseModel):
    corrected: dict


class RevokeBody(BaseModel):
    reason: str = "privacy officer revocation"


def _conflict(exc: Exception):
    raise HTTPException(status_code=409, detail=str(exc))


# ---------- 策略 ----------

@app.post("/api/policies", tags=["policies"])
def create_policy(body: PolicyBody, user=Depends(require_role("admin"))):
    content = body.content or dicomutil.default_policy(body.level)
    return policies_svc.register_policy(body.name, content, user["username"],
                                        version=body.version)


@app.get("/api/policies", tags=["policies"])
def list_policies(user=Depends(require_role("technician", "clinician", "officer", "admin"))):
    return policies_svc.list_policies()


# ---------- 入库与队列 ----------

@app.post("/api/studies/ingest-synthetic", tags=["studies"])
def ingest_synthetic(body: IngestBody, user=Depends(require_role("technician"))):
    data = dicomutil.build_synthetic_dicom(
        patient_id=body.patient_id, patient_name=body.patient_name,
        accession=body.accession)
    try:
        return ingest_svc.ingest_study(
            data, user["username"], body.policy_id,
            fault_inject=body.fault_inject)
    except store.ConflictError as exc:
        _conflict(exc)


@app.post("/api/studies/ingest", tags=["studies"])
def ingest_upload(file: bytes = b"", user=Depends(require_role("technician")),
                  x_policy_id: Optional[str] = None,
                  x_fault_inject: Optional[str] = None):
    if not file:
        raise HTTPException(status_code=400, detail="empty DICOM payload")
    return ingest_svc.ingest_study(file, user["username"], x_policy_id,
                                   fault_inject=x_fault_inject)


@app.get("/api/studies", tags=["studies"])
def list_studies(user=Depends(require_role("technician", "clinician", "officer", "admin"))):
    return ingest_svc.list_studies()


@app.get("/api/studies/{study_id}", tags=["studies"])
def get_study(study_id: str, user=Depends(require_role("technician", "clinician", "admin"))):
    try:
        study = ingest_svc.get_study(study_id)
    except store.NotFound:
        raise HTTPException(404, "study not found")
    study.pop("identity_fp", None)  # 不向前端返回身份指纹以外的原身份
    return {"study": study, "versions": versions_svc.list_versions(study_id)}


@app.get("/api/studies/{study_id}/frozen-summary", tags=["studies"])
def frozen_summary(study_id: str, user=Depends(require_role("technician", "admin"))):
    try:
        summary = ingest_svc.frozen_summary(study_id)
    except store.NotFound:
        raise HTTPException(404, "study not found")
    summary.get("identity", {}).clear()  # 冻结摘要可查结构，但不通过普通接口暴露原身份
    return summary


@app.post("/api/versions/derive", tags=["versions"])
def derive(body: DeriveBody, user=Depends(require_role("technician"))):
    try:
        return versions_svc.create_version(
            body.study_id, user["username"], policy_id=body.policy_id, reason=body.reason)
    except store.ConflictError as exc:
        _conflict(exc)
    except store.NotFound:
        raise HTTPException(404, "study not found")


# ---------- 处理队列 / Worker ----------

@app.post("/api/queue/run", tags=["queue"])
def run_worker(cycles: int = 1, ignore_backoff: bool = False,
               user=Depends(require_role("technician", "admin"))):
    results = []
    for _ in range(max(1, cycles)):
        r = queue.run_once(ignore_backoff=ignore_backoff)
        if r is None:
            break
        results.append(r)
    return {"processed": results}


@app.get("/api/queue/jobs", tags=["queue"])
def get_jobs(status: Optional[str] = None,
             user=Depends(require_role("technician", "admin"))):
    return queue.list_jobs(status)


@app.post("/api/queue/requeue", tags=["queue"])
def requeue(body: RequeueBody, user=Depends(require_role("technician"))):
    try:
        return queue.requeue(body.job_id, user["username"],
                             payload_override={} if body.clear_fault else None)
    except store.ConflictError as exc:
        _conflict(exc)
    except store.NotFound:
        raise HTTPException(404, "job not found")


# ---------- 质检界面 ----------

@app.get("/api/qc/queue", tags=["qc"])
def qc_queue(status: Optional[str] = None,
             user=Depends(require_role("technician", "admin"))):
    return versions_svc.list_qc_queue(status)


@app.get("/api/versions/{version_id}", tags=["qc"])
def version_detail(version_id: str, user=Depends(require_role("technician", "admin"))):
    try:
        return versions_svc.get_version(version_id)
    except store.NotFound:
        raise HTTPException(404, "version not found")


@app.get("/api/versions/{version_id}/preview", tags=["qc"])
def version_preview(version_id: str, user=Depends(require_role("technician", "admin"))):
    ver = versions_svc.get_version(version_id)
    if not ver.get("derived_cas_id"):
        raise HTTPException(409, "no derived artifact yet")
    data = store.sealed_blob_get(ver["derived_cas_id"])
    return Response(content=dicomutil.render_preview_png(data), media_type="image/png")


@app.post("/api/qc/review", tags=["qc"])
def qc_review(body: QCBody, user=Depends(require_role("technician"))):
    try:
        return versions_svc.manual_qc(body.version_id, user["username"],
                                      body.approve, body.note)
    except store.ConflictError as exc:
        _conflict(exc)
    except store.NotFound:
        raise HTTPException(404, "version not found")


# ---------- 受控回链 ----------

@app.post("/api/relink/request", tags=["relink"])
def relink_request(body: RelinkBody, user=Depends(require_role("clinician"))):
    try:
        return reidentify.request_relink(body.study_id, user["username"],
                                         body.purpose, body.window_minutes)
    except store.ConflictError as exc:
        _conflict(exc)
    except store.NotFound:
        raise HTTPException(404, "study not found")


@app.post("/api/relink/{reid_id}/share-a", tags=["relink"])
def relink_share_a(reid_id: str, body: ShareBody,
                   user=Depends(require_role("clinician"))):
    try:
        return reidentify.submit_share(reid_id, user["username"], "clinician", body.share)
    except store.ConflictError as exc:
        _conflict(exc)
    except store.NotFound:
        raise HTTPException(404, "reidentification not found")


@app.get("/api/relink/officer/pending", tags=["relink"])
def officer_pending(user=Depends(require_role("officer"))):
    return reidentify.officer_pending(user["username"])


@app.post("/api/relink/{reid_id}/share-b", tags=["relink"])
def relink_share_b(reid_id: str, body: ShareBody,
                   user=Depends(require_role("officer"))):
    try:
        return reidentify.submit_share(reid_id, user["username"], "officer", body.share)
    except store.ConflictError as exc:
        _conflict(exc)
    except store.NotFound:
        raise HTTPException(404, "reidentification not found")


@app.post("/api/relink/{reid_id}/correction", tags=["relink"])
def relink_correction(reid_id: str, body: CorrectionBody,
                      user=Depends(require_role("clinician"))):
    try:
        return reidentify.submit_correction(
            reid_id, user["username"], body.corrected)
    except store.ConflictError as exc:
        _conflict(exc)
    except store.NotFound:
        raise HTTPException(404, "reidentification not found")


@app.post("/api/relink/{reid_id}/export", tags=["relink"])
def relink_export(reid_id: str, user=Depends(require_role("clinician"))):
    try:
        return reidentify.export_relink(reid_id, user["username"])
    except store.ConflictError as exc:
        _conflict(exc)
    except store.NotFound:
        raise HTTPException(404, "reidentification not found")


@app.post("/api/relink/{reid_id}/revoke", tags=["relink"])
def relink_revoke(reid_id: str, body: RevokeBody,
                  user=Depends(require_role("officer", "admin"))):
    try:
        result = reidentify.revoke_relink(reid_id, user["username"], body.reason)
    except store.NotFound:
        raise HTTPException(404, "reidentification not found")
    if not result["revoked"] and result["status"] in ("exported", "revoked", "expired"):
        # 竞态落败或已终结：返回 409，不产生误导
        raise HTTPException(status_code=409,
                            detail=f"revocation did not take effect: {result['status']}")
    return result


@app.post("/api/relink/sweep", tags=["relink"])
def relink_sweep(user=Depends(require_role("officer", "admin"))):
    return {"expired": reidentify.sweep_expired(user["username"])}


@app.get("/api/relink", tags=["relink"])
def relink_list(status: Optional[str] = None, study_id: Optional[str] = None,
                user=Depends(require_role("officer", "admin"))):
    return reidentify.list_relinks(status=status, study_id=study_id)


# ---------- 审计导出 ----------

@app.get("/api/audit", tags=["audit"])
def audit_list(actor: Optional[str] = None, action: Optional[str] = None,
               study_id: Optional[str] = None, reid_id: Optional[str] = None,
               user=Depends(require_role("admin", "officer"))):
    return audit_svc.query(actor=actor, action=action, study_id=study_id,
                           reid_id=reid_id)


@app.get("/api/audit/verify", tags=["audit"])
def audit_verify(user=Depends(require_role("admin", "officer"))):
    return store.verify_audit_chain()


@app.post("/api/audit/export", tags=["audit"])
def audit_export(fmt: str = "json", user=Depends(require_role("admin"))):
    if fmt == "csv":
        return audit_svc.export_csv(user["username"])
    return audit_svc.export_jsonl(user["username"])


@app.get("/api/blobs/{cas_id}", tags=["audit"])
def download_blob(cas_id: str, user=Depends(require_role("admin"))):
    try:
        data = store.blob_get(cas_id)
    except store.NotFound:
        raise HTTPException(404, "blob not found")
    return Response(content=data, media_type="application/octet-stream")
