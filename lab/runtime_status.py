"""Read-only base compliance and scoped trusted-tool privacy summaries."""
from datetime import datetime

from lab.privacy import validate_privacy_proof


def _object(value):
    return value if isinstance(value, dict) else {}


def privacy_proof_summary(proof, scope="base", ready=True):
    verified = ready and validate_privacy_proof(proof)
    detail = "Prova della privacy assente, incompleta o incoerente: protezioni e assenza di account non vengono indicate come verificate."
    if verified:
        detail = ("Prova della base" if scope == "base" else "Prova del clone prima del trasferimento") + ": Defender locale attivo, cloud e invio campioni disabilitati; WER e invii automatici dei tool controllati disabilitati, MDE non iscritto. Edge chiuso e archivi di autenticazione assenti; policy login/sync configurate, adozione runtime non dimostrata."
        if scope == "base":
            detail += " Ogni clone viene ricontrollato prima del campione."
    return {
        "status": "verified" if verified else "unverified", "verified": verified,
        "proof_scope": scope, "runtime_recheck_required": scope == "base",
        "defender": {"status": "verified" if verified else "unverified",
                     "local_active": True if verified else None,
                     "cloud_reporting_disabled": True if verified else None,
                     "automatic_sample_submission_disabled": True if verified else None},
        "edge": {"status": "verified" if verified else "unverified",
                 "login_policy_configured": True if verified else None,
                 "sync_policy_configured": True if verified else None,
                 "browser_closed": True if verified else None,
                 "authentication_stores_absent": True if verified else None,
                 "runtime_policy_adoption_verified": False if verified else None},
        "trusted_tools": {"automatic_reputation_disabled": True if verified else None,
                          "automatic_submission_disabled": True if verified else None,
                          "windows_error_reporting_disabled": True if verified else None,
                          "mde_not_onboarded": True if verified else None},
        "automatic_sample_uploads": False if verified else None,
        "external_lookup": {"mode": "sha256_only", "sample_uploads": False,
                            "unknown_hash_uploads": False,
                            "detail": "VirusTotal e Hybrid Analysis: solo lookup SHA-256 opt-in; hash sconosciuto non avvia upload del file."},
        "separation": {"status": "configured", "analysis_clones": "disposable",
                       "base_state": "immutable_separate",
                       "detail": "Disposable analysis clones use their own disk, TPM and UEFI state. Cleanup does not modify the clean base or the source VM."},
        "detail": detail,
        "internet_caveat": "Le policy dei programmi fidati non impediscono al campione stesso di comunicare o inviare file a servizi Internet pubblici.",
    }


def privacy_status(base):
    base = _object(base)
    metadata = _object(base.get("metadata"))
    return privacy_proof_summary(metadata.get("privacy"), ready=(
        base.get("status") == "ready" and metadata.get("ready") is True))


def _now(value=None):
    return (value or datetime.now().astimezone()).astimezone() if value is None or value.tzinfo is None else value


def runtime_status(base, now=None):
    return {"checked_at": _now(now).isoformat(), "privacy": privacy_status(base)}
