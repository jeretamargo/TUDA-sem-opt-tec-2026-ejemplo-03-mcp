"""Seguridad del laboratorio 04: validación, confirmación del host y auditoría.

Diseño (defendible en el cierre oral):

- Validación en el borde MCP, antes de tocar el dominio. Falla cerrado
  con ``ValidationError`` -> el servidor lo convierte en
  ``{"status": ..., "message": ...}`` accionable, sin trazas internas.
- Confirmación human-in-the-loop con token opaco de un solo uso y dos
  estados: emitido y aprobado por el host:
  el modelo NO puede inventar un ``confirmation_id`` válido porque es un
  token aleatorio (``secrets.token_urlsafe``) emitido por
  ``request_registration_confirmation`` y guardado sólo en el servidor,
  atado a un par (activity_id, student_email), con TTL y un solo uso.
  Un booleano ``confirmed=true`` nunca se acepta: sería falsificable
  por el modelo. Emitir el token no basta: sólo el adaptador confiable del
  host puede marcarlo como aprobado tras recibir el "sí" de la persona.
- Idempotencia en dos capas: el token es de un solo uso (reuso ->
  ``confirmation_reused``, no re-ejecuta) y el dominio tiene constraint
  único (activity, student_email) -> ``already_registered`` sin duplicar.
- Auditoría append-only en JSONL (``audit_log.jsonl``): quién (email
  normalizado), qué (activity_id), cuándo (UTC), con qué token y con
  qué resultado. No se expone como resource ni tool: sólo lo lee el
  operador del servidor.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Errores (todos se convierten en dicts accionables en server.py, nunca trazas)
# ---------------------------------------------------------------------------


class ValidationError(ValueError):
    """Error de entrada que puede convertirse en una respuesta para el host."""


class ConfirmationRequired(PermissionError):
    """La acción mutable no debe ejecutarse sin confirmación humana."""


class ConfirmationInvalid(ConfirmationRequired):
    """El confirmation_id no existe o ya fue consumido."""


class ConfirmationExpired(ConfirmationRequired):
    """El confirmation_id venció (TTL agotado)."""


class ConfirmationMismatch(ConfirmationRequired):
    """El confirmation_id no corresponde a este (activity_id, email)."""


class ConfirmationPendingApproval(ConfirmationRequired):
    """El host todavía no registró la aprobación humana."""


# ---------------------------------------------------------------------------
# Validación de entradas (borde MCP, antes del dominio)
# ---------------------------------------------------------------------------

MAX_QUERY_LENGTH = 100
MAX_EMAIL_LENGTH = 254
MAX_ACTIVITY_ID_DIGITS = 9  # evita IDs absurdos / overflow

# Regex razonable (no RFC completa a propósito): en producción se reutiliza
# la validación del service layer Django (_normalize_email). Suficiente para
# el laboratorio y mucho más estricta que `"@" in value`.
_EMAIL_RE = re.compile(r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$")
_ACTIVITY_ID_RE = re.compile(r"^[0-9]+$")


def validate_activity_id(activity_id: object) -> str:
    """Valida que activity_id sea un entero positivo en forma de string.

    El dominio Django usa PK numérica (``_coerce_id`` hace ``int(...)``),
    así que el formato real exigido es ese. Normaliza a string sin ceros
    a la izquierda (``"007"`` -> ``"7"``).
    """
    if activity_id is None:
        raise ValidationError("activity_id es obligatorio")
    value = str(activity_id).strip()
    if not value:
        raise ValidationError("activity_id es obligatorio")
    if len(value) > MAX_ACTIVITY_ID_DIGITS + 1:
        raise ValidationError(
            f"activity_id inválido: {value!r} (demasiado largo)"
        )
    if not _ACTIVITY_ID_RE.match(value):
        raise ValidationError(
            f"activity_id inválido: {value!r} "
            "(debe ser un entero positivo, ej. '1', '12')"
        )
    if int(value) <= 0:
        raise ValidationError(
            f"activity_id inválido: {value!r} "
            "(debe ser un entero positivo, ej. '1', '12')"
        )
    return str(int(value))  # normaliza "007" -> "7"


def validate_email(student_email: object) -> str:
    """Valida y normaliza un email (trim + minúsculas + forma válida)."""
    if student_email is None:
        raise ValidationError("student_email es obligatorio")
    value = str(student_email).strip().lower()
    if not value:
        raise ValidationError("student_email es obligatorio")
    if len(value) > MAX_EMAIL_LENGTH:
        raise ValidationError("student_email debe ser un correo válido")
    if value.count("@") != 1:
        raise ValidationError(
            f"student_email debe ser un correo válido: {str(student_email)!r}"
        )
    local, _, domain = value.partition("@")
    if not local or not domain or len(local) > 64:
        raise ValidationError(
            f"student_email debe ser un correo válido: {str(student_email)!r}"
        )
    if ".." in value or value.startswith((".", "-", "@")):
        raise ValidationError(
            f"student_email debe ser un correo válido: {str(student_email)!r}"
        )
    if not _EMAIL_RE.match(value) or "." not in domain:
        raise ValidationError(
            f"student_email debe ser un correo válido: {str(student_email)!r}"
        )
    return value


def validate_query(query: object, max_length: int = MAX_QUERY_LENGTH) -> str:
    """Limpia la query de búsqueda: recorta y limita longitud."""
    text = str(query or "").strip()
    return text[:max_length]


# ---------------------------------------------------------------------------
# Confirmación del host: tokens opacos de un solo uso
# ---------------------------------------------------------------------------

DEFAULT_CONFIRMATION_TTL_SECONDS = 600  # 10 minutos


@dataclass
class PendingConfirmation:
    activity_id: str
    student_email: str
    created_at: datetime
    expires_at: datetime
    used: bool = False
    approved_at: datetime | None = None
    approved_by: str = ""


@dataclass(frozen=True)
class HostApproval:
    """Aprobación que el adaptador confiable del host registró."""

    activity_id: str
    student_email: str
    confirmation_id: str
    approved_at: datetime
    approved_by: str
    newly_approved: bool


class ConfirmationStore:
    """Emite y consume tokens de confirmación.

    En producción este store viviría en el host/sesión con identidad del
    usuario (quién confirmó y cuándo). Aquí se simula en el proceso del
    servidor con las mismas propiedades de seguridad: token impredecible,
    atado a (activity_id, email), con vencimiento y un solo uso.
    """

    def __init__(self, ttl_seconds: int = DEFAULT_CONFIRMATION_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._pending: dict[str, PendingConfirmation] = {}
        self._lock = threading.Lock()

    def issue(self, activity_id: str, student_email: str) -> str:
        token = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        with self._lock:
            self._pending[token] = PendingConfirmation(
                activity_id=activity_id,
                student_email=student_email,
                created_at=now,
                expires_at=now + timedelta(seconds=self._ttl),
            )
        return token

    def peek_valid(
        self,
        confirmation_id: str | None,
        activity_id: str,
        student_email: str,
    ) -> bool:
        """True si el token existe, no venció, no se usó y matchea el par."""
        return (
            self.failure_reason(confirmation_id, activity_id, student_email)
            is None
        )

    def approval_failure_reason(
        self,
        confirmation_id: str | None,
        activity_id: str,
        student_email: str,
    ) -> ConfirmationRequired | None:
        """Causa de rechazo para la acción mutable, incluida la aprobación."""
        if not confirmation_id or not str(confirmation_id).strip():
            return self.failure_reason(confirmation_id, activity_id, student_email)
        with self._lock:
            reason = self._check_locked(
                str(confirmation_id).strip(), activity_id, student_email
            )
            if reason is not None:
                return reason
            pending = self._pending[str(confirmation_id).strip()]
            if pending.approved_at is None:
                return ConfirmationPendingApproval(
                    "La solicitud está pendiente de aprobación humana en el host. "
                    "Mostrá el resumen y esperá el 'sí' antes de inscribir."
                )
            return None

    def approve_from_host(
        self, confirmation_id: str | None, approved_by: str
    ) -> HostApproval:
        """Registra el sí humano desde código confiable del host.

        Esta función no es una tool MCP. El adaptador del host debe invocarla
        únicamente después de mostrar el resumen y obtener la aprobación.
        """
        token = str(confirmation_id or "").strip()
        actor = str(approved_by or "").strip()
        if not actor:
            raise ValueError("approved_by es obligatorio para auditar la aprobación")
        with self._lock:
            pending = self._pending.get(token)
            if pending is None or pending.used:
                raise ConfirmationInvalid(
                    "confirmation_id inválido o ya utilizado. "
                    "Solicitá uno nuevo con `request_registration_confirmation`."
                )
            if datetime.now(timezone.utc) > pending.expires_at:
                raise ConfirmationExpired(
                    "La confirmación venció. "
                    "Solicitá una nueva con `request_registration_confirmation`."
                )
            if pending.approved_at is not None:
                return HostApproval(
                    activity_id=pending.activity_id,
                    student_email=pending.student_email,
                    confirmation_id=token,
                    approved_at=pending.approved_at,
                    approved_by=pending.approved_by,
                    newly_approved=False,
                )
            pending.approved_at = datetime.now(timezone.utc)
            pending.approved_by = actor
            return HostApproval(
                activity_id=pending.activity_id,
                student_email=pending.student_email,
                confirmation_id=token,
                approved_at=pending.approved_at,
                approved_by=actor,
                newly_approved=True,
            )

    def failure_reason(
        self,
        confirmation_id: str | None,
        activity_id: str,
        student_email: str,
    ) -> ConfirmationRequired | None:
        """Causa del rechazo sin mutar nada (None = válido).

        Permite devolver mensajes específicos y accionables sin consumir
        el token. Única fuente de verdad: ``consume()`` la reutiliza.
        """
        if not confirmation_id or not str(confirmation_id).strip():
            return ConfirmationRequired(
                "Se requiere confirmación antes de inscribir. "
                "Llamá primero a `request_registration_confirmation` y "
                "pedí aprobación explícita al humano en el host."
            )
        with self._lock:
            return self._check_locked(
                str(confirmation_id).strip(), activity_id, student_email
            )

    def _check_locked(
        self, token: str, activity_id: str, student_email: str
    ) -> ConfirmationRequired | None:
        pending = self._pending.get(token)
        if pending is None or pending.used:
            return ConfirmationInvalid(
                "confirmation_id inválido o ya utilizado. "
                "Solicitá uno nuevo con `request_registration_confirmation`."
            )
        if datetime.now(timezone.utc) > pending.expires_at:
            return ConfirmationExpired(
                "La confirmación venció. "
                "Solicitá una nueva con `request_registration_confirmation`."
            )
        if (
            pending.activity_id != activity_id
            or pending.student_email != student_email
        ):
            return ConfirmationMismatch(
                "La confirmación no corresponde a este "
                "activity_id/student_email. Solicitá una nueva confirmación "
                "para estos valores exactos."
            )
        return None

    def consume(
        self,
        confirmation_id: str | None,
        activity_id: str,
        student_email: str,
    ) -> None:
        """Valida y marca el token como usado. Lanza ConfirmationRequired."""
        reason = self.approval_failure_reason(
            confirmation_id, activity_id, student_email
        )
        if reason is not None:
            raise reason
        with self._lock:
            # Re-chequeo atómico bajo lock: evita doble uso en carrera.
            reason = self._check_locked(
                str(confirmation_id).strip(), activity_id, student_email
            )
            if reason is not None:
                raise reason
            pending = self._pending[str(confirmation_id).strip()]
            if pending.approved_at is None:
                raise ConfirmationPendingApproval(
                    "La solicitud está pendiente de aprobación humana en el host. "
                    "Mostrá el resumen y esperá el 'sí' antes de inscribir."
                )
            pending.used = True


# Store global del proceso (el servidor MCP corre en un solo proceso stdio).
confirmation_store = ConfirmationStore()


def require_human_confirmation(confirmed_by_host: bool) -> None:
    # La confirmación debe provenir del host o de una interfaz humana; no de una
    # afirmación inventada por el modelo. El mecanismo concreto es el
    # ConfirmationStore (token opaco), no un booleano del modelo.
    if not confirmed_by_host:
        raise ConfirmationRequired(
            "Se requiere confirmación antes de inscribir. "
            "Llamá primero a `request_registration_confirmation` y "
            "pedí aprobación explícita al humano en el host."
        )


def is_host_confirmation_valid(
    confirmation_id: str | None,
    activity_id: str | None = None,
    student_email: str | None = None,
) -> bool:
    """Verifica una confirmación emitida por el host, no por el modelo.

    Falla cerrado: ``None``/desconocido/usado/vencido/desatado/sin aprobación
    del host -> ``False``.
    Cuando se conocen ``activity_id`` y ``student_email`` también se exige
    el binding; sin ellos se chequea existencia, vigencia y aprobación. Nunca
    se usa como única barrera: ``register`` siempre usa ``consume`` con
    binding.
    """
    if not confirmation_id:
        return False
    if activity_id is None or student_email is None:
        with confirmation_store._lock:
            pending = confirmation_store._pending.get(str(confirmation_id).strip())
            if pending is None or pending.used or pending.approved_at is None:
                return False
            return datetime.now(timezone.utc) <= pending.expires_at
    return confirmation_store.approval_failure_reason(
        str(confirmation_id).strip(), activity_id, student_email
    ) is None


# ---------------------------------------------------------------------------
# Auditoría
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditEvent:
    activity_id: str
    student_email: str
    requested_at: datetime
    confirmation_id: str = ""
    result: str = "ok"
    detail: str = ""
    approved_by: str = ""


def new_audit_event(
    activity_id: str,
    student_email: str,
    confirmation_id: str = "",
    result: str = "ok",
    detail: str = "",
    approved_by: str = "",
) -> AuditEvent:
    return AuditEvent(
        activity_id=activity_id,
        student_email=student_email,
        requested_at=datetime.now(timezone.utc),
        confirmation_id=confirmation_id,
        result=result,
        detail=detail,
        approved_by=approved_by,
    )


@dataclass
class AuditLog:
    """Registro append-only en JSONL. No se expone vía MCP.

    Quién puede leerlo: sólo el operador del servidor (dueño del archivo).
    Cada línea es un evento con quién/cuándo/qué/resultado.
    """

    path: str = field(
        default_factory=lambda: os.environ.get(
            "MCP_AUDIT_FILE",
            str(_default_audit_path()),
        )
    )
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, event: AuditEvent) -> None:
        line = json.dumps(
            {
                "requested_at": event.requested_at.isoformat(),
                "activity_id": event.activity_id,
                "student_email": event.student_email,
                "confirmation_id": event.confirmation_id,
                "result": event.result,
                "detail": event.detail,
                "approved_by": event.approved_by,
            },
            ensure_ascii=False,
        )
        logger.info("Audit event: %s", line)
        try:
            with self._lock:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
        except OSError:
            logger.exception("No se pudo persistir el evento de auditoría")


def _default_audit_path() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "audit_log.jsonl")
