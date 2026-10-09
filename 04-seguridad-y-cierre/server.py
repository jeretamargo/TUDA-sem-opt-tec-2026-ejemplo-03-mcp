"""Servidor MCP seguro (etapa 04): validación, confirmación e idempotencia.

Capacidades:
- Resource `activities://available` — catálogo (sólo id/título/cupos).
- Resource `activities://{activity_id}` — detalle (sin datos sensibles).
- Tool `search_activities` — búsqueda (sólo lectura).
- Tool `request_registration_confirmation` — paso 1: valida y emite el
  token opaco que el HUMANO debe aprobar en el host.
- Tool `register_for_activity` — paso 2: sólo ejecuta con token válido.
- Prompt `guia_inscripcion` — flujo guiado que orquesta lo anterior.

Flujo exigido: modelo → `request_registration_confirmation` → el HOST
muestra el resumen al humano y pide "sí, confirmo" → el adaptador confiable
del host registra la aprobación → modelo llama `register_for_activity` con el
`confirmation_id` → dominio → resultado → auditoría. El modelo jamás puede
auto-confirmar.
"""

from mcp.server import MCPServer

from domain import (
    ActivityFull,
    ActivityNotFound,
    AlreadyRegistered,
    InvalidEmail,
    get_activity_service,
)
from security import (
    AuditLog,
    ConfirmationInvalid,
    ConfirmationRequired,
    ValidationError,
    confirmation_store,
    is_host_confirmation_valid,
    new_audit_event,
    require_human_confirmation,
    validate_activity_id,
    validate_email,
    validate_query,
)

mcp = MCPServer("Actividades seguras — laboratorio")
audit_log = AuditLog()


def approve_registration_confirmation_from_host(
    confirmation_id: str, approved_by: str
) -> dict[str, str]:
    """Registra una aprobación humana desde el adaptador confiable del host.

    No es una tool MCP deliberadamente: el modelo no debe poder invocarla.
    El host debe llamarla sólo tras mostrar el resumen de la solicitud y
    obtener una aceptación explícita. ``approved_by`` identifica la cuenta o
    sesión del host que aprobó, para dejar evidencia auditable.
    """
    try:
        approval = confirmation_store.approve_from_host(
            confirmation_id, approved_by
        )
    except (ConfirmationInvalid, ValueError) as error:
        return {"status": "confirmation_invalid", "message": str(error)}
    except ConfirmationRequired as error:
        return {"status": "confirmation_invalid", "message": str(error)}

    if approval.newly_approved:
        audit_log.record(
            new_audit_event(
                approval.activity_id,
                approval.student_email,
                confirmation_id=approval.confirmation_id,
                result="confirmation_approved",
                approved_by=approval.approved_by,
            )
        )
    return {
        "status": "confirmation_approved",
        "confirmation_id": approval.confirmation_id,
        "approved_at": approval.approved_at.isoformat(),
        "approved_by": approval.approved_by,
    }


# ---------------------------------------------------------------------------
# Resources (sólo información necesaria, nunca emails ni trazas)
# ---------------------------------------------------------------------------


@mcp.resource("activities://available")
def available_activities() -> str:
    """Catálogo legible de actividades con cupo (id, título, cupos)."""
    service = get_activity_service()
    items = service.list_available()
    if not items:
        return "# Actividades disponibles\n\n_No hay actividades con cupo._"
    lines = ["# Actividades disponibles", ""]
    for activity in items:
        lines.append(
            f"- **{activity.title}** (`{activity.id}`): "
            f"{activity.seats} cupos libres de {activity.capacity}"
        )
    return "\n".join(lines)


@mcp.resource("activities://{activity_id}")
def activity_detail(activity_id: str) -> str:
    """Detalle legible de una actividad (sin exponer inscriptos)."""
    try:
        safe_id = validate_activity_id(activity_id)
    except ValidationError as error:
        return f"validation_error: {error}"
    service = get_activity_service()
    try:
        activity = service.get_activity(safe_id)
    except ActivityNotFound:
        return f"activity_not_found: no existe la actividad `{safe_id}`"
    estado = "Disponible" if activity.available else "No disponible"
    return "\n".join(
        [
            f"# {activity.title}",
            "",
            f"- ID: `{activity.id}`",
            f"- Descripción: {activity.description}",
            f"- Cupos: {activity.seats} libres de {activity.capacity}",
            f"- Estado: {estado}",
        ]
    )


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def search_activities(
    query: str = "", only_available: bool = True
) -> list[dict[str, object]]:
    """Busca actividades por título (sólo lectura, sin efectos).

    Args:
        query: subcadena del título; vacío = todo el catálogo.
        only_available: si es True filtra a las que tienen cupo.
    Devuelve lista de {id, title, available, seats} (sin datos sensibles).
    """
    service = get_activity_service()
    results = service.search(validate_query(query), bool(only_available))
    return [
        {
            "id": a.id,
            "title": a.title,
            "available": a.available,
            "seats": a.seats,
        }
        for a in results
    ]


@mcp.tool()
def request_registration_confirmation(
    activity_id: str, student_email: str
) -> dict[str, str]:
    """Paso 1 de la inscripción: valida y emite un token para el HUMANO.

    NO inscribe. Devuelve `confirmation_id` + resumen para que el HOST lo
    muestre a la persona y le pida aprobación explícita. Recién después el
    modelo puede llamar a `register_for_activity` con ese token.
    El token es opaco, de un solo uso, atado a (activity_id, email) y vence
    en 10 minutos. Si ya está inscripto o no hay cupo, lo dice sin emitir.
    """
    try:
        safe_id = validate_activity_id(activity_id)
    except ValidationError as error:
        return {"status": "validation_error", "message": str(error)}
    try:
        safe_email = validate_email(student_email)
    except ValidationError as error:
        return {"status": "invalid_email", "message": str(error)}

    service = get_activity_service()
    try:
        activity = service.get_activity(safe_id)
    except ActivityNotFound:
        audit_log.record(
            new_audit_event(safe_id, safe_email, result="activity_not_found")
        )
        return {
            "status": "activity_not_found",
            "message": f"No existe la actividad `{safe_id}`. "
            "Leé `activities://available` para ver el catálogo.",
        }
    if service.is_registered(safe_id, safe_email):
        audit_log.record(
            new_audit_event(safe_id, safe_email, result="already_registered")
        )
        return {
            "status": "already_registered",
            "message": f"{safe_email} ya está inscripto en `{activity.title}`. "
            "No se emitió confirmación.",
        }
    if not activity.available:
        audit_log.record(
            new_audit_event(safe_id, safe_email, result="activity_full")
        )
        return {
            "status": "activity_full",
            "message": f"La actividad `{activity.title}` no tiene cupos. "
            "Elegí otra de `activities://available`.",
        }

    token = confirmation_store.issue(safe_id, safe_email)
    audit_log.record(
        new_audit_event(
            safe_id, safe_email, confirmation_id=token, result="confirmation_issued"
        )
    )
    return {
        "status": "confirmation_issued",
        "confirmation_id": token,
        "activity_id": safe_id,
        "student_email": safe_email,
        "summary": (
            f"Inscripción pendiente: {safe_email} → `{activity.title}` "
            f"(ID {safe_id}, {activity.seats} cupos libres). "
            "El HUMANO debe aprobarla en el host."
        ),
        "next_step": (
            "Mostrá este resumen al humano y pedí '¿Confirmás?'. "
            "El adaptador confiable del host debe registrar ese 'sí' antes de "
            "llamar a `register_for_activity` con este confirmation_id. "
            "Vence en 10 minutos y es de un solo uso."
        ),
    }


@mcp.tool()
def register_for_activity(
    activity_id: str,
    student_email: str,
    confirmation_id: str | None = None,
) -> dict[str, str]:
    """Paso 2 de la inscripción: inscribe SÓLO con confirmación humana válida.

    Efecto: crea la inscripción (mutable). Exige el `confirmation_id`
    opaco emitido por `request_registration_confirmation` para estos mismos
    valores; un booleano o un token inventado se rechaza. Es idempotente en
    efecto: el reintento con otro token devuelve `already_registered` sin
    duplicar, y el reuso del mismo token se rechaza sin re-ejecutar.
    """
    try:
        safe_activity_id = validate_activity_id(activity_id)
    except ValidationError as error:
        return {"status": "validation_error", "message": str(error)}
    try:
        safe_email = validate_email(student_email)
    except ValidationError as error:
        return {"status": "invalid_email", "message": str(error)}

    # Puerta de la etapa 04: la confirmación debe venir del host, no del
    # modelo. is_host_confirmation_valid() falla cerrado ante token ausente,
    # inválido, pendiente de aprobación, vencido, reusado o desatado;
    # consume() además lo reclama (un solo uso) de forma atómica.
    try:
        require_human_confirmation(
            is_host_confirmation_valid(
                confirmation_id, safe_activity_id, safe_email
            )
        )
        confirmation_store.consume(
            confirmation_id, safe_activity_id, safe_email
        )
    except ConfirmationRequired:
        # La puerta falló: clasificar la causa (sin mutar) para devolver
        # un mensaje específico y accionable en vez de uno genérico.
        cause = confirmation_store.approval_failure_reason(
            confirmation_id, safe_activity_id, safe_email
        ) or ConfirmationRequired(
            "Se requiere confirmación antes de inscribir. "
            "Llamá primero a `request_registration_confirmation` y "
            "pedí aprobación explícita al humano en el host."
        )
        audit_log.record(
            new_audit_event(
                safe_activity_id,
                safe_email,
                confirmation_id=str(confirmation_id or ""),
                result=(
                    "confirmation_required"
                    if type(cause) is ConfirmationRequired
                    else "confirmation_rejected"
                ),
                detail=str(cause),
            )
        )
        if type(cause) is ConfirmationRequired:
            return {"status": "confirmation_required", "message": str(cause)}
        return {"status": "confirmation_invalid", "message": str(cause)}

    token = str(confirmation_id or "").strip()
    service = get_activity_service()
    try:
        result = service.register(safe_activity_id, safe_email)
    except ActivityNotFound:
        audit_log.record(
            new_audit_event(
                safe_activity_id, safe_email, confirmation_id=token,
                result="activity_not_found",
            )
        )
        return {
            "status": "activity_not_found",
            "message": f"No existe la actividad `{safe_activity_id}`.",
        }
    except InvalidEmail as error:  # redundante con validación, por si cambia el dominio
        audit_log.record(
            new_audit_event(
                safe_activity_id, safe_email, confirmation_id=token,
                result="invalid_email", detail=str(error),
            )
        )
        return {"status": "invalid_email", "message": str(error)}
    except ActivityFull as error:
        audit_log.record(
            new_audit_event(
                safe_activity_id, safe_email, confirmation_id=token,
                result="activity_full", detail=str(error),
            )
        )
        return {"status": "activity_full", "message": str(error)}
    except AlreadyRegistered as error:
        # Idempotencia: el constraint único evitó el duplicado.
        audit_log.record(
            new_audit_event(
                safe_activity_id, safe_email, confirmation_id=token,
                result="already_registered", detail=str(error),
            )
        )
        return {"status": "already_registered", "message": str(error)}

    audit_log.record(
        new_audit_event(
            safe_activity_id, safe_email, confirmation_id=token, result="registered"
        )
    )
    return result


# ---------------------------------------------------------------------------
# Prompt guiado
# ---------------------------------------------------------------------------


@mcp.prompt(
    description="Guía paso a paso: explorar, pedir confirmación humana e inscribir."
)
def guia_inscripcion(
    query: str = "", student_email: str = ""
) -> list[dict[str, object]]:
    """Flujo guiado de inscripción con confirmación humana obligatoria.

    Args:
        query: tema de interés (ej. "robótica"); vacío = todo el catálogo.
        student_email: email si ya se conoce; vacío = pedirlo antes de inscribir.
    No inscribe por sí mismo: orquesta resources y tools en orden.
    """
    query = validate_query(query)
    student_email = str(student_email or "").strip()
    contexto = "Che, quiero inscribirme a una actividad de la UNTDF."
    if query:
        contexto += f' Mi tema de interés es "{query}".'
    else:
        contexto += " Quiero ver todo el catálogo."
    if student_email:
        contexto += f" Mi email es {student_email}."
    instrucciones = "\n".join(
        [
            "Dale, te guío paso a paso. Seguí este orden exacto:",
            "",
            "1. Leé el resource `activities://available` para mostrar el catálogo con cupo.",
            f"2. Usá la tool `search_activities` con `query=\"{query}\"` y `only_available=True` para afinar"
            + (" según el interés." if query else " (sin tema: mostrá todo)."),
            "3. Con la candidata elegida, leé `activities://{activity_id}` para mostrar título, descripción y cupos.",
            "4. Llamá a `request_registration_confirmation` con `activity_id` y `student_email`. "
            "Esta tool NO inscribe: devuelve un `confirmation_id` y un resumen.",
            "5. Mostrá el resumen al HUMANO en el host y pedí aprobación explícita ('¿Confirmás la inscripción a X con email Y?'). "
            "NUNCA inventes el `confirmation_id`: sólo vale el token opaco devuelto en el paso 4.",
            "6. Recién con el 'sí' del humano y la aprobación registrada por el adaptador del host, llamá a `register_for_activity` con `activity_id`, `student_email` y ese `confirmation_id`.",
            "7. Comunicá el resultado: `registered` (celebralo con el ID), `already_registered` (ya estaba, sin duplicar), "
            "`activity_full` / `activity_not_found` / `invalid_email` / `confirmation_*` (explicá causa y ofrecé alternativas del catálogo).",
            "",
            "Importante: vos no inscribís por tu cuenta ni confirmás por el humano; sólo orquestás estos resources/tools. No inventes actividades ni IDs.",
        ]
    )
    return [
        {"role": "user", "content": contexto},
        {"role": "assistant", "content": instrucciones},
    ]


if __name__ == "__main__":
    mcp.run()
