# 04 — Seguridad y cierre

## Propósito

Revisar la integración como una interfaz que habilita acciones a través de un host agéntico. Una tool disponible no equivale a un permiso automático.

## Actividad

Esta carpeta contiene una base segura por defecto: el servidor valida entradas
y rechaza cualquier inscripción porque `is_host_confirmation_valid` siempre
devuelve `False`. Preparala y abrila con Inspector:

```sh
uv sync
uv run mcp dev server.py
```

Aplicá estas mejoras al servidor de la etapa 03:

1. Validá los argumentos de cada capacidad, especialmente `activity_id` y `student_email`.
2. Convertí errores de dominio en resultados accionables. Como mínimo, cubrí actividad inexistente, cupo agotado y correo inválido.
3. Para la inscripción, completá `is_host_confirmation_valid`: debe verificar
   una confirmación emitida por el host o su interfaz, no aceptar un booleano
   que el modelo pueda inventar. Definí además cómo se evita una doble
   inscripción y qué dato se audita.
4. Revisá cada resource: debe devolver sólo la información necesaria y no filtrar datos sensibles.
5. Conectá el servidor local por `stdio` desde el host y realizá una prueba de extremo a extremo.

### Integración de aprobación del host

`request_registration_confirmation` sólo emite una solicitud pendiente. El
adaptador confiable del host debe mostrar su `summary`, obtener el "sí" de la
persona y recién entonces llamar, desde código del host y no como tool MCP, a
`approve_registration_confirmation_from_host(confirmation_id, approved_by)`.
El identificador `approved_by` debe ser la cuenta o sesión autenticada que
aceptó. Sin esa marca, `register_for_activity` devuelve
`confirmation_invalid` y no modifica el dominio. La auditoría guarda el
evento `confirmation_approved`, el momento y `approved_by`.

Ejemplo conceptual de configuración local en OpenCode:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "activities": {
      "type": "local",
      "command": ["uv", "run", "python", "mcp_server/server.py"],
      "enabled": true
    }
  }
}
```

## Lista de verificación

- [ ] Los nombres y descripciones de las tools dicen con precisión qué hacen y qué efecto tienen.
- [ ] Todas las entradas se validan antes de llegar al dominio.
- [ ] Los errores indican causa, campo o alternativa; no filtran trazas internas.
- [ ] Las acciones mutables requieren confirmación y son idempotentes o manejan repeticiones de forma explícita.
- [ ] Existe un registro auditable de quién solicitó una inscripción y cuándo.
- [ ] El servidor expone la mínima autoridad necesaria; no existe una tool genérica como `execute_sql(query)`.

## Cierre: explicación oral

Prepará una demo con el flujo completo: pedido de la persona → selección de tool por el modelo → permiso del host → `tools/call` → service layer de Django → resultado → respuesta final.

También deberías poder explicar por qué REST y MCP pueden convivir: REST atiende contratos orientados a clientes de software; MCP expone capacidades descubribles para un host agéntico. MCP no reemplaza automáticamente la API REST.

## Extensión opcional: HTTP remoto

Cuando el servidor deje de ser local, el transporte puede ser Streamable HTTP. Antes de publicarlo, definí autenticación, límites de tasa, logs y trazas. Este despliegue no forma parte del mínimo del laboratorio.
