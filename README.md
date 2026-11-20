# Aegis Protocol v2

Contrato único, SDK y CLI auxiliar para enrolamiento obligatorio, licenciamiento offline firmado con **Ed25519**, huella compuesta de máquina, modo de funcionalidad reducida (**RFM**) / modo suave (**advisory**) y telemetría tipada para toda la suite Aegis.

Documentación de diseño y especificación completa en [`../docs/CONTRATO-AEGIS-PROTOCOL-V2.md`](../docs/CONTRATO-AEGIS-PROTOCOL-V2.md) y [`../docs/PLAN-PROTOCOLO-Y-LICENCIAS.md`](../docs/PLAN-PROTOCOLO-Y-LICENCIAS.md).

## Estructura

- **Raíz Go (`github.com/aegis-suite-apps/aegis-protocol`):** paquete Go reutilizable para `aegis-backup`, `aegis-setup`, `aegis-shell`, más los binarios `cmd/aegis-agent` (CLI para automatización y `aegis-gate`) y `cmd/aegis-enroll` (ventana nativa Win32 de enrolamiento para instaladores y apps de la suite).
- **`ts/` (`@aegis-suite-apps/protocol`):** esquemas Zod v2, firma/verificación Ed25519 (`jose`), evaluador `Guard`, huella de equipo, DPAPI nativo en Windows (`bun:ffi`) y cliente HTTP para `aegis-rd` y `aegis-vault`.
- **`vectors/`:** vectores criptográficos generados en TypeScript y verificados tanto en TypeScript como en Go.

## Pruebas

```powershell
# TypeScript / Bun
cd ts
bun install
bun test
bun run typecheck

# Go + verificación de vectores cruzados
cd ..
go test ./...
```
