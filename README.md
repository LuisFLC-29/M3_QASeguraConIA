# Auth Secure IA

Módulo de autenticación de usuarios construido con apoyo de herramientas de IA, enfocado en **calidad** (pruebas automatizadas) y **seguridad** (validación, hash seguro, JWT, rate limiting y análisis estático).

## Objetivos del reto cubiertos

- **Pruebas automatizadas unitarias** con `pytest` y `pytest-cov` (80%+ de cobertura).
- **Evaluación de vulnerabilidades de seguridad**:
  - Validación de entrada con Pydantic.
  - Pruebas de SQL injection y XSS.
  - Análisis estático con Bandit.
- **Configuraciones de seguridad avanzadas para IA**:
  - Archivo `.cursorrules` con reglas de seguridad para Cursor/Copilot.
  - Archivo `prompts.md` con prompts usados y recomendaciones.

## Stack

- Python 3.11+
- FastAPI
- passlib[bcrypt] para hash de contraseñas
- python-jose para JWT
- pytest / pytest-cov
- Bandit

## Instalación

```bash
python -m venv .venv
source .venv/bin/activate  # En Windows: .venv\Scripts\activate
pip install .
pip install .[dev]

