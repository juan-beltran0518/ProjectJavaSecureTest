#!/usr/bin/env python3
"""
Azure OpenAI GPT-4o Security Auditor & Remediator
Analyzes security reports (SARIF/JSON) and generates detailed vulnerability report with remediation
"""

import os
import json
import sys
from datetime import datetime
from typing import Dict, List, Any

try:
    from openai import AzureOpenAI
except ImportError:
    print("❌ Error: No se pudo encontrar la librería openai.")
    print("Asegúrate de ejecutar: pip install -U openai")
    sys.exit(1)

# 1. Configuración de Azure OpenAI
AZURE_ENDPOINT = os.environ.get("AZURE_OPENAI_PDF_ENDPOINT")
AZURE_API_KEY = os.environ.get("AZURE_OPENAI_PDF_API_KEY")
AZURE_DEPLOYMENT = os.environ.get("AZURE_OPENAI_PDF_DEPLOYMENT")
AZURE_API_VERSION = os.environ.get("AZURE_OPENAI_PDF_API_VERSION", "2024-02-15-preview")

if not all([AZURE_ENDPOINT, AZURE_API_KEY, AZURE_DEPLOYMENT]):
    print("❌ Error: Una o más credenciales de Azure OpenAI no están configuradas.")
    print(f"  - AZURE_OPENAI_PDF_ENDPOINT: {bool(AZURE_ENDPOINT)}")
    print(f"  - AZURE_OPENAI_PDF_API_KEY: {bool(AZURE_API_KEY)}")
    print(f"  - AZURE_OPENAI_PDF_DEPLOYMENT: {bool(AZURE_DEPLOYMENT)}")
    sys.exit(1)

# Validar que sea Azure endpoint, no OpenAI estándar
if "api.openai.com" in AZURE_ENDPOINT:
    print("❌ ERROR CRÍTICO: AZURE_OPENAI_PDF_ENDPOINT es de OpenAI estándar, no de Azure!")
    print(f"   Recibido: {AZURE_ENDPOINT}")
    print(f"   Esperado: https://tu-recurso.openai.azure.com/")
    print("\n💡 Para Azure OpenAI:")
    print("   1. Ve a Azure Portal → Tu recurso OpenAI")
    print('   2. "Keys and Endpoint" → Copia la URL Endpoint (debe contener .azure.com)')
    print("   3. Actualiza AZURE_OPENAI_PDF_ENDPOINT en GitHub Secrets")
    sys.exit(1)

if ".openai.azure.com" not in AZURE_ENDPOINT:
    print("⚠️ ADVERTENCIA: El endpoint no parece ser de Azure OpenAI")
    print(f"   Recibido: {AZURE_ENDPOINT}")
    print(f"   Esperado: debe contener '.openai.azure.com'")
    print("\n   Continuando de todas formas...\n")

client = AzureOpenAI(
    api_key=AZURE_API_KEY,
    api_version=AZURE_API_VERSION,
    azure_endpoint=AZURE_ENDPOINT
)
MODEL = AZURE_DEPLOYMENT  # Usar el nombre del deployment configurado

# JSON Schema para structured output
VULNERABILITY_SCHEMA = {
    "type": "json_schema",
    "json_schema": {
        "name": "security_audit_report",
        "schema": {
            "type": "object",
            "properties": {
                "timestamp": {"type": "string", "description": "ISO 8601 timestamp"},
                "vulnerabilidades": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string", "description": "Unique ID (e.g., vuln-001)"},
                            "archivo": {"type": "string", "description": "Path to vulnerable file"},
                            "linea": {"type": "integer", "description": "Line number"},
                            "severidad": {
                                "type": "string",
                                "enum": ["CRÍTICO", "ALTO", "MEDIO", "BAJO"],
                                "description": "Severity level"
                            },
                            "herramienta": {
                                "type": "string",
                                "enum": ["Semgrep", "CodeQL", "Snyk", "Trivy", "ZAP", "TruffleHog", "Dependabot"],
                                "description": "Security tool that detected it"
                            },
                            "regla": {"type": "string", "description": "Rule ID"},
                            "titulo": {"type": "string", "description": "Short descriptive title"},
                            "descripcion": {"type": "string", "description": "What the vulnerability is"},
                            "impacto": {"type": "string", "description": "Business/security impact (e.g., RCE, Data Breach)"},
                            "explotabilidad": {"type": "string", "description": "How easy to exploit (e.g., FÁCIL, DIFÍCIL)"},
                            "solucion": {"type": "string", "description": "How to fix it"},
                            "codigo_vulnerable": {"type": "string", "description": "Code snippet showing the issue"},
                            "codigo_corregido": {"type": "string", "description": "Fixed code snippet"}
                        },
                        "required": ["id", "archivo", "linea", "severidad", "herramienta", "titulo", "descripcion", "impacto", "solucion"]
                    }
                },
                "resumen": {
                    "type": "object",
                    "properties": {
                        "total": {"type": "integer", "description": "Total vulnerabilities"},
                        "criticos": {"type": "integer"},
                        "altos": {"type": "integer"},
                        "medios": {"type": "integer"},
                        "bajos": {"type": "integer"}
                    },
                    "required": ["total", "criticos", "altos", "medios", "bajos"]
                },
                "can_auto_fix": {"type": "boolean", "description": "Whether auto-remediation is possible"},
                "veredicto": {
                    "type": "string",
                    "enum": ["RECHAZADO", "ADVERTENCIA", "ACEPTADO"],
                    "description": "Final verdict"
                }
            },
            "required": ["timestamp", "vulnerabilidades", "resumen", "can_auto_fix", "veredicto"]
        }
    }
}


def _is_truthy(value):
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def parse_sarif(file_path: str) -> List[Dict[str, Any]]:
    """Extrae hallazgos detallados de archivos SARIF (CodeQL, Semgrep, Snyk)"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        findings = []
        for run in data.get('runs', []):
            tool_name = run.get('tool', {}).get('driver', {}).get('name', 'Herramienta')

            for result in run.get('results', []):
                level = result.get('level', 'warning')
                if level not in ['error', 'warning', 'note']:
                    continue

                msg = result.get('message', {}).get('text', 'Sin descripción')
                locs = result.get('locations', [{}])
                phys_loc = locs[0].get('physicalLocation', {}) if locs else {}
                uri = phys_loc.get('artifactLocation', {}).get('uri', 'N/A')

                # Extraer número de línea (puede estar en region)
                line_num = 0
                if 'region' in phys_loc:
                    line_num = phys_loc['region'].get('startLine', 0)

                findings.append({
                    "herramienta": tool_name,
                    "regla": result.get('ruleId', 'N/A'),
                    "archivo": uri,
                    "linea": line_num,
                    "nivel": level,
                    "descripcion": msg,
                    "propiedades": result.get('properties', {})
                })

        return findings
    except Exception as e:
        print(f"⚠️ Error parsing SARIF {file_path}: {e}")
        return []


def parse_json_generic(file_path: str) -> List[Dict[str, Any]]:
    """Lectura para JSON/JSON Lines (Trufflehog, Trivy, ZAP)"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                return []

            try:
                return [json.loads(content)]
            except json.JSONDecodeError:
                # Try JSON Lines format
                f.seek(0)
                return [json.loads(line) for line in f if line.strip()]
    except Exception as e:
        print(f"⚠️ Error parsing JSON {file_path}: {e}")
        return []


def parse_findings_directory(results_dir: str) -> Dict[str, Any]:
    """Recorre directorio de resultados y consolida todos los hallazgos"""
    all_context = {
        "herramientas": {},
        "hallazgos_totales": 0
    }

    if not os.path.exists(results_dir):
        print(f"⚠️ Directorio {results_dir} no encontrado.")
        print(f"💡 Creando directorio {results_dir} con reportes vacíos...")
        os.makedirs(results_dir, exist_ok=True)
        return all_context

    for root, _, files in os.walk(results_dir):
        for file in files:
            path = os.path.join(root, file)

            if os.path.getsize(path) == 0:
                continue

            print(f"📂 Procesando: {file}")

            findings = []
            if file.endswith('.sarif'):
                findings = parse_sarif(path)
            elif file.endswith('.json'):
                findings = parse_json_generic(path)

            if findings:
                all_context["herramientas"][file] = {
                    "hallazgos": findings,
                    "cantidad": len(findings)
                }
                all_context["hallazgos_totales"] += len(findings)

    return all_context


def create_markdown_report(json_response: Dict[str, Any], repo_name: str = "N/A") -> str:
    """Convierte JSON response a markdown legible para humanos"""

    md = f"""# 🛡️ Informe de Seguridad - Auditoría IA

**Fecha**: {json_response.get('timestamp', 'N/A')}
**Repositorio**: {repo_name}

---

## 📊 Resumen Ejecutivo

| Métrica | Cantidad |
|---------|----------|
| **Total de Vulnerabilidades** | {json_response['resumen']['total']} |
| **🔴 Críticas** | {json_response['resumen']['criticos']} |
| **🟠 Altas** | {json_response['resumen']['altos']} |
| **🟡 Medias** | {json_response['resumen']['medios']} |
| **🟢 Bajas** | {json_response['resumen']['bajos']} |

**Veredicto Final**: `{json_response['veredicto']}`
"""

    if json_response['veredicto'] == 'RECHAZADO':
        md += "\n⚠️ **ESTA PR SERÁ BLOQUEADA** - Existen vulnerabilidades críticas o altas que deben resolverse.\n"
    elif json_response['veredicto'] == 'ADVERTENCIA':
        md += "\n⚠️ **ADVERTENCIA** - Hay vulnerabilidades que deben revisarse antes de mergear.\n"
    else:
        md += "\n✅ **ACEPTADO** - Riesgos bajo control.\n"

    # Vulnerabilidades por severidad
    md += "\n---\n\n## 🔴 Vulnerabilidades Críticas y Altas\n\n"

    critical_high = [v for v in json_response['vulnerabilidades']
                     if v['severidad'] in ['CRÍTICO', 'ALTO']]

    if not critical_high:
        md += "*No hay vulnerabilidades críticas o altas.*\n"
    else:
        for vuln in critical_high:
            md += f"""
### {vuln['titulo']} ({vuln['severidad']})

**Ubicación**: `{vuln['archivo']}:{vuln['linea']}`
**Herramienta**: {vuln['herramienta']} | **Regla**: `{vuln['regla']}`

**Descripción**: {vuln['descripcion']}

**Impacto**: 🎯 {vuln['impacto']}
**Explotabilidad**: ⚡ {vuln['explotabilidad']}

**Solución**:
```
{vuln['solucion']}
```

**Código Vulnerable**:
```java
{vuln.get('codigo_vulnerable', 'N/A')}
```

**Código Corregido**:
```java
{vuln.get('codigo_corregido', 'N/A')}
```

---
"""

    # Vulnerabilidades medias y bajas
    md += "\n## 🟡 Vulnerabilidades Medias y Bajas\n\n"

    medium_low = [v for v in json_response['vulnerabilidades']
                  if v['severidad'] in ['MEDIO', 'BAJO']]

    if not medium_low:
        md += "*No hay vulnerabilidades medias o bajas.*\n"
    else:
        md += "| Archivo | Línea | Severidad | Título | Impacto |\n"
        md += "|---------|-------|-----------|--------|----------|\n"
        for vuln in medium_low:
            md += f"| `{vuln['archivo']}` | {vuln['linea']} | {vuln['severidad']} | {vuln['titulo']} | {vuln['impacto']} |\n"

    md += f"""

---

## 📝 Recomendaciones

- ✅ Resolver todas las vulnerabilidades **CRÍTICAS** inmediatamente
- ⚠️ Planificar remediación de vulnerabilidades **ALTAS** en el próximo sprint
- 💡 Revisar y considerar las vulnerabilidades **MEDIAS**

---

*Generado automáticamente por Azure OpenAI Security Auditor*
"""

    return md


def main():
    results_dir = sys.argv[1] if len(sys.argv) > 1 else 'security-results'
    repo_name = os.environ.get('GITHUB_REPOSITORY', 'N/A')
    fail_on_api_error = _is_truthy(os.environ.get("IA_FAIL_ON_API_ERROR", "false"))

    print(f"--- 🛡️ Iniciando Auditoría Azure OpenAI en {results_dir} ---")
    print(f"📦 Repositorio: {repo_name}")
    print(f"🔧 AZURE_OPENAI_PDF_ENDPOINT configurado: {bool(os.environ.get('AZURE_OPENAI_PDF_ENDPOINT'))}")
    print(f"🔧 AZURE_OPENAI_PDF_API_KEY configurado: {bool(os.environ.get('AZURE_OPENAI_PDF_API_KEY'))}")
    print(f"🔧 AZURE_OPENAI_PDF_DEPLOYMENT: {os.environ.get('AZURE_OPENAI_PDF_DEPLOYMENT', 'N/A')}")
    print(f"⚙️ IA_FAIL_ON_API_ERROR: {fail_on_api_error}")

    # Parse all findings
    print(f"\n📂 Analizando directorio: {results_dir}")
    parsed_data = parse_findings_directory(results_dir)
    print(f"✅ Total de hallazgos encontrados: {parsed_data['hallazgos_totales']}")

    if parsed_data["hallazgos_totales"] == 0:
        print("\n✅ No se detectaron hallazgos en los reportes.")
        print("📝 Generando reporte vacío...")

        # Create empty report
        empty_report = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "vulnerabilidades": [],
            "resumen": {"total": 0, "criticos": 0, "altos": 0, "medios": 0, "bajos": 0},
            "can_auto_fix": False,
            "veredicto": "ACEPTADO"
        }

        with open("VULNERABILITIES.json", "w", encoding="utf-8") as f:
            json.dump(empty_report, f, indent=2)
            print(f"✅ Creado: VULNERABILITIES.json")

        with open("REPORTE_IA_SEGURIDAD.md", "w", encoding="utf-8") as f:
            f.write(create_markdown_report(empty_report, repo_name))
            print(f"✅ Creado: REPORTE_IA_SEGURIDAD.md")

        sys.exit(0)

    # Prepare context for GPT-4o
    context = json.dumps(parsed_data, indent=2)

    prompt = f"""
ERES UN AUDITOR SENIOR DE SEGURIDAD DEVOPS ESPECIALIZADO EN JAVA.

TU TAREA: Analizar reportes de seguridad y devolver ÚNICAMENTE un JSON estructurado.

DATOS DE SEGURIDAD:
{context}

FORMATO DE RESPUESTA - DEBES DEVOLVER EXACTAMENTE ESTO:
{{
  "timestamp": "ISO_8601_DATE",
  "vulnerabilidades": [
    {{
      "id": "vuln-001",
      "archivo": "ruta/archivo.java",
      "linea": 42,
      "severidad": "CRÍTICO|ALTO|MEDIO|BAJO",
      "herramienta": "Semgrep|CodeQL|Snyk|Trivy|ZAP|TruffleHog|Dependabot",
      "regla": "rule-id",
      "titulo": "Título breve",
      "descripcion": "Qué es la vulnerabilidad",
      "impacto": "RCE|SQL Injection|Data Breach|etc",
      "explotabilidad": "FÁCIL|MODERADA|DIFÍCIL",
      "solucion": "Cómo arreglarlo",
      "codigo_vulnerable": "Snippet vulnerable",
      "codigo_corregido": "Snippet fixed"
    }}
  ],
  "resumen": {{
    "total": 5,
    "criticos": 1,
    "altos": 2,
    "medios": 1,
    "bajos": 1
  }},
  "can_auto_fix": false,
  "veredicto": "RECHAZADO|ADVERTENCIA|ACEPTADO"
}}

REGLAS CRÍTICAS:
1. NUNCA uses otras claves (evaluacion, findings, etc) - SOLO vulnerabilidades, resumen, veredicto, can_auto_fix
2. Mapea TODAS las severidades a: CRÍTICO, ALTO, MEDIO, BAJO
3. Si hay CRÍTICO o ALTO → veredicto = "RECHAZADO"
4. Si hay MEDIO → veredicto = "ADVERTENCIA"
5. Si solo BAJO o nada → veredicto = "ACEPTADO"
6. Responde ÚNICAMENTE el JSON, sin markdown, sin explicaciones

COMIENZA:
"""

    try:
        print(f"🤖 Solicitando análisis a {MODEL}...")

        response = client.chat.completions.create(
            model=MODEL,
            max_tokens=4096,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        # Extract text from response
        response_text = response.choices[0].message.content

        # Try to parse JSON
        try:
            json_response = json.loads(response_text)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code blocks
            import re
            json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response_text, re.DOTALL)
            if json_match:
                json_response = json.loads(json_match.group(1))
            else:
                print(f"⚠️ No se pudo parsear JSON de la respuesta: {response_text[:200]}")
                raise ValueError("Invalid JSON response from Azure OpenAI")

        # Validar estructura JSON
        required_keys = ['vulnerabilidades', 'resumen', 'veredicto']
        missing_keys = [k for k in required_keys if k not in json_response]

        if missing_keys:
            print(f"⚠️ ADVERTENCIA: Faltan claves en respuesta: {missing_keys}")
            print(f"   Respuesta recibida: {json.dumps(json_response, indent=2)[:500]}")

            # Intentar transformar estructura de Azure
            if 'evaluacion' in json_response and 'vulnerabilidades' not in json_response:
                print("🔄 Transformando respuesta de Azure OpenAI...")
                evaluacion = json_response.get('evaluacion', [])

                # Contar por severidad
                severity_counts = {
                    'CRÍTICO': 0, 'ALTO': 0, 'MEDIO': 0, 'BAJO': 0
                }
                for item in evaluacion:
                    sev = item.get('severidad', 'BAJO')
                    if sev in severity_counts:
                        severity_counts[sev] += 1

                json_response['vulnerabilidades'] = evaluacion
                json_response['resumen'] = {
                    'total': len(evaluacion),
                    'criticos': severity_counts['CRÍTICO'],
                    'altos': severity_counts['ALTO'],
                    'medios': severity_counts['MEDIO'],
                    'bajos': severity_counts['BAJO']
                }
                json_response['can_auto_fix'] = False

            # Crear estructura mínima si aún faltan cosas
            if 'resumen' not in json_response:
                json_response['resumen'] = {
                    'total': 0, 'criticos': 0, 'altos': 0, 'medios': 0, 'bajos': 0
                }
            if 'vulnerabilidades' not in json_response:
                json_response['vulnerabilidades'] = []
            if 'veredicto' not in json_response:
                json_response['veredicto'] = 'ACEPTADO'
            if 'can_auto_fix' not in json_response:
                json_response['can_auto_fix'] = False

        # Add timestamp if missing
        if 'timestamp' not in json_response:
            json_response['timestamp'] = datetime.utcnow().isoformat() + "Z"

        # Save JSON report
        with open("VULNERABILITIES.json", "w", encoding="utf-8") as f:
            json.dump(json_response, f, indent=2)

        # Generate markdown report
        md_report = create_markdown_report(json_response, repo_name)
        with open("REPORTE_IA_SEGURIDAD.md", "w", encoding="utf-8") as f:
            f.write(md_report)

        print("✅ Reportes generados exitosamente.")
        print(f"   - VULNERABILITIES.json (máquina-readable)")
        print(f"   - REPORTE_IA_SEGURIDAD.md (humano-readable)")

        # Exit based on verdict
        if json_response['veredicto'] == 'RECHAZADO':
            print("❌ Veredicto de IA: Vulnerabilidades críticas/altas detectadas.")
            sys.exit(1)

        print(f"🟢 Veredicto de IA: {json_response['veredicto']}")
        sys.exit(0)

    except Exception as e:
        print(f"\n❌ Error con {MODEL}: {e}")
        import traceback
        traceback.print_exc()

        if fail_on_api_error:
            print("❌ IA_FAIL_ON_API_ERROR=true: bloqueando pipeline por error de IA.")
            sys.exit(1)

        print("⚠️ IA_FAIL_ON_API_ERROR=false: no se bloquea el pipeline por error de IA.")
        print("📝 Generando reporte vacío por razones de continuidad...")

        # Crear reporte vacío para no bloquear el pipeline
        empty_report = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "vulnerabilidades": [],
            "resumen": {"total": 0, "criticos": 0, "altos": 0, "medios": 0, "bajos": 0},
            "can_auto_fix": False,
            "veredicto": "ACEPTADO"
        }

        with open("VULNERABILITIES.json", "w", encoding="utf-8") as f:
            json.dump(empty_report, f, indent=2)

        with open("REPORTE_IA_SEGURIDAD.md", "w", encoding="utf-8") as f:
            f.write(f"# ⚠️ Error en Auditoría IA\n\n**Error**: {str(e)}\n")

        sys.exit(0)


if __name__ == "__main__":
    main()