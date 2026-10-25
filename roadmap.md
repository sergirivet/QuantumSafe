QUANTUMSAFE — ROADMAP DE DESARROLLO
Cómo utilizar este roadmap
Estos prompts deben ejecutarse en orden.
No avances al siguiente prompt hasta completar el Definition of Done del actual.
Cada prompt tiene dos objetivos simultáneos:
1. Construir una parte real de QuantumSafe.
2. Aprender las competencias técnicas necesarias para Security Engineering, Applied Cryptography, Cloud Security, Go, Kubernetes, KMS y Cloud-Native Security.
Regla general para Claude
En todos los prompts:
* No escribas grandes cantidades de código sin que yo lo haya intentado.
* Enséñame mediante implementación.
* Prioriza Go para el producto.
* Utiliza librerías criptográficas existentes y auditadas.
* No implementes primitivas criptográficas desde cero.
* Evita sobreingeniería.
* No introduzcas tecnologías antes de que exista una razón real para utilizarlas.
* Si una decisión arquitectónica es mala, dímelo.
* Si estoy intentando construir demasiado, recórtalo.
* Distingue siempre entre una implementación educativa y una implementación production-grade.
* Cuando una afirmación dependa de documentación o estándares actuales, utiliza fuentes oficiales.
* No inventes APIs, capacidades cloud, resultados de benchmarks ni propiedades criptográficas.

PROMPT 00 — ARCHITECTURE & PROJECT FOUNDATION
Quiero empezar el desarrollo de mi proyecto personal QuantumSafe.

QuantumSafe será una plataforma de Cryptographic Discovery & Post-Quantum Readiness.

Su objetivo final será:

Discovery
→ Cryptographic Inventory
→ Dependencies
→ Risk
→ Crypto Agility
→ PQC Readiness
→ Migration Planning
→ Migration Validation

Posteriormente tendrá un componente secundario de Crypto Services:

Key Management
Key Lifecycle
Key Rotation
Envelope Encryption
Signing / Verification
Audit

Quiero que actúes como Senior Software Architect + Go Engineer + Security Engineer.

Antes de escribir código, quiero que diseñemos correctamente la primera versión del proyecto.

## Objetivo

Diseñar un Modular Monolith inicial, desarrollado principalmente en Go.

No quiero microservices.

No quiero Kubernetes todavía.

No quiero AWS todavía.

No quiero un KMS completo todavía.

## Lo que quiero aprender

- estructura de proyectos Go
- packages
- modules
- separation of concerns
- dependency management
- interfaces
- domain boundaries
- configuration
- logging
- testing
- idiomatic Go

## Tareas

1. Evalúa críticamente esta arquitectura conceptual:

cmd/
internal/
migrations/
automation/
deployments/
docs/
tests/

2. Propón una estructura inicial mínima.

3. Explica qué paquetes debemos crear ahora y cuáles debemos esperar.

4. Define los bounded contexts iniciales.

5. Explica qué debe estar dentro de internal/ y por qué.

6. Define una estrategia inicial de configuración.

7. Define cómo gestionaremos errores.

8. Define cómo escribiremos tests.

9. Define las primeras decisiones arquitectónicas que deberíamos documentar mediante ADRs.

10. No introduzcas abstracciones que todavía no tengan una necesidad real.

## Restricción importante

Quiero una arquitectura que pueda crecer posteriormente hacia:

- PostgreSQL
- REST API
- workers
- AWS
- STACKIT
- Docker
- Kubernetes
- Helm
- Kubernetes Operator

pero no quiero construir ahora esas capas.

## Entregables

Quiero terminar esta fase con:

- repositorio Go inicial
- go.mod
- estructura de directorios
- CLI mínima
- configuración mínima
- logging mínimo
- primer test
- README inicial
- primer ADR

## Definition of Done

La aplicación debe compilar y ejecutar correctamente.

Antes de darme código, explícame las decisiones arquitectónicas y hazme tomar las decisiones que correspondan.

PROMPT 01 — GO FUNDAMENTALS THROUGH QUANTUMSAFE CLI
Continuemos QuantumSafe desde la fase anterior.

Ahora quiero utilizar el proyecto para aprender Go de forma práctica.

Actúa como Senior Go Engineer y mentor.

## Objetivo

Construir una CLI inicial:

quantumsafe

con comandos conceptuales como:

quantumsafe scan
quantumsafe version
quantumsafe help

Todavía NO quiero construir el scanner real.

## Quiero aprender mediante implementación

Introduce únicamente los conceptos de Go que necesitamos:

- structs
- methods
- functions
- packages
- interfaces cuando exista una necesidad real
- pointers cuando tenga sentido
- errors
- error wrapping
- context
- JSON
- testing

No me enseñes todo Go de golpe.

## Ejercicio

Antes de implementar QuantumSafe, dame pequeños ejercicios para entender:

1. structs
2. methods
3. errors
4. interfaces

Después intégralos en el proyecto.

## Importante

No quiero una abstracción genérica del tipo:

ScannerFactoryProviderManager

si todavía no tenemos scanners.

Quiero idiomatic Go.

## Deliverable

Una CLI funcional capaz de:

quantumsafe version

y:

quantumsafe scan example.com

aunque inicialmente el scan solo pueda mostrar que todavía no está implementado.

## Definition of Done

- Go tests
- idiomatic package structure
- proper error handling
- context preparado para operaciones futuras
- README actualizado

Termina la respuesta con el primer ejercicio que debo implementar yo.

PROMPT 02 — DISCOVERY ENGINE
Ahora quiero construir el primer componente real de QuantumSafe: Discovery.

Actúa como Senior Go Networking Engineer + Security Engineer.

## Objetivo

Implementar:

quantumsafe scan example.com

con un pipeline inicial:

DNS
→ IPs
→ TCP services
→ HTTP/HTTPS
→ TLS

No necesitamos todavía:

- AWS
- STACKIT
- Kubernetes
- GitHub
- cloud discovery

## Quiero aprender

- net package
- DNS
- TCP connections
- timeouts
- context cancellation
- concurrency
- goroutines
- worker pools
- channels
- TLS en Go
- HTTP clients
- error handling

## Importante

No hagas un scanner ofensivo.

El scanner debe estar diseñado para sistemas autorizados.

Debe incluir límites razonables:

- timeouts
- concurrency limits
- input validation
- context cancellation

Presta especial atención a SSRF y a cómo una futura plataforma SaaS debería controlar los targets permitidos.

## Arquitectura

Quiero evaluar si tiene sentido introducir:

type Scanner interface {
    Scan(ctx context.Context, target Target) ([]Finding, error)
}

No lo implementes simplemente porque lo he sugerido.

Evalúa si realmente lo necesitamos ahora.

## Entregable

El scanner debe poder descubrir:

- DNS records relevantes
- IPs
- TCP services
- HTTP status
- TLS certificate
- TLS version
- cipher suite

## Tests

Incluye tests para:

- timeout
- invalid target
- TLS parsing
- scanner errors
- context cancellation

## Definition of Done

Debe poder ejecutarse:

quantumsafe scan example.com

y producir un resultado estructurado.

No introduzcas PostgreSQL todavía.

PROMPT 03 — CRYPTO INVENTORY + POSTGRESQL
Ahora quiero convertir los resultados del scanner en un Cryptographic Inventory persistente.

Actúa como:

- Go Backend Engineer
- PostgreSQL Engineer
- Security Engineer

## Objetivo

Diseñar un modelo relacional para:

Asset
Service
Certificate
Algorithm
CryptoUsage
Scan

Relaciones:

Asset
→ Service
→ CryptoUsage
→ Algorithm

Service
→ Certificate

## Quiero aprender

- PostgreSQL schema design
- foreign keys
- constraints
- indexes
- migrations
- transactions
- connection pooling
- SQL desde Go
- repository patterns

## Restricción

No quiero almacenar todo como JSON.

Utiliza un modelo relacional donde corresponda.

Puedes usar JSONB únicamente cuando esté justificado.

## Tareas

1. Diseña el modelo.
2. Explícame las relaciones.
3. Identifica índices.
4. Diseña migrations.
5. Implementa persistence desde Go.
6. Integra Discovery con Inventory.

## No quiero todavía

- Risk Engine
- PQC scoring
- React
- cloud

## Definition of Done

Después de ejecutar:

quantumsafe scan example.com

deberíamos poder almacenar y recuperar:

- asset
- service
- certificate
- TLS version
- cipher suite
- cryptographic algorithms

desde PostgreSQL.

Incluye integration tests.

PROMPT 04 — REST API
Ahora quiero convertir QuantumSafe en una aplicación backend realmente utilizable.

Actúa como Senior Go Backend Engineer + Security Engineer.

## Objetivo

Construir una REST API sobre el sistema existente.

Inicialmente:

POST /api/v1/scans
GET /api/v1/scans/{id}

GET /api/v1/assets
GET /api/v1/assets/{id}

GET /api/v1/services
GET /api/v1/certificates
GET /api/v1/algorithms

## Quiero aprender

- HTTP servers en Go
- routing
- JSON
- request validation
- response design
- status codes
- error handling
- middleware
- context
- timeouts
- authentication conceptually
- authorization conceptually
- pagination

## Importante

No quiero implementar authentication compleja todavía.

Pero quiero que la arquitectura permita introducirla posteriormente.

## Seguridad

Analiza:

- input validation
- SSRF
- request size limits
- timeouts
- error information leakage
- logging
- auditability

## Deliverable

Una API funcional documentada.

Incluye:

- API examples
- integration tests
- error format consistente
- README/API documentation

No construyas frontend todavía.

PROMPT 05 — RISK ENGINE
Ahora quiero construir el Risk Engine de QuantumSafe.

Actúa como Security Architect.

## Objetivo

Crear un sistema de risk assessment explicable.

No quiero inventar una fórmula y presentarla como estándar.

Quiero separar:

- fuentes/estándares utilizados
- factores que nosotros elegimos
- fórmula propia de QuantumSafe

## Factores iniciales

Considera:

- algorithm risk
- internet exposure
- business criticality
- data sensitivity
- dependency impact
- migration complexity
- crypto agility

## Resultado

Debe poder producir algo como:

Risk: HIGH

Reasons:
- quantum-vulnerable public-key algorithm
- internet exposed
- high business criticality
- low crypto agility

## Quiero aprender

- security risk modelling
- scoring
- explainability
- domain modelling
- testable business rules

## Importante

No quiero machine learning.

No quiero un sistema complejo.

Empieza con reglas deterministas y explicables.

## Deliverable

Implementar:

risk assessment

para cada crypto usage/service.

Incluye tests exhaustivos para las reglas.

Documenta por qué cada factor existe y de dónde procede conceptualmente.

PROMPT 06 — PQC READINESS
Ahora quiero implementar el componente de Post-Quantum Readiness.

Actúa como Applied Cryptography Engineer + Security Architect.

## Objetivo

QuantumSafe debe identificar:

- classical algorithms
- quantum-vulnerable public-key algorithms
- PQC algorithms
- potentially affected services
- migration dependencies

Debe poder responder:

"What should this organization migrate first?"

## Quiero aprender

- threat model de Shor
- symmetric vs asymmetric impact
- RSA/ECC
- ML-KEM
- ML-DSA
- hybrid cryptography
- NIST PQC standards
- migration planning

## Importante

Utiliza documentación oficial y actualizada de NIST.

No inventes propiedades de ML-KEM o ML-DSA.

No conviertas QuantumSafe en una librería criptográfica.

## Deliverable

Añadir:

GET /api/v1/pqc/readiness

y modelos de:

PQC Risk
Migration Priority
Affected Algorithms

## Output

Algo como:

Service:
payments-api

Current:
ECDSA P-256

PQC Risk:
HIGH

Recommendation:
Prepare migration path.

No quiero afirmar que simplemente cambiar ECDSA por ML-DSA sea suficiente.

La recomendación debe considerar contexto y dependencias.

PROMPT 07 — CRYPTO AGILITY
Ahora quiero construir Crypto Agility como una capacidad explícita de QuantumSafe.

Actúa como Security Architect + Applied Cryptography Engineer.

## Pregunta fundamental

QuantumSafe debe responder:

"How difficult would it be to replace this cryptographic mechanism?"

## Evaluar

- hardcoded algorithms
- configurable algorithms
- provider abstraction
- cryptographic library dependencies
- key versioning
- policy configuration
- service dependencies
- migration tests
- algorithm coupling

## Quiero aprender

- crypto agility
- loose coupling
- dependency inversion
- configuration vs hardcoding
- migration architecture

## Primera versión

NO quiero static code analysis complejo.

Empieza con metadata declarativa y reglas sencillas.

Ejemplo:

algorithm configurable: yes
provider abstraction: yes
key versioning: yes
hardcoded: no

→ Crypto Agility: HIGH

## Deliverable

Implementar:

GET /api/v1/crypto-agility

y un scoring explicable.

Documenta que el score es un modelo propio de QuantumSafe y no un estándar universal.

## Importante

No construyas todavía un scanner completo de source code.

PROMPT 08 — MIGRATION PLANNER
Ahora quiero unir:

Risk
+
PQC Readiness
+
Crypto Agility

para crear Migration Planning.

Actúa como Security Architect.

## Objetivo

Generar recomendaciones accionables.

Ejemplo:

Current:
ECDSA P-256

Risk:
HIGH

Crypto Agility:
LOW

Migration Complexity:
MEDIUM

Plan:

1. introduce algorithm abstraction
2. version cryptographic keys
3. identify dependencies
4. test hybrid mechanism
5. validate compatibility

## Quiero aprender

- migration planning
- dependency analysis
- architecture trade-offs
- technical debt
- prioritization

## Restricción

QuantumSafe NO debe modificar sistemas reales automáticamente.

Debe producir:

assessment
+
recommendation
+
migration plan

## Deliverable

Modelo:

MigrationPlan
MigrationStep
MigrationDependency
MigrationValidation

API:

GET /api/v1/migration/plans

Incluye ejemplos reproducibles.

PROMPT 09 — CRYPTO SERVICES ARCHITECTURE
Ahora quiero introducir Crypto Services en QuantumSafe.

IMPORTANTE:

QuantumSafe sigue siendo principalmente una plataforma de Cryptographic Discovery & PQC Readiness.

Crypto Services es un componente técnico secundario para:

- key management
- applied cryptography
- cloud-native security

No quiero convertir el producto en un KMS comercial.

Actúa como:

Applied Cryptography Engineer
+
Security Architect.

## Diseña un pequeño bounded context:

Crypto Services
├── Keys
├── Key Versions
├── Lifecycle
├── Rotation
├── Envelope Encryption
├── Signing
├── Verification
└── Audit

## Antes de programar

Explícame:

- KMS vs Secrets Manager
- key vs key version
- key metadata
- key material
- key lifecycle
- authorization boundary

## No implementar todavía

- HSM
- distributed KMS
- multi-region
- enterprise PKI
- production-grade root of trust

El componente debe estar claramente etiquetado como experimental/educational.

Después de la arquitectura, implementaremos solamente el modelo de Key + KeyVersion.

PROMPT 10 — KEY LIFECYCLE
Ahora quiero implementar Key Lifecycle Management.

Actúa como Applied Cryptography Engineer.

## Modelo

Key
→ KeyVersion

Estados:

CREATED
ENABLED
DISABLED
SCHEDULED_FOR_DESTRUCTION
DESTROYED

## Quiero aprender

- key lifecycle
- versioning
- state machines
- authorization
- metadata
- auditability
- secure handling

## Implementar

POST /keys

GET /keys

GET /keys/{id}

POST /keys/{id}/versions

GET /keys/{id}/versions

POST /keys/{id}/disable

POST /keys/{id}/enable

No implementes todavía encryption.

## Requisitos

Una key lógica puede tener múltiples versiones.

Debe existir una única versión activa cuando corresponda.

Las transiciones inválidas deben rechazarse.

## Tests

Cubre:

- valid transitions
- invalid transitions
- concurrent operations
- authorization
- audit events

No almacenes material criptográfico en logs.

PROMPT 11 — KEY ROTATION
Ahora quiero implementar Key Rotation.

Actúa como Applied Cryptography Engineer + Backend Engineer.

## Objetivo

Implementar:

POST /keys/{id}/rotate

Debe:

1. crear nueva key version
2. activar la nueva versión
3. mantener versiones antiguas según política
4. registrar audit event

## Quiero aprender

- rotation
- versioning
- backward compatibility
- key retirement
- audit trails
- transactional consistency

## Importante

Explícame primero:

¿Qué significa realmente rotar una clave?

Diferencia entre:

- generar nueva key version
- re-encrypt data
- re-wrap DEKs
- retire old key

No quiero confundir estos conceptos.

## Deliverable

Rotation funcional y testeada.

Incluye failure scenarios:

- DB failure
- duplicate rotation
- concurrent rotation
- partial operation

PROMPT 12 — ENVELOPE ENCRYPTION
Ahora quiero implementar Envelope Encryption.

Esta es una fase prioritaria porque quiero desarrollar competencias directamente relacionadas con Applied Cryptography/KMS.

Actúa como Applied Cryptography Engineer.

## Modelo

KEK
↓
wrap DEK

DEK
↓
AES-256-GCM
↓
ciphertext

## Quiero entender primero

- por qué DEK
- por qué KEK
- cuándo generar cada uno
- dónde vive cada uno
- qué se almacena
- qué se recupera
- cómo funciona decrypt
- cómo funciona rotation
- qué pasa cuando rota una KEK
- cómo re-wrappear DEKs
- performance implications

## Implementación

Implementa un modelo conceptual como:

EncryptedObject:

ciphertext
nonce
wrapped_dek
kek_id
kek_version
algorithm

## Requisitos

- AES-GCM
- authenticated encryption
- nonce uniqueness
- secure random generation
- no key material in logs
- no key material in API responses
- proper error handling

## MUY IMPORTANTE

No implementes AES.

Utiliza librerías estándar/profesionales.

Explícame exactamente qué material criptográfico se encuentra en memoria durante:

Encrypt
Decrypt
Rotate

## Después

Añade benchmarks.

PROMPT 13 — SIGNING & VERIFICATION
Ahora quiero añadir signing y verification.

Actúa como Applied Cryptography Engineer.

## Objetivo

Añadir Crypto Services para:

POST /crypto/sign
POST /crypto/verify

Inicialmente:

ECDSA

Posteriormente podremos estudiar:

RSA
ML-DSA

## Quiero aprender

- signatures vs encryption
- signing
- verification
- key separation
- algorithm identifiers
- signature encoding
- failure handling

## Importante

No reutilices una misma key para usos incompatibles.

Define key purposes.

Ejemplo:

ENCRYPTION
SIGNING

## Seguridad

No devuelvas material privado.

No registres private keys.

Documenta:

- what is signed
- canonicalization
- encoding
- verification failure

## Deliverable

Signing + verification funcionales y testeados.

PROMPT 14 — AUDIT TRAIL
Ahora quiero implementar Auditability.

Actúa como Security Engineer + SRE.

## Objetivo

Registrar operaciones sensibles:

- key created
- key rotated
- key disabled
- encrypt
- decrypt
- sign
- verify
- authorization failure

## Audit event

Debe contener conceptualmente:

timestamp
actor
action
resource
key_id
key_version
result
request_id
metadata

## IMPORTANTE

Nunca almacenar:

- plaintext
- private key
- secret key
- DEK
- credentials
- sensitive payloads

## Quiero aprender

- audit design
- security logging
- tamper considerations
- correlation IDs
- structured logs
- compliance concepts

Distingue:

application logs
vs
security audit logs.

## Deliverable

Audit trail persistente en PostgreSQL.

PROMPT 15 — AWS INTEGRATION
Ahora quiero introducir AWS.

Actúa como Cloud Security Engineer + Go Engineer.

## Objetivo

Añadir discovery de recursos AWS.

Inicialmente:

- IAM
- EC2
- S3
- KMS
- CloudTrail

Pero empieza por una sola integración.

## Quiero aprender

- AWS APIs
- IAM
- least privilege
- roles
- credentials
- KMS
- CloudTrail
- cloud resource inventory

## Arquitectura

NO quiero crear una abstracción CloudProvider enorme desde el principio.

Primero implementa una integración real.

Después evalúa qué interfaces emergen naturalmente.

## Seguridad

Nunca:

- hardcode credentials
- almacenar AWS keys en Git
- usar excessive permissions

Diseña IAM con least privilege.

## Python

Utiliza Python solamente para automatizaciones donde tenga sentido.

El core de QuantumSafe continúa en Go.

## Deliverable

QuantumSafe debe poder importar recursos AWS al inventory.

PROMPT 16 — STACKIT + PROVIDER ABSTRACTION
Ahora quiero añadir STACKIT.

Actúa como Cloud Security Architect.

## Objetivo

Comparar conceptualmente:

AWS
vs
STACKIT

y posteriormente integrar STACKIT donde tenga sentido.

## Primero

Investiga documentación oficial actualizada.

No inventes:

- APIs
- recursos
- IAM capabilities
- KMS capabilities

Si algo no puede confirmarse:

"No puedo confirmar esto."

## Después

Identifica qué conceptos son realmente comunes entre AWS y STACKIT.

Solo entonces diseña una abstracción:

CloudProvider

si realmente está justificada.

## Quiero aprender

- provider abstraction
- dependency inversion
- cloud portability
- sovereign cloud
- API integration

## Deliverable

Inventory capaz de representar recursos procedentes de múltiples providers sin destruir las diferencias específicas de cada provider.

PROMPT 17 — DOCKER & PRODUCTION CONTAINER
Ahora quiero containerizar QuantumSafe correctamente.

Actúa como DevOps + Security Engineer.

## Componentes

- Go API
- workers
- PostgreSQL

## Quiero aprender

- Dockerfile
- multi-stage builds
- minimal images
- non-root containers
- environment configuration
- secrets
- health checks
- networking
- volumes

## Deliverable

docker compose up

debe levantar:

QuantumSafe
+
PostgreSQL

## Security

Analiza:

- container user
- filesystem permissions
- exposed ports
- secrets
- dependency vulnerabilities
- image size
- supply chain

No introduzcas Kubernetes todavía.

PROMPT 18 — KUBERNETES FUNDAMENTALS
Ahora quiero migrar QuantumSafe a Kubernetes.

NO quiero Operators todavía.

Actúa como Kubernetes Engineer.

## Primero enséñame

- Pod
- Deployment
- Service
- ConfigMap
- Secret
- Volume
- probes
- resources
- namespaces

## Después

Desplegar:

QuantumSafe API
+
workers
+
PostgreSQL

## Quiero entender

- desired state
- declarative configuration
- controllers
- scheduling
- service discovery
- health checks
- restart behaviour

## Security

Aplicar:

- non-root
- least privilege
- NetworkPolicy cuando sea apropiado
- Secret handling
- resource limits
- securityContext

## Deliverable

QuantumSafe funcionando en un cluster local.

No Helm todavía.
No Operator todavía.

PROMPT 19 — HELM
Ahora que entiendo Kubernetes básico, quiero empaquetar QuantumSafe con Helm.

Actúa como Kubernetes Engineer.

## Quiero aprender

- Helm charts
- values
- templates
- environments
- upgrades
- rollback

## Crear

helm/quantumsafe/

Debe parametrizar:

- image
- replicas
- resources
- database configuration
- environment
- secrets
- probes

## Quiero evitar

templates innecesariamente complejos.

## Deliverable

Poder:

helm install quantumsafe ...

y posteriormente actualizarlo.

Documenta cómo funciona el chart.

PROMPT 20 — KUBERNETES OPERATOR
Ahora quiero construir un Kubernetes Operator para QuantumSafe.

Este es un objetivo prioritario porque quiero desarrollar competencias de Kubernetes Operators para Security/Cloud-Native Engineering.

Actúa como:

- Kubernetes Engineer
- Go Engineer
- Controller/Operator expert

## Antes de programar

Explícame:

- CRD
- controller
- reconciliation
- desired state
- actual state
- status
- conditions
- retries
- idempotency
- eventual consistency

## CRD

Crear:

apiVersion: quantumsafe.io/v1
kind: CryptoKey

spec:
  algorithm: AES-256-GCM
  rotationPeriod: 30d

## Operator

Debe gestionar:

CryptoKey
↓
Key resource
↓
rotation
↓
status

## Primera versión

Solo:

- create
- reconcile
- update status
- detect configuration changes
- retry failures

Después:

- automatic rotation

## Requisitos

El reconciliation loop debe ser:

- idempotent
- retryable
- observable

## No hacer

No construir un Operator enterprise.

No añadir 20 CRDs.

Uno es suficiente para demostrar:

desired state
+
reconciliation
+
self-healing
+
key lifecycle.

PROMPT 21 — SRE & OBSERVABILITY
Ahora quiero convertir QuantumSafe en un sistema operable.

Actúa como SRE + Security Engineer.

## Añadir

- structured logging
- metrics
- health endpoints
- readiness
- liveness
- graceful shutdown
- retries
- timeouts
- request IDs
- audit correlation

## Métricas

API:
request_count
latency
errors

Discovery:
scan_duration
targets
services

Crypto:
encrypt_latency
decrypt_latency
sign_latency
verify_latency
rotation_latency

Database:
query_latency
connection_pool

## Quiero aprender

- observability
- SLI/SLO concepts
- failure handling
- retries
- timeouts
- graceful degradation

## Deliverable

Poder detectar:

- API unhealthy
- database unavailable
- scanner failures
- high crypto latency
- worker failures

PROMPT 22 — PERFORMANCE ENGINEERING
Ahora quiero analizar el rendimiento de QuantumSafe.

Actúa como Performance Engineer + Go Engineer + Applied Cryptography Engineer.

NO optimices nada antes de medirlo.

## Medir

- API latency
- scanner throughput
- database queries
- encryption
- decryption
- signing
- verification
- key rotation
- PQC operations

## Herramientas

- go test -bench
- pprof
- profiling
- allocation analysis

## Quiero aprender

- benchmarks
- CPU profiling
- memory profiling
- allocations
- concurrency
- bottleneck identification

## Deliverable

Crear benchmarks reproducibles.

Documentar:

baseline
bottleneck
change
result

No inventes resultados.

Todos los números deben proceder de ejecuciones reales.

PROMPT 23 — PQC LAB
Ahora quiero conectar QuantumSafe con los conocimientos de mi TFG.

Actúa como Applied Cryptography Engineer especializado en PQC.

## Objetivo

Construir un PQC Lab separado del core de Discovery.

Comparar:

Classical
Hybrid
PQC

Key establishment:

X25519
X25519 + ML-KEM
ML-KEM

Signatures:

ECDSA
ECDSA + ML-DSA
ML-DSA

## Medir

- key sizes
- ciphertext sizes
- signature sizes
- handshake payload
- latency
- CPU
- memory
- throughput

## Importante

No inventes resultados.

Cada benchmark debe ser reproducible.

No presentes benchmarks realizados en mi máquina como verdades universales.

Documenta:

hardware
OS
Go version
library version
parameters
benchmark methodology

## Objetivo conceptual

El PQC Lab debe alimentar posteriormente:

PQC Readiness
+
Migration Validation
+
Crypto Agility

No debe convertirse en otro proyecto independiente.

PROMPT 24 — SECURITY HARDENING
Ahora quiero realizar un security review completo de QuantumSafe.

Actúa como:

Senior Security Engineer
+
Application Security Engineer
+
Cloud Security Engineer.

Realiza threat modeling sobre:

- API
- scanner
- database
- crypto services
- KMS component
- cloud integrations
- Docker
- Kubernetes
- Operator

## Especial atención

### Scanner

- SSRF
- internal network access
- metadata services
- DNS rebinding
- malicious targets

### API

- authentication
- authorization
- injection
- abuse
- rate limiting
- information leakage

### Crypto Services

- key exposure
- plaintext exposure
- nonce reuse
- authorization
- audit integrity

### Kubernetes

- RBAC
- Secrets
- ServiceAccounts
- container security
- network policies

### Cloud

- IAM
- credentials
- least privilege

## Deliverable

Crear threat model actualizado y security hardening checklist.

Para cada finding:

severity
impact
likelihood
mitigation
status

PROMPT 25 — CI/CD & SUPPLY CHAIN
Ahora quiero construir un pipeline CI/CD profesional.

Actúa como DevSecOps Engineer.

## Pipeline

push
↓
format
↓
unit tests
↓
integration tests
↓
static analysis
↓
dependency checks
↓
security checks
↓
Docker build
↓
container security scan

## Quiero aprender

- GitHub Actions
- CI/CD
- dependency security
- supply-chain security
- reproducible builds
- container security

## Posteriormente

Deployment a Kubernetes.

## Importante

No conviertas CI/CD en una plataforma gigantesca.

Debe ser fácil de entender y mantener.

PROMPT 26 — DISASTER RECOVERY & OPERATIONS
Ahora quiero aprender a operar QuantumSafe.

Actúa como SRE.

Diseña un pequeño modelo operativo para:

- backup
- restore
- database recovery
- key metadata recovery
- audit recovery
- deployment rollback
- failure scenarios

## Quiero entender

¿Qué ocurre si:

1. PostgreSQL desaparece?
2. API se reinicia?
3. worker muere?
4. Kubernetes node desaparece?
5. una key rotation falla?
6. una versión de key queda inconsistente?
7. un deployment rompe la API?

## Deliverable

Crear:

operations.md
disaster-recovery.md

y ejercicios prácticos de recuperación.

No quiero una arquitectura enterprise multi-region.

PROMPT 27 — FINAL ARCHITECTURE REVIEW
Quiero que hagas una revisión arquitectónica final de QuantumSafe.

Actúa como Principal Security Architect.

No asumas que todo lo que hemos construido está bien.

Quiero que critiques:

- architecture
- boundaries
- packages
- database
- API
- discovery
- crypto services
- KMS
- cloud integrations
- Kubernetes
- Operator
- observability
- security
- performance

Busca:

- overengineering
- accidental complexity
- coupling
- security weaknesses
- unnecessary abstractions
- poor separation of concerns
- scalability problems
- maintainability problems

Para cada problema:

Problem
Why it matters
Severity
Recommendation

No cambies arquitectura solamente por hacerla más sofisticada.

PROMPT 28 — PORTFOLIO & GITHUB
Ahora quiero convertir QuantumSafe en un portfolio técnico profesional.

Actúa como Senior Engineer + Technical Writer + Hiring Manager para puestos de:

Applied Cryptography
Security Engineering
Cloud Security
Go
Kubernetes
KMS

Revisa el proyecto como si fueras a evaluar mi GitHub.

Quiero asegurar que existan:

- README
- architecture diagram
- threat model
- crypto design
- API documentation
- security documentation
- ADRs
- tests
- integration tests
- benchmarks
- profiling
- Docker
- Kubernetes
- Helm
- Operator
- CI/CD
- AWS
- STACKIT
- Python automation
- PQC Lab

Clasifica:

MUST HAVE
SHOULD HAVE
NICE TO HAVE

No quiero añadir funcionalidades nuevas solo para impresionar.

Quiero mejorar la presentación y evidencia de lo que realmente construimos.

PROMPT 29 — INTERVIEW PREPARATION
Quiero utilizar QuantumSafe como preparación para entrevistas de:

Applied Cryptography
Security Engineering
Cloud Security
Go
KMS
Kubernetes
Cloud-Native Security

Actúa como entrevistador técnico senior.

Genera preguntas basadas exclusivamente en cosas que realmente haya implementado en QuantumSafe.

Divide las preguntas en:

1. Go
2. Applied Cryptography
3. KMS
4. Envelope Encryption
5. DEK/KEK
6. Key Rotation
7. RSA-OAEP
8. AES-GCM
9. ECDSA
10. HMAC
11. PQC
12. Crypto Agility
13. REST
14. PostgreSQL
15. AWS
16. STACKIT
17. Kubernetes
18. Operators
19. SRE
20. Infrastructure
21. Python
22. Security

Para cada pregunta:

- pregunta
- qué está evaluando
- respuesta esperada
- errores comunes
- follow-up question

Después hazme una entrevista simulada.

No me des las respuestas inmediatamente.

PROMPT 30 — FINAL TECHNICAL DEFENSE
Quiero hacer una defensa técnica completa de QuantumSafe.

Actúa como un panel compuesto por:

- Principal Software Engineer
- Applied Cryptography Engineer
- Cloud Security Engineer
- Kubernetes Engineer
- SRE
- Security Architect

Quiero que me hagan preguntas difíciles sobre el sistema.

Especialmente:

- por qué Go
- por qué modular monolith
- por qué PostgreSQL
- por qué DEK/KEK
- envelope encryption
- key rotation
- key versioning
- secure key storage
- AES-GCM
- RSA-OAEP
- ECDSA
- HMAC
- ML-KEM
- ML-DSA
- hybrid cryptography
- crypto agility
- migration planning
- AWS
- STACKIT
- Kubernetes
- Operators
- reconciliation
- self-healing
- SRE
- observability
- performance
- threat model

No quiero preguntas puramente teóricas.

Relaciona cada pregunta con una decisión o componente real de QuantumSafe.

Si mi respuesta es incorrecta:

1. dime qué está mal
2. explica el concepto
3. pregunta de nuevo de una forma diferente

El objetivo es que pueda defender técnicamente el proyecto sin depender de memorizar respuestas.

ORDEN FINAL
El orden recomendado es:
00 Architecture
        ↓
01 Go CLI
        ↓
02 Discovery
        ↓
03 PostgreSQL + Inventory
        ↓
04 REST API
        ↓
05 Risk Engine
        ↓
06 PQC Readiness
        ↓
07 Crypto Agility
        ↓
08 Migration Planner
        ↓
09 Crypto Services Architecture
        ↓
10 Key Lifecycle
        ↓
11 Key Rotation
        ↓
12 Envelope Encryption
        ↓
13 Signing / Verification
        ↓
14 Audit
        ↓
15 AWS
        ↓
16 STACKIT
        ↓
17 Docker
        ↓
18 Kubernetes
        ↓
19 Helm
        ↓
20 Kubernetes Operator
        ↓
21 SRE / Observability
        ↓
22 Performance
        ↓
23 PQC Lab
        ↓
24 Security Hardening
        ↓
25 CI/CD
        ↓
26 Disaster Recovery
        ↓
27 Architecture Review
        ↓
28 Portfolio
        ↓
29 Interview Preparation
        ↓
30 Technical Defense
Regla de progreso
No consideres una fase terminada porque "el código funciona".
Una fase está terminada cuando:
Concept understood
+
Implementation works
+
Tests exist
+
Security considered
+
Documentation exists
+
Git history is clean
+
I can explain the design in an interview
El objetivo final no es tener 30 features.
El objetivo es que cada fase deje una evidencia técnica demostrable de una competencia profesional.
