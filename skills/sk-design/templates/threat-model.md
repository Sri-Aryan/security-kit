<!--
SecurityKit threat model template. Fill every {{placeholder}}; keep headings and order.
Every component, flow and threat must point to evidence: file:line, a config file, or "stated by <user>".
-->
# Threat model: {{product_name}}

**Version:** {{version}} · **Date:** {{date}} · **Prepared with:** SecurityKit sk-design {{skill_version}}  
**Scope:** {{scope}}  <!-- whole product, or the feature under review -->  
**Participants / sources:** {{participants}}

## 1. Context

| | |
|---|---|
| Purpose | {{purpose}} |
| Users and roles | {{users_roles}} |
| Data handled (classification) | {{data_classification}} |
| Regulatory / contractual | {{regulatory}} |
| Business impact if compromised | {{business_impact}} |
| Target security level | {{security_level}} <!-- e.g. Low / Standard / High, with reason --> |

## 2. System model

### Components

| ID | Component | Type | Tech | Trust zone | Evidence |
|---|---|---|---|---|---|
| C1 | {{name}} | {{process/store/external}} | {{tech}} | {{zone}} | `{{file}}:{{line}}` |

### Data flows

| ID | From → To | Protocol | Authn | Authz point | Data | Crosses boundary |
|---|---|---|---|---|---|---|
| F1 | {{from}} → {{to}} | {{protocol}} | {{authn}} | {{authz}} | {{data}} | {{yes/no}} |

### Diagram

```mermaid
flowchart LR
  {{diagram}}
```

### Trust boundaries

| ID | Boundary | What crosses it | Controls at the crossing |
|---|---|---|---|
| TB1 | {{boundary}} | {{flows}} | {{controls}} |

## 3. Attack surface

| Entry point | Kind | Exposure (public/internal/admin) | Authn | Evidence |
|---|---|---|---|---|
| {{entry}} | {{kind}} | {{exposure}} | {{authn}} | `{{file}}:{{line}}` |

## 4. Threats (STRIDE)

| ID | Threat | STRIDE | Component / flow | Likelihood | Impact | Existing controls | Response | Mitigation / requirement | Owner | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| T1 | {{threat}} | {{S/T/R/I/D/E}} | {{C/F id}} | {{H/M/L}} | {{H/M/L}} | {{controls}} | {{mitigate/eliminate/transfer/accept}} | {{requirement}} | {{owner}} | {{open/mitigated/accepted}} |

## 5. Abuse cases

| ID | As an attacker I want to… | Workflow | Control | Test |
|---|---|---|---|---|
| A1 | {{abuse}} | {{workflow}} | {{control}} | {{test}} |

## 6. Security requirements derived

| ID | Requirement | From threat(s) | Verified by | Status |
|---|---|---|---|---|
| R1 | {{requirement}} | {{T ids}} | {{test / skill / review}} | {{status}} |

## 7. Accepted and transferred risks

| Threat | Decision | Reason | Owner | Review date |
|---|---|---|---|---|
| {{T id}} | {{accept/transfer}} | {{reason}} | {{owner}} | {{date}} |

## 8. Open questions

- {{question}}

## 9. Review

- Model matches the running system: {{yes/no + notes}}
- All entry points and boundaries covered: {{yes/no}}
- Mitigations measurable and tested: {{yes/no}}
- Next review: {{when}} (and on any change to connections, data or trust boundaries)
