# Pentest com Windows Nativo (PTES + LOLBins)

Simulação completa de um fluxo de **pentest alinhado ao PTES (Penetration Testing Execution Standard)** utilizando **exclusivamente ferramentas nativas do Windows**  
(CMD, PowerShell e recursos built-in do Windows 10/11 e Windows Server 2016+).

> ⚠️ **Aviso crítico (2026)**  
> - Apenas para **fins educacionais em laboratório próprio**  
> - Uso sem autorização escrita é **crime** (art. 154-A CP + LGPD + Marco Civil)  
> - Em ambientes reais, isso é usado por **red teams autorizados** para simular **Living-off-the-Land attacks (LOLBins)**

---

## Fases PTES adaptadas para Windows nativo

| Fase PTES | Ferramentas nativas usadas | Exemplos |
|----------|---------------------------|----------|
| Pre-engagement | Manual (Word / Notepad) | Planejamento de escopo, RoE |
| Intelligence Gathering | ping, nslookup, netstat, systeminfo, whoami /all | Recon passivo + ativo |
| Threat Modeling | Manual + PowerShell | Get-AD\*, net view |
| Vulnerability Analysis | netstat, systeminfo, wmic, Get-HotFix | Enumeração de serviços |
| Exploitation | rundll32, mshta, certutil, bitsadmin, PowerShell | LOLBins |
| Post Exploitation | net user, schtasks, wevtutil, Invoke-Command | Persistência, pivoting |
| Reporting | Out-File, Export-Csv | Evidências |

---

## Ambiente de teste sugerido

- **Atacante:** Windows 11 (PC ou VM)
- **Vítima:** Windows 10/11 (VM)
- **IP da vítima:** `192.168.56.101`
- **Rede:** Interna (Host-Only ou NAT)
- **Credenciais:** Usuário low-priv previamente obtido (phishing simulado, share etc.)

---

## 1. Intelligence Gathering (Recon)

### No atacante (PowerShell como admin)

```powershell
# Identidade e contexto
whoami /all
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
