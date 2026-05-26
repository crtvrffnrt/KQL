<div align="center">
  <img src="./logo.png" alt="KQL Hunter logo" width="360">

  <h1>KQL Hunter</h1>

  <p><strong>Compact, practical KQL for hunting, triage, and quick investigation pivots.</strong></p>

  <p>
    <a href="#identity"><img src="https://img.shields.io/badge/identity-0F172A?style=flat-square&logo=microsoft&logoColor=white" alt="Identity"></a>
    <a href="#mailbox"><img src="https://img.shields.io/badge/mailbox-111827?style=flat-square&logo=gmail&logoColor=white" alt="Mailbox"></a>
    <a href="#endpoint"><img src="https://img.shields.io/badge/endpoint-0EA5E9?style=flat-square&logo=windows&logoColor=white" alt="Endpoint"></a>
    <a href="#network"><img src="https://img.shields.io/badge/network-F59E0B?style=flat-square&logo=cloudflare&logoColor=white" alt="Network"></a>
    <a href="#defender"><img src="https://img.shields.io/badge/defender-22C55E?style=flat-square&logo=shield&logoColor=white" alt="Defender"></a>
  </p>

  <p>
    <a href="#identity"><strong>Identity</strong></a> •
    <a href="#mailbox"><strong>Mailbox</strong></a> •
    <a href="#endpoint"><strong>Endpoint</strong></a> •
    <a href="#network"><strong>Network</strong></a> •
    <a href="#defender"><strong>Defender</strong></a>
  </p>
</div>

> A grab-and-go set of queries for everyday defensive hunting.

---

## At a Glance

- Fast triage and hunting queries
- Reusable patterns for common investigations
- Focused on Microsoft Sentinel, Defender, and UAL-style telemetry
- Easy to tweak for your tenant, entity, or time window

## Identity

Queries for suspicious sign-ins, admin changes, impossible travel, and account activity pivots.

## Mailbox

Queries for phishing, malicious mail access, inbox abuse, and suspicious URL or attachment activity.

## Endpoint

Queries for malware execution, persistence, remote tools, suspicious scripts, and host reconnaissance.

## Network

Queries for botnet activity, Nmap-style scanning, brute force patterns, and unusual remote connections.

## Defender

Queries for tampering, realtime protection changes, AV exclusions, firewall bypass, and other control-disabling behavior.

## Structure

- Root `.kql` files cover the main hunts and detections
- `parser/` contains UAL parsing helpers

## Use

Open a query, swap in your entity or IP, adjust the time window, and run it in your hunting workspace.

