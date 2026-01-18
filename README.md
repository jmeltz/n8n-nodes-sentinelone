# n8n-nodes-sentinelone

![SentinelOne](https://img.shields.io/badge/SentinelOne-6C2DC7?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48dGV4dCB4PSI1MCIgeT0iNjUiIGZvbnQtc2l6ZT0iNDgiIGZvbnQtd2VpZ2h0PSJib2xkIiBmaWxsPSJ3aGl0ZSIgdGV4dC1hbmNob3I9Im1pZGRsZSI+UzE8L3RleHQ+PC9zdmc+&logoColor=white)
![n8n](https://img.shields.io/badge/n8n-EA4B71?style=for-the-badge&logo=n8n&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

An n8n community node for interacting with the **SentinelOne API v2.1**. Manage your endpoint security infrastructure directly from your n8n workflows.

## Features

### Agent Operations
| Operation | Description |
|-----------|-------------|
| **Get Agents** | Retrieve agents with comprehensive filtering options |
| **Get Applications** | Get installed applications for specific agents |
| **Initiate Scan** | Run full disk scans on targeted agents |
| **Connect to Network** | Reconnect isolated agents to the network |
| **Disconnect from Network** | Quarantine/isolate agents from the network |
| **Restart Machine** | Remotely restart endpoints |
| **Shutdown** | Remotely shut down endpoints |
| **Uninstall Agent** | Remove SentinelOne agents from endpoints |

### Threat Operations
| Operation | Description |
|-----------|-------------|
| **Get Threats** | Retrieve threats with filtering by status, verdict, OS type, etc. |
| **Mitigate Threat** | Apply mitigation actions (kill, quarantine, remediate, rollback, un-quarantine, network-quarantine) |

### Device Control Operations
| Operation | Description |
|-----------|-------------|
| **Create Rule** | Create device control rules scoped to sites, groups, accounts, or global |
| **Delete Rules** | Delete device control rules by ID |
| **Get Device Events** | Retrieve device control events (blocked/allowed devices) |
| **Get Device Rules** | Retrieve device control rules with filtering by interface, device class, action, etc. |
| **Update Rule** | Update existing device control rules |

### Tag Operations
| Operation | Description |
|-----------|-------------|
| **Get Tags** | Retrieve endpoint tags |
| **Manage Tags** | Add, remove, or override tags on agents |

## Installation

### Community Nodes (Recommended)

1. Go to **Settings** > **Community Nodes**
2. Select **Install**
3. Enter `n8n-nodes-sentinelone`
4. Agree to the risks and click **Install**

### Manual Installation

```bash
# In your n8n installation directory
npm install n8n-nodes-sentinelone
```

## Credentials

You'll need to configure your SentinelOne API credentials:

| Field | Description |
|-------|-------------|
| **API URL** | Your SentinelOne console URL (e.g., `https://usea1-partners.sentinelone.net`) |
| **API Token** | Your API token from SentinelOne console |

### Getting Your API Token

1. Log in to your SentinelOne Management Console
2. Navigate to **Settings** > **Users**
3. Select your user or create a service user
4. Click **Generate API Token**
5. Copy the token (it won't be shown again!)

## Operations Detail

### Agent: Get Agents

Retrieve a list of agents with powerful filtering capabilities.

**Filters Available:**
- Account/Site/Group IDs
- Computer name (contains)
- External IP (contains)
- OS Types (Windows, macOS, Linux)
- Machine Types (Desktop, Laptop, Server, Kubernetes, etc.)
- Network Status (Connected, Disconnected)
- Scan Status
- Infection status
- Agent version
- And many more...

### Agent: Get Applications

Retrieve installed applications for specific agents.

**Required:** Agent IDs (comma-separated)

### Agent: Actions (Scan, Connect, Disconnect, Restart, Shutdown, Uninstall)

Target agents by:
- **Agent IDs**: Specific agent IDs (comma-separated)
- **Filter**: Dynamic filter criteria (OS type, site, group, infection status, etc.)

### Threat: Get Threats

Retrieve threats with filtering:
- Analyst Verdicts (True Positive, False Positive, Suspicious, Undefined)
- Incident Statuses (In Progress, Resolved, Unresolved)
- Mitigation Statuses (Mitigated, Active, Blocked, Pending, etc.)
- Content Hash, Classification
- Date ranges

### Threat: Mitigate Threat

Apply mitigation actions:
- **Kill** - Terminate the threat process
- **Quarantine** - Quarantine the threat file
- **Remediate** - Remediate the threat (macOS/Windows)
- **Rollback Remediation** - Rollback remediation (Windows only)
- **Un-Quarantine** - Release from quarantine
- **Network Quarantine** - Network isolate the affected endpoint

### Device Control: Create Rule

Create a new device control rule with:
- **Scope**: Global (Tenant), Account, Site, or Group level
- **Interface**: USB, Bluetooth, Thunderbolt, eSATA
- **Rule Type**: Device Class, Vendor ID, Product ID, Device ID, Bluetooth Version
- **Action**: Allow, Block, Read-Only
- **Status**: Enabled or Disabled

### Device Control: Get Device Rules

Retrieve device control rules with filtering:
- Interfaces (USB, Bluetooth, Thunderbolt, eSATA)
- Device Classes (Mass Storage, Printer, Portable Device, Communication)
- Actions (Allow, Block, Read-Only)
- Scopes (Account, Global, Group, Site)
- Statuses (Enabled, Disabled)

### Device Control: Update Rule

Update an existing device control rule by ID. Modifiable fields:
- Rule Name, Action, Status, Device Class, Vendor ID, Product ID

### Device Control: Delete Rules

Delete device control rules by providing rule IDs (comma-separated).

### Device Control: Get Device Events

Retrieve device control events with filtering:
- Event Types (Blocked, Allowed, Read-Only)
- Interfaces, Agent IDs, Site/Group IDs
- Date ranges, Computer name, Query search

### Tag: Get Tags & Manage Tags

- **Get Tags**: Retrieve endpoint tags with filtering
- **Manage Tags**: Add, remove, or override tags
  - Supports key-value pairs
  - Target by Agent IDs or filter criteria

## Example Workflows

### Automated Threat Response

```
Trigger: Webhook from SIEM
    |
SentinelOne: Get Threats (filter: unresolved)
    |
IF: severity == high
    |
SentinelOne: Mitigate Threat (action: quarantine)
    |
SentinelOne: Disconnect from Network
    |
Slack: Notify Security Team
```

### Daily Security Report

```
Trigger: Schedule (Daily 8 AM)
    |
SentinelOne: Get Agents (filter: isActive=true)
    |
SentinelOne: Get Threats (filter: last 24 hours)
    |
Function: Calculate statistics
    |
Email: Send daily report
```

### Endpoint Tagging Automation

```
Trigger: Webhook (new employee)
    |
SentinelOne: Get Agents (filter: computerName contains "new-laptop")
    |
SentinelOne: Manage Tags (action: add, key: department, value: engineering)
```

### Device Control Audit

```
Trigger: Schedule (Weekly)
    |
SentinelOne: Get Device Rules (filter: interface=USB, action=Allow)
    |
Function: Format audit report
    |
Google Sheets: Append to compliance log
```

### Block USB Storage on New Sites

```
Trigger: Webhook (new site created)
    |
SentinelOne: Create Rule (scope: site, interface: USB, deviceClass: Mass Storage, action: Block)
    |
SentinelOne: Get Device Events (filter: siteId, eventType: blocked)
    |
Slack: Notify IT team of new policy
```

## API Reference

This node uses the **SentinelOne API v2.1**. For complete API documentation, visit your SentinelOne console's API documentation at:

```
https://your-console.sentinelone.net/api-doc/overview
```

## Compatibility

- **n8n Version:** 0.5.0+
- **Node.js:** 18+
- **SentinelOne API:** v2.1

## Support

- **Issues:** [GitHub Issues](https://github.com/jmeltz/n8n-nodes-sentinelone/issues)
- **SentinelOne Docs:** [Developer Portal](https://developer.sentinelone.com/)

## Changelog

### v0.3.0
- Expanded Device Control operations:
  - Create Rule (with site/group/account/global scoping)
  - Update Rule
  - Delete Rules
  - Get Device Events
- Enhanced rule creation with support for device class, vendor ID, product ID, and Bluetooth version matching

### v0.2.0
- Added Threat operations (Get Threats, Mitigate Threat)
- Added Device Control operations (Get Device Rules)
- Added Tag operations (Get Tags, Manage Tags)
- Enhanced filtering options for all operations

### v0.1.0
- Initial release
- Agent operations (Get Agents, Get Applications, Actions)

## License

[MIT](LICENSE)

---

Made with :purple_heart: for the n8n community
