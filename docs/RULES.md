# Writing Rules in Vigil IDS

Vigil uses a simple YAML format to define detection rules. By default, rules are loaded from `rules/default.yaml`.

## Rule Structure

Every rule consists of metadata and a **condition**. When a packet matches the condition, an alert is generated.

```yaml
rules:
  - id: "RULE-001"                # Unique identifier for the rule
    name: "Example Rule"          # Short, readable name
    description: "What this does" # Detailed description
    severity: "high"              # e.g., low, medium, high, critical
    action: "alert"               # Action to take (currently 'alert')
    condition:
      type: <condition_type>      # The type of detection logic
```

## Supported Condition Types

Vigil currently supports the following rule types:

### 1. `ip_blocklist`

Matches traffic originating from known malicious IP addresses.

```yaml
    condition:
      type: ip_blocklist
      src_ips:
        - "192.168.1.100"
        - "10.0.0.55"
```

### 2. `port_scan` (Stateful)

Detects if a single source IP contacts multiple distinct destination ports within a given time window.

```yaml
    condition:
      type: port_scan
      threshold: 15       # Number of unique ports
      window_secs: 10     # Time window in seconds
```

### 3. `protocol_anomaly`

Detects suspicious patterns in packet headers, such as:
- Source and Destination ports being identical (e.g., Land attack)
- Truncated packets where the payload size is smaller than the IP header indicates

```yaml
    condition:
      type: protocol_anomaly
```

### 4. `match_all`

Matches every single packet. Useful for debugging or full packet logging.

```yaml
    condition:
      type: match_all
```

## Rule Engine Processing

The `vigil-ids` engine reads packets and applies the active ruleset. 

- **Stateless Rules** (`ip_blocklist`, `protocol_anomaly`, `match_all`) are evaluated in parallel utilizing all available CPU cores.
- **Stateful Rules** (`port_scan`) maintain an internal history mapping source IPs to ports accessed over time. They are evaluated sequentially to ensure data consistency without locking overhead.
