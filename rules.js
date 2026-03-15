const RULES = [
    // ── CRITICAL ──────────────────────────────────────────
    {
        id: "R001", name: "Public S3 Bucket", severity: "critical",
        pattern: /"?public[_-]?access"?\s*[:=]\s*["']?true["']?/i,
        fix: "Set 'public_access: false' and use IAM policies to control bucket access."
    },
    {
        id: "R002", name: "Hardcoded Password", severity: "critical",
        pattern: /"?password"?\s*[:=]\s*["']?[a-zA-Z0-9@#$%^&*_\-.]{4,}["']?/i,
        fix: "Never hardcode passwords. Use environment variables or a secrets manager like AWS Secrets Manager."
    },
    {
        id: "R003", name: "Hardcoded API Key", severity: "critical",
        pattern: /"?api[_-]?key"?\s*[:=]\s*["']?[a-zA-Z0-9\-_]{6,}["']?/i,
        fix: "Move API keys to environment variables. Never commit secrets to source code."
    },
    {
        id: "R004", name: "Hardcoded Secret Key", severity: "critical",
        pattern: /"?secret[_-]?key"?\s*[:=]\s*["']?[a-zA-Z0-9\-_]{6,}["']?/i,
        fix: "Store secret keys in a vault (e.g. HashiCorp Vault, AWS Secrets Manager)."
    },
    {
        id: "R005", name: "Hardcoded Access Token", severity: "critical",
        pattern: /"?access[_-]?token"?\s*[:=]\s*["']?[a-zA-Z0-9\-_.]{8,}["']?/i,
        fix: "Use short-lived tokens via IAM roles. Never hardcode long-lived tokens."
    },
    {
        id: "R006", name: "Admin Credentials Exposed", severity: "critical",
        pattern: /"?admin[_-]?password"?\s*[:=]\s*["']?.+["']?/i,
        fix: "Remove admin credentials from config. Use IAM roles with least-privilege access."
    },
    {
        id: "R007", name: "Private Key in Config", severity: "critical",
        pattern: /-----BEGIN (RSA |EC )?PRIVATE KEY-----|"?private[_-]?key"?\s*[:=]/i,
        fix: "Never store private keys in config files. Use certificate stores or key management services."
    },

    // ── HIGH ──────────────────────────────────────────────
    {
        id: "R008", name: "Unencrypted Storage", severity: "high",
        pattern: /"?encrypt(ion|ed)?"?\s*[:=]\s*["']?false["']?/i,
        fix: "Enable encryption at rest. Set 'encryption: true' or configure KMS keys."
    },
    {
        id: "R009", name: "All Ports Open (0.0.0.0/0)", severity: "high",
        pattern: /"?cidr"?\s*[:=]\s*["']?0\.0\.0\.0\/0["']?/i,
        fix: "Restrict CIDR ranges to known IPs. Never expose all ports to the public internet."
    },
    {
        id: "R010", name: "Root Account Usage", severity: "high",
        pattern: /"?user"?\s*[:=]\s*["']?root["']?/i,
        fix: "Avoid root credentials. Create IAM users with least-privilege permissions."
    },
    {
        id: "R011", name: "SSL/TLS Disabled", severity: "high",
        pattern: /"?ssl"?\s*[:=]\s*["']?false["']?|"?tls"?\s*[:=]\s*["']?false["']?/i,
        fix: "Always enable SSL/TLS for data in transit. Set 'ssl: true' and use valid certificates."
    },
    {
        id: "R012", name: "Firewall Disabled", severity: "high",
        pattern: /"?firewall"?\s*[:=]\s*["']?false["']?|"?enable[_-]?firewall"?\s*[:=]\s*["']?false["']?/i,
        fix: "Enable firewall rules to control inbound and outbound traffic to your resources."
    },
    {
        id: "R013", name: "Unrestricted SSH Access", severity: "high",
        pattern: /port\s*[:=]\s*["']?22["']?.*cidr|ssh.*0\.0\.0\.0/i,
        fix: "Restrict SSH (port 22) to specific trusted IP addresses only."
    },

    // ── MEDIUM ────────────────────────────────────────────
    {
        id: "R014", name: "Logging Disabled", severity: "medium",
        pattern: /"?logging"?\s*[:=]\s*["']?false["']?|"?enable[_-]?logging"?\s*[:=]\s*["']?false["']?/i,
        fix: "Enable logging to track access patterns and detect suspicious activity."
    },
    {
        id: "R015", name: "MFA Not Enforced", severity: "medium",
        pattern: /"?mfa([_-]?enabled)?"?\s*[:=]\s*["']?false["']?/i,
        fix: "Enable MFA for all user accounts, especially admin and privileged roles."
    },
    {
        id: "R016", name: "Monitoring Disabled", severity: "medium",
        pattern: /"?monitor(ing)?"?\s*[:=]\s*["']?false["']?|"?enable[_-]?monitoring"?\s*[:=]\s*["']?false["']?/i,
        fix: "Enable monitoring to track resource health and detect anomalies early."
    },
    {
        id: "R017", name: "Versioning Disabled", severity: "medium",
        pattern: /"?versioning"?\s*[:=]\s*["']?false["']?|"?enable[_-]?versioning"?\s*[:=]\s*["']?false["']?/i,
        fix: "Enable versioning on storage buckets to protect against accidental data deletion."
    },
    {
        id: "R018", name: "Weak Password Policy", severity: "medium",
        pattern: /"?min[_-]?password[_-]?length"?\s*[:=]\s*["']?[1-7]["']?/i,
        fix: "Set minimum password length to at least 12 characters with complexity requirements."
    },
    {
        id: "R019", name: "Debug Mode Enabled", severity: "medium",
        pattern: /"?debug"?\s*[:=]\s*["']?true["']?/i,
        fix: "Disable debug mode in production. It can expose sensitive stack traces and data."
    },

    // ── LOW ───────────────────────────────────────────────
    {
        id: "R020", name: "Backup Disabled", severity: "low",
        pattern: /"?backup"?\s*[:=]\s*["']?false["']?|"?enable[_-]?backup"?\s*[:=]\s*["']?false["']?/i,
        fix: "Enable automated backups with a defined retention period to prevent data loss."
    },
    {
        id: "R021", name: "No Tags Defined", severity: "low",
        pattern: /"?tags"?\s*[:=]\s*(\{\s*\}|\[\s*\]|null)/i,
        fix: "Add resource tags for cost tracking, ownership, and environment identification."
    },
    {
        id: "R022", name: "Auto Updates Disabled", severity: "low",
        pattern: /"?auto[_-]?update"?\s*[:=]\s*["']?false["']?/i,
        fix: "Enable automatic updates to ensure security patches are applied promptly."
    },
    {
        id: "R023", name: "Deletion Protection Off", severity: "low",
        pattern: /"?deletion[_-]?protection"?\s*[:=]\s*["']?false["']?/i,
        fix: "Enable deletion protection on critical resources to prevent accidental removal."
    }
];