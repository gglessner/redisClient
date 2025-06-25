# Redis Security Auditing Client

A comprehensive Redis security auditing tool designed for penetration testers, security auditors, and security professionals.

**Author:** Garland Glessner <gglessner@gmail.com>  
**License:** GNU General Public License v3.0

## Features

- **Server Version Detection**: Identifies Redis version for CVE assessment
- **CVE Vulnerability Checking**: Local lookup table for known Redis vulnerabilities
- **TLS/SSL Support**: Validates encryption configuration
- **Authentication Testing**: Checks for proper authentication setup
- **ACL Analysis**: Enumerates users and permissions (if accessible)
- **Permission Testing**: Tests actual write, read, and delete capabilities
- **Data Dumping**: Lists all keys and their data with proper formatting
- **Security Configuration Analysis**: Comprehensive security posture assessment
- **Memory and Persistence Checks**: Validates data protection mechanisms
- **Network Security Assessment**: Analyzes network configuration and binding
- **Command Access Control**: Identifies dangerous command availability
- **Command Renaming Detection**: Checks if critical commands are disabled
- **Replication Security**: Checks replication configuration
- **Lua Scripting Analysis**: Assesses scripting capabilities
- **Module Security**: Reviews loaded modules and versions
- **Logging Configuration**: Validates log settings and file locations
- **Monitoring Command Access**: Checks MONITOR command availability
- **Backup Configuration**: Reviews persistence and backup settings
- **OS Hardening**: Checks running user and environment
- **Protected Mode Validation**: Ensures proper network protection
- **Sensitive Data Detection**: Identifies potentially sensitive keys
- **Clean Operation**: No denial of service tests, production-safe

## Installation

1. **Clone or download the repository**
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

```bash
# Connect to local Redis server
python redisClient.py localhost:6379

# Connect to remote server with TLS
python redisClient.py redis.example.com:6380 --tls

# Connect with authentication
python redisClient.py 192.168.1.100:6379 --password mypassword

# Custom timeout
python redisClient.py localhost:6379 --timeout 15

# Enable CVE vulnerability checking
python redisClient.py localhost:6379 --cve-check

# Dump all keys and their data
python redisClient.py localhost:6379 --dump-data

# Test write, read, and delete permissions
python redisClient.py localhost:6379 --test-permissions

# Combine multiple options
python redisClient.py localhost:6379 --cve-check --dump-data --test-permissions
```

### Command Line Options

- `server`: Redis server address in format `host:port`
- `--tls`: Use TLS encryption for connection
- `--password`: Redis password for authentication
- `--timeout`: Connection timeout in seconds (default: 10)
- `--cve-check`: Check server version against local CVE table
- `--dump-data`: Dump all keys and their data
- `--test-permissions`: Test write, read, and delete capabilities
- `--version`: Show version information

## Security Assessment Areas

### 1. Version Analysis & CVE Assessment
- Identifies Redis server version
- Checks against local CVE database for known vulnerabilities
- Provides direct links to NVD for detailed vulnerability information
- Critical for security research and compliance

### 2. Authentication & Authorization
- Tests for password protection
- Identifies unauthenticated access
- Enumerates ACL users and permissions (if accessible)
- Checks for overly permissive user configurations

### 3. Permission Testing
- **Write Testing**: Creates a test key to verify write capabilities
- **Read Testing**: Retrieves and verifies the test key value
- **Delete Testing**: Removes the test key and verifies deletion
- **Real Permission Assessment**: Tests actual capabilities, not just configuration
- **Clean Operation**: Creates and removes test data, leaving no trace

### 4. Data Exposure Analysis
- **Key Enumeration**: Lists all keys in the database
- **Data Type Detection**: Identifies string, list, set, hash, zset, stream types
- **Content Sampling**: Shows first 10 items for large collections
- **TTL Information**: Displays time-to-live for each key
- **Sensitive Data Detection**: Identifies potentially sensitive key patterns

### 5. Encryption Assessment
- Validates TLS/SSL configuration
- Checks for encrypted communications
- Identifies unencrypted data transmission risks

### 6. Network Security
- Analyzes port configuration (default port warnings)
- Checks binding settings (all interfaces vs. localhost)
- Validates protected mode configuration
- Identifies network exposure risks

### 7. Command Security
- Analyzes dangerous command availability (FLUSHALL, CONFIG, DEBUG, etc.)
- Detects if critical commands have been renamed or disabled
- Identifies potential misconfiguration
- Checks MONITOR command access

### 8. Memory and Persistence
- Checks memory management policies
- Validates data persistence mechanisms (RDB/AOF)
- Reviews backup configuration
- Identifies data durability risks

### 9. Client Management
- Monitors connection limits and usage
- Identifies resource usage patterns
- Checks for connection exhaustion risks

### 10. Replication Security
- Assesses master/slave configuration
- Validates replication security settings
- Checks for cluster configuration

### 11. Scripting and Modules
- Analyzes Lua scripting capabilities
- Reviews loaded modules and versions
- Identifies potential execution risks

### 12. Logging and Monitoring
- Validates log level configuration
- Checks log file locations
- Reviews monitoring command access
- Identifies audit trail gaps

### 13. OS and Environment
- Checks if Redis is running as root
- Validates filesystem permissions (if accessible)
- Reviews resource limits

### 14. Data Exposure
- Samples keyspace for sensitive data patterns
- Identifies potentially sensitive key names
- Reviews data structure types

## Security Findings

The tool categorizes findings by severity:

- **CRITICAL**: Immediate security risks requiring immediate attention
  - No authentication required
  - Critical CVEs affecting the server version
  - Remote code execution vulnerabilities

- **HIGH**: Significant security vulnerabilities
  - TLS not enabled
  - Protected mode disabled
  - Bound to all network interfaces
  - High-severity CVEs
  - Write/Read permission denied

- **MEDIUM**: Moderate security concerns
  - Dangerous commands available
  - No persistence configured
  - Using default port
  - MONITOR command accessible
  - Delete permission denied

- **LOW**: Minor security observations
  - Command renaming/disabled (good practice)
  - Memory policy configuration
  - Logging configuration
  - Lua scripting enabled
  - Full database access granted

## Example Output

### Basic Security Audit
```
============================================================
Redis Security Audit - localhost:6379
Timestamp: 2025-06-24 13:53:21
============================================================

[INFO] Connection established successfully
[INFO] Redis Server Version: 8.0.2
[INFO] ACLs enabled. Users: ['default']
[INFO] Connected clients: 1/10000
[INFO] Found 0 keys in database
[INFO] Redis role: master
[INFO] Connected slaves: 0
[INFO] Loaded modules:
  - vectorset (version 1)

============================================================
SECURITY AUDIT REPORT
============================================================

[CRITICAL] Findings:
  1. No Authentication Required
     Category: Authentication
     Description: Redis server accepts connections without authentication
     Recommendation: Enable authentication by setting a strong password

[HIGH] Findings:
  1. TLS Not Enabled
     Category: Encryption
     Description: Redis connection is not using TLS encryption
     Recommendation: Enable TLS encryption for Redis connections in production

  2. Protected Mode Disabled
     Category: Configuration
     Description: Redis protected-mode is not enabled
     Recommendation: Enable protected-mode to prevent unauthorized access

  3. Redis Bound to All Interfaces
     Category: Network
     Description: Redis is accessible on all network interfaces
     Recommendation: Bind Redis to localhost or a private network interface

SUMMARY:
  Total findings: 25
  Critical: 1
  High: 3
  Medium: 12
  Low: 9
```

### Permission Testing
```
============================================================
PERMISSION TESTING
============================================================
[INFO] Testing permissions with key: redis_audit_test_1750798702
[INFO] Test value: test_value_1750798702

1. Testing WRITE permission...
   ✓ WRITE permission: GRANTED
2. Testing READ permission...
   ✓ READ permission: GRANTED
   ✓ Retrieved value matches: test_value_1750798702
3. Testing DELETE permission...
   ✓ DELETE permission: GRANTED
4. Verifying deletion...
   ✓ Deletion verified: Key successfully removed

========================================
PERMISSION TEST SUMMARY
========================================
WRITE:  ✓ GRANTED
READ:   ✓ GRANTED
DELETE: ✓ GRANTED
VERIFY: ✓ SUCCESS
```

### Data Dumping
```
============================================================
REDIS DATA DUMP
============================================================
[INFO] Found 3 keys in database

Key 1: user:session:12345
Type: hash
TTL: 3600 seconds (-1 = no expiry, -2 = key doesn't exist)
Length: 3 fields
  username: john_doe
  email: john@example.com
  last_login: 2025-06-24T13:30:00Z
----------------------------------------

Key 2: cache:products
Type: list
Length: 25 items
  [1]: {"id": 1, "name": "Product A"}
  [2]: {"id": 2, "name": "Product B"}
  ... and 23 more items
----------------------------------------

Key 3: session:abc123
Type: string
TTL: 1800 seconds (-1 = no expiry, -2 = key doesn't exist)
Value: {"user_id": 123, "permissions": ["read", "write"]}
----------------------------------------
```

## CVE Database

The tool includes a local CVE lookup table covering known Redis vulnerabilities:

- **CVE-2023-28856/28857**: Memory corruption in Redis 7.0.0 through 7.0.11
- **CVE-2022-31144**: Integer overflow in redis-cli (RCE possible)
- **CVE-2022-24834**: Integer overflow in Redis HyperLogLog (DoS possible)
- **CVE-2021-32626**: Integer overflow in redis-cli (RCE possible)
- **CVE-2021-29477**: Integer overflow in Redis HyperLogLog (DoS possible)
- **CVE-2020-14147**: Integer overflow in Redis HyperLogLog (DoS possible)
- **CVE-2018-11218**: Heap buffer overflow in ziplist (RCE possible)

The database is easily expandable by adding new entries to the `REDIS_CVE_TABLE` in the source code. The tool correctly identifies that recent Redis versions (like 8.0.2) are not vulnerable to older CVEs.

## Advanced Usage Scenarios

### Penetration Testing
```bash
# Comprehensive security assessment
python redisClient.py target:6379 --cve-check --dump-data --test-permissions

# Test with authentication
python redisClient.py target:6379 --password discovered_password --cve-check

# Test with TLS
python redisClient.py target:6380 --tls --cve-check --test-permissions
```

### Compliance Auditing
```bash
# Data exposure assessment
python redisClient.py target:6379 --dump-data

# Permission validation
python redisClient.py target:6379 --test-permissions

# Full compliance check
python redisClient.py target:6379 --cve-check --dump-data --test-permissions
```

### Security Research
```bash
# Vulnerability assessment
python redisClient.py target:6379 --cve-check

# Configuration analysis
python redisClient.py target:6379

# Data analysis
python redisClient.py target:6379 --dump-data
```

## Security Considerations

### Production Use
- This tool is designed for security assessment only
- No denial of service tests are performed
- All operations are read-only or non-destructive
- Proper cleanup is performed after each operation
- No data is modified or deleted during assessment (except test keys)
- Test keys are automatically created and removed during permission testing

### Legal and Ethical Use
- Only use on systems you own or have explicit permission to test
- Follow responsible disclosure practices
- Comply with applicable laws and regulations
- Respect network policies and access controls
- Permission testing creates temporary test data - ensure this is acceptable

### Limitations
- Some checks may require elevated privileges
- Network restrictions may limit certain assessments
- Results should be validated manually
- CVE database may not include all known vulnerabilities
- Some Redis configurations may prevent certain checks
- Permission testing requires write access to the database

## Troubleshooting

### Connection Issues
- **Protected Mode**: Redis may be running in protected mode, only accepting local connections
- **Authentication**: Server may require a password (use `--password`)
- **TLS**: Server may require encrypted connections (use `--tls`)
- **Firewall**: Network firewalls may block connections
- **Bind Configuration**: Server may be bound to specific interfaces only

### Permission Testing Issues
- **Write Permission Denied**: User cannot create new keys
- **Read Permission Denied**: User cannot read existing keys
- **Delete Permission Denied**: User cannot remove keys
- **ACL Restrictions**: Access Control Lists may prevent certain operations

### Data Dumping Issues
- **Large Datasets**: Output may be overwhelming for databases with many keys
- **Memory Constraints**: Very large keys may cause memory issues
- **Permission Restrictions**: Some keys may not be accessible

### Common Error Messages
- `DENIED Redis is running in protected mode`: Enable authentication or disable protected mode
- `Error 10054`: Connection forcibly closed - check network/firewall settings
- `Authentication failed`: Invalid password provided
- `SSL: WRONG_VERSION_NUMBER`: Server doesn't support TLS on the specified port
- `WRONGTYPE Operation against a key`: Key type mismatch during data dumping

## Contributing

Contributions are welcome! Please ensure:
- Code follows Python best practices
- Security features are production-safe
- Documentation is updated
- Tests are included for new features
- CVE database is updated with new vulnerabilities
- Permission testing is non-destructive and clean

## License

This project is licensed under the GNU General Public License v3.0. See the LICENSE file for details.

## Disclaimer

This tool is provided for educational and security assessment purposes only. The author is not responsible for any misuse or damage caused by this software. Always obtain proper authorization before testing any system. 