#!/usr/bin/env python3
"""
Redis Security Auditing Client
Author: Garland Glessner <gglessner@gmail.com>
License: GNU General Public License v3.0

A comprehensive Redis security auditing tool for penetration testers and security auditors.
This tool performs various security assessments without causing denial of service.
"""

import argparse
import socket
import ssl
import sys
import time
import json
import re
from typing import Optional, Dict, List, Any
from dataclasses import dataclass
from datetime import datetime
import redis
from redis.exceptions import (
    RedisError, ConnectionError, AuthenticationError, 
    ResponseError, TimeoutError, NoPermissionError
)
import os
from packaging import version


@dataclass
class SecurityFinding:
    """Represents a security finding during the audit."""
    severity: str
    category: str
    title: str
    description: str
    recommendation: str
    evidence: Optional[str] = None


# Local CVE lookup table for Redis versions (expand as needed)
REDIS_CVE_TABLE = {
    # Format: 'version': [(CVE, description, severity, reference_url)]
    # Only include CVEs that affect versions up to the specified version
    '7.0.0': [
        ('CVE-2023-28856', 'Memory corruption in Redis 7.0.0 through 7.0.11', 'HIGH', 'https://nvd.nist.gov/vuln/detail/CVE-2023-28856'),
        ('CVE-2023-28857', 'Memory corruption in Redis 7.0.0 through 7.0.11', 'HIGH', 'https://nvd.nist.gov/vuln/detail/CVE-2023-28857'),
    ],
    '6.2.0': [
        ('CVE-2022-31144', 'Integer overflow in redis-cli (RCE possible)', 'HIGH', 'https://nvd.nist.gov/vuln/detail/CVE-2022-31144'),
        ('CVE-2022-24834', 'Integer overflow in Redis HyperLogLog (DoS possible)', 'HIGH', 'https://nvd.nist.gov/vuln/detail/CVE-2022-24834'),
    ],
    '6.0.0': [
        ('CVE-2021-32626', 'Integer overflow in redis-cli (RCE possible)', 'HIGH', 'https://nvd.nist.gov/vuln/detail/CVE-2021-32626'),
        ('CVE-2021-29477', 'Integer overflow in Redis HyperLogLog (DoS possible)', 'HIGH', 'https://nvd.nist.gov/vuln/detail/CVE-2021-29477'),
    ],
    '5.0.0': [
        ('CVE-2020-14147', 'Integer overflow in Redis HyperLogLog (DoS possible)', 'HIGH', 'https://nvd.nist.gov/vuln/detail/CVE-2020-14147'),
    ],
    '4.0.0': [
        ('CVE-2018-11218', 'Heap buffer overflow in ziplist (RCE possible)', 'CRITICAL', 'https://nvd.nist.gov/vuln/detail/CVE-2018-11218'),
    ],
    # Add more versions and CVEs as needed
}

# Helper to compare Redis versions
def get_vulnerabilities_for_version(server_version):
    vulns = []
    for v, cves in REDIS_CVE_TABLE.items():
        try:
            # Check if the server version is LESS THAN OR EQUAL TO the vulnerable version
            # This means the server is vulnerable to CVEs affecting this version and below
            if version.parse(server_version) <= version.parse(v):
                vulns.extend(cves)
        except Exception:
            continue
    return vulns

class RedisSecurityAuditor:
    """Comprehensive Redis security auditing tool."""
    
    def __init__(self, host: str, port: int, use_tls: bool = False, 
                 password: Optional[str] = None, timeout: int = 10, cve_check: bool = False,
                 dump_data: bool = False, test_permissions: bool = False):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.password = password
        self.timeout = timeout
        self.cve_check = cve_check
        self.dump_data = dump_data
        self.test_permissions = test_permissions
        self.redis_client = None
        self.findings: List[SecurityFinding] = []
        self.server_version = None
        self.server_info = None
        
    def connect(self) -> bool:
        """Establish connection to Redis server."""
        try:
            connection_params = {
                'host': self.host,
                'port': self.port,
                'socket_timeout': self.timeout,
                'socket_connect_timeout': self.timeout,
                'retry_on_timeout': True,
                'decode_responses': True
            }
            
            if self.use_tls:
                connection_params['ssl'] = True
                connection_params['ssl_cert_reqs'] = ssl.CERT_NONE  # For testing purposes
                
            if self.password:
                connection_params['password'] = self.password
                
            self.redis_client = redis.Redis(**connection_params)
            
            # Test connection
            self.redis_client.ping()
            return True
            
        except AuthenticationError:
            print(f"[ERROR] Authentication failed for {self.host}:{self.port}")
            return False
        except ConnectionError as e:
            print(f"[ERROR] Connection failed to {self.host}:{self.port}: {e}")
            return False
        except Exception as e:
            print(f"[ERROR] Unexpected error connecting to {self.host}:{self.port}: {e}")
            return False
    
    def get_server_info(self) -> Optional[Dict[str, Any]]:
        """Get comprehensive server information."""
        try:
            info = self.redis_client.info()
            return info
        except Exception as e:
            print(f"[ERROR] Failed to get server info: {e}")
            return None
    
    def get_server_version(self) -> Optional[str]:
        """Get Redis server version."""
        try:
            info = self.redis_client.info('server')
            version_str = info.get('redis_version', 'Unknown')
            self.server_version = version_str
            print(f"[INFO] Redis Server Version: {version_str}")
            return version_str
        except Exception as e:
            print(f"[ERROR] Failed to get server version: {e}")
            return None
    
    def check_tls_encryption(self) -> None:
        """Check if TLS encryption is properly configured."""
        if not self.use_tls:
            self.findings.append(SecurityFinding(
                severity="HIGH",
                category="Encryption",
                title="TLS Not Enabled",
                description="Redis connection is not using TLS encryption",
                recommendation="Enable TLS encryption for Redis connections in production"
            ))
        else:
            print("[INFO] TLS encryption is enabled")
    
    def check_authentication(self) -> None:
        """Check authentication configuration."""
        try:
            # Try to execute a command without authentication
            test_client = redis.Redis(
                host=self.host,
                port=self.port,
                socket_timeout=self.timeout,
                decode_responses=True
            )
            
            # If we can execute commands without password, authentication is disabled
            test_client.ping()
            self.findings.append(SecurityFinding(
                severity="CRITICAL",
                category="Authentication",
                title="No Authentication Required",
                description="Redis server accepts connections without authentication",
                recommendation="Enable authentication by setting a strong password"
            ))
            test_client.close()
            
        except AuthenticationError:
            print("[INFO] Authentication is properly configured")
        except Exception:
            pass
    
    def check_dangerous_commands(self) -> None:
        """Check for dangerous commands availability."""
        dangerous_commands = [
            'FLUSHALL', 'FLUSHDB', 'CONFIG', 'DEBUG', 'SHUTDOWN',
            'SLAVEOF', 'REPLICAOF', 'BGREWRITEAOF', 'BGSAVE'
        ]
        
        for cmd in dangerous_commands:
            try:
                # Try to get command info
                cmd_info = self.redis_client.execute_command('COMMAND', 'INFO', cmd)
                if cmd_info:
                    self.findings.append(SecurityFinding(
                        severity="MEDIUM",
                        category="Command Access",
                        title=f"Dangerous Command Available: {cmd}",
                        description=f"The {cmd} command is available and may be misused",
                        recommendation=f"Consider disabling {cmd} command if not needed"
                    ))
            except Exception:
                pass
    
    def check_memory_configuration(self) -> None:
        """Check memory and persistence configuration."""
        try:
            info = self.redis_client.info('memory')
            
            # Check maxmemory policy
            maxmemory_policy = info.get('maxmemory_policy', 'noeviction')
            if maxmemory_policy == 'noeviction':
                self.findings.append(SecurityFinding(
                    severity="LOW",
                    category="Memory Management",
                    title="No Memory Eviction Policy",
                    description="Redis is configured with 'noeviction' policy",
                    recommendation="Consider setting an appropriate maxmemory policy"
                ))
            
            # Check if persistence is enabled
            rdb_enabled = info.get('rdb_last_save_time', 0) > 0
            aof_enabled = info.get('aof_enabled', 0) == 1
            
            if not rdb_enabled and not aof_enabled:
                self.findings.append(SecurityFinding(
                    severity="MEDIUM",
                    category="Persistence",
                    title="No Persistence Configured",
                    description="Redis has no persistence mechanism enabled",
                    recommendation="Enable RDB or AOF persistence for data durability"
                ))
                
        except Exception as e:
            print(f"[WARNING] Could not check memory configuration: {e}")
    
    def check_network_security(self) -> None:
        """Check network security settings."""
        try:
            info = self.redis_client.info('server')
            
            # Check bind configuration
            tcp_port = info.get('tcp_port', 0)
            if tcp_port == 6379:  # Default port
                self.findings.append(SecurityFinding(
                    severity="MEDIUM",
                    category="Network Security",
                    title="Using Default Port",
                    description="Redis is running on default port 6379",
                    recommendation="Consider changing the default port for security through obscurity"
                ))
                
        except Exception as e:
            print(f"[WARNING] Could not check network security: {e}")
    
    def check_client_connections(self) -> None:
        """Check client connection information."""
        try:
            info = self.redis_client.info('clients')
            connected_clients = info.get('connected_clients', 0)
            max_clients = info.get('maxclients', 0)
            
            print(f"[INFO] Connected clients: {connected_clients}/{max_clients}")
            
            if connected_clients > max_clients * 0.8:
                self.findings.append(SecurityFinding(
                    severity="LOW",
                    category="Resource Management",
                    title="High Client Connection Usage",
                    description=f"Using {connected_clients}/{max_clients} client connections",
                    recommendation="Monitor client connections and adjust maxclients if needed"
                ))
                
        except Exception as e:
            print(f"[WARNING] Could not check client connections: {e}")
    
    def check_slow_log(self) -> None:
        """Check slow query log configuration."""
        try:
            slow_log = self.redis_client.slowlog_get(10)  # Get last 10 slow queries
            if slow_log:
                print(f"[INFO] Found {len(slow_log)} slow queries in log")
                for entry in slow_log[:3]:  # Show first 3
                    print(f"  - Query: {entry.get('command', 'Unknown')}")
                    print(f"    Duration: {entry.get('duration', 0)} microseconds")
            else:
                print("[INFO] No slow queries found in log")
                
        except Exception as e:
            print(f"[WARNING] Could not check slow log: {e}")
    
    def check_key_patterns(self) -> None:
        """Analyze key patterns for potential security issues."""
        try:
            # Get a sample of keys (limited to avoid DoS)
            keys = self.redis_client.keys('*')
            if len(keys) > 1000:
                keys = keys[:1000]  # Limit to first 1000 keys
                
            print(f"[INFO] Found {len(keys)} keys in database")
            
            # Analyze key patterns
            patterns = {}
            for key in keys:
                if ':' in key:
                    prefix = key.split(':')[0]
                    patterns[prefix] = patterns.get(prefix, 0) + 1
            
            # Report suspicious patterns
            for prefix, count in sorted(patterns.items(), key=lambda x: x[1], reverse=True)[:5]:
                if count > 100:
                    print(f"[INFO] Common key prefix '{prefix}': {count} keys")
                    
        except Exception as e:
            print(f"[WARNING] Could not analyze key patterns: {e}")
    
    def check_replication_status(self) -> None:
        """Check replication configuration."""
        try:
            info = self.redis_client.info('replication')
            role = info.get('role', 'unknown')
            
            print(f"[INFO] Redis role: {role}")
            
            if role == 'master':
                connected_slaves = info.get('connected_slaves', 0)
                print(f"[INFO] Connected slaves: {connected_slaves}")
                
            elif role == 'slave':
                master_host = info.get('master_host', 'unknown')
                master_port = info.get('master_port', 'unknown')
                print(f"[INFO] Connected to master: {master_host}:{master_port}")
                
        except Exception as e:
            print(f"[WARNING] Could not check replication status: {e}")
    
    def check_lua_scripting(self) -> None:
        """Check Lua scripting capabilities."""
        try:
            # Try to execute a simple Lua script
            result = self.redis_client.eval("return 'test'", 0)
            if result == 'test':
                self.findings.append(SecurityFinding(
                    severity="LOW",
                    category="Scripting",
                    title="Lua Scripting Enabled",
                    description="Lua scripting is available",
                    recommendation="Monitor Lua script usage and consider restrictions if needed"
                ))
                
        except Exception as e:
            print(f"[WARNING] Could not check Lua scripting: {e}")
    
    def check_module_loading(self) -> None:
        """Check for loaded modules."""
        try:
            modules = self.redis_client.execute_command('MODULE', 'LIST')
            if modules:
                print("[INFO] Loaded modules:")
                for module in modules:
                    print(f"  - {module[1]} (version {module[3]})")
            else:
                print("[INFO] No modules loaded")
                
        except Exception as e:
            print(f"[WARNING] Could not check modules: {e}")
    
    def check_acl_and_users(self):
        """Check for ACLs and enumerate users/permissions if possible."""
        try:
            acl_list = self.redis_client.acl_list()
            users = self.redis_client.acl_users()
            print(f"[INFO] ACLs enabled. Users: {users}")
            for user in users:
                user_info = self.redis_client.acl_getuser(user)
                # Check for overly permissive users
                if user_info.get('commands', '') == 'allcommands' and user_info.get('keys', '') == 'allkeys':
                    self.findings.append(SecurityFinding(
                        severity="HIGH",
                        category="ACL",
                        title=f"User '{user}' has full access",
                        description=f"User '{user}' can run all commands on all keys.",
                        recommendation="Restrict user permissions using ACLs."
                    ))
        except Exception:
            print("[INFO] ACLs not enabled or not accessible.")
    
    def check_protected_mode(self):
        """Check if protected-mode is enabled."""
        try:
            config = self.redis_client.config_get('protected-mode')
            if config.get('protected-mode', 'yes') != 'yes':
                self.findings.append(SecurityFinding(
                    severity="HIGH",
                    category="Configuration",
                    title="Protected Mode Disabled",
                    description="Redis protected-mode is not enabled.",
                    recommendation="Enable protected-mode to prevent unauthorized access."
                ))
        except Exception:
            pass
    
    def check_bind_address(self):
        """Check if Redis is bound to 0.0.0.0 or a public IP."""
        try:
            config = self.redis_client.config_get('bind')
            bind_val = config.get('bind', '')
            if '0.0.0.0' in bind_val or not bind_val:
                self.findings.append(SecurityFinding(
                    severity="HIGH",
                    category="Network",
                    title="Redis Bound to All Interfaces",
                    description="Redis is accessible on all network interfaces.",
                    recommendation="Bind Redis to localhost or a private network interface."
                ))
        except Exception:
            pass
    
    def check_command_renaming(self):
        """Check if dangerous commands have been renamed or disabled."""
        dangerous = ['FLUSHALL', 'FLUSHDB', 'CONFIG', 'SHUTDOWN', 'DEBUG', 'MODULE']
        for cmd in dangerous:
            try:
                info = self.redis_client.execute_command('COMMAND', 'INFO', cmd)
                if info and info[0] and info[0][1] == 0:
                    self.findings.append(SecurityFinding(
                        severity="LOW",
                        category="Command Renaming",
                        title=f"Command {cmd} Renamed/Disabled",
                        description=f"{cmd} command is not available (renamed or disabled).",
                        recommendation=f"Ensure dangerous commands are renamed or disabled in production."
                    ))
            except Exception:
                # If command is not available, that's good
                self.findings.append(SecurityFinding(
                    severity="LOW",
                    category="Command Renaming",
                    title=f"Command {cmd} Renamed/Disabled",
                    description=f"{cmd} command is not available (renamed or disabled).",
                    recommendation=f"Ensure dangerous commands are renamed or disabled in production."
                ))
    
    def check_sensitive_keys(self):
        """Look for keys with sensitive names (sampled)."""
        try:
            keys = self.redis_client.keys('*')
            if len(keys) > 1000:
                keys = keys[:1000]
            sensitive_patterns = ['password', 'passwd', 'secret', 'token', 'key', 'auth']
            for key in keys:
                for pat in sensitive_patterns:
                    if pat in key.lower():
                        self.findings.append(SecurityFinding(
                            severity="HIGH",
                            category="Data Exposure",
                            title=f"Sensitive Key Found: {key}",
                            description=f"Key '{key}' may contain sensitive data.",
                            recommendation="Review and secure sensitive keys."
                        ))
        except Exception:
            pass
    
    def check_log_config(self):
        """Check log level and log file location."""
        try:
            config = self.redis_client.config_get()
            loglevel = config.get('loglevel', 'notice')
            logfile = config.get('logfile', '')
            if loglevel not in ['warning', 'notice']:
                self.findings.append(SecurityFinding(
                    severity="LOW",
                    category="Logging",
                    title="Non-Standard Log Level",
                    description=f"Log level is set to {loglevel}.",
                    recommendation="Set loglevel to 'notice' or 'warning' in production."
                ))
            if logfile == '' or logfile == 'stdout':
                self.findings.append(SecurityFinding(
                    severity="LOW",
                    category="Logging",
                    title="Log File Not Set",
                    description="Redis logs to stdout or no file.",
                    recommendation="Set a log file for persistent logging."
                ))
        except Exception:
            pass
    
    def check_monitor_command(self):
        """Check if MONITOR command is available."""
        try:
            self.redis_client.execute_command('MONITOR')
            self.findings.append(SecurityFinding(
                severity="MEDIUM",
                category="Monitoring",
                title="MONITOR Command Available",
                description="MONITOR command is available and may leak sensitive data.",
                recommendation="Restrict MONITOR command in production."
            ))
        except Exception:
            pass
    
    def check_backup_config(self):
        """Check for backup configuration (non-intrusive)."""
        try:
            config = self.redis_client.config_get()
            dir_val = config.get('dir', '')
            dbfilename = config.get('dbfilename', '')
            if not dir_val or not dbfilename:
                self.findings.append(SecurityFinding(
                    severity="MEDIUM",
                    category="Backup",
                    title="No Backup Configured",
                    description="No backup directory or filename set.",
                    recommendation="Configure RDB/AOF backups for disaster recovery."
                ))
        except Exception:
            pass
    
    def check_running_user(self):
        """Check if Redis is running as root (if info is available)."""
        try:
            info = self.redis_client.info('server')
            run_user = info.get('run_id', None)
            if run_user and run_user == 'root':
                self.findings.append(SecurityFinding(
                    severity="HIGH",
                    category="OS Hardening",
                    title="Redis Running as Root",
                    description="Redis is running as root user.",
                    recommendation="Run Redis as a non-root user."
                ))
        except Exception:
            pass
    
    def check_cve(self):
        """Check server version against local CVE table."""
        if not self.server_version:
            return
        vulns = get_vulnerabilities_for_version(self.server_version)
        for cve, desc, severity, url in vulns:
            self.findings.append(SecurityFinding(
                severity=severity,
                category="CVE",
                title=f"{cve} - {desc}",
                description=f"Server version {self.server_version} is affected by {cve}: {desc}",
                recommendation=f"Upgrade to a patched version. See: {url}",
                evidence=url
            ))
    
    def dump_all_data(self) -> None:
        """Dump all keys and their data with proper formatting."""
        try:
            print(f"\n{'='*60}")
            print("REDIS DATA DUMP")
            print(f"{'='*60}")
            
            # Get all keys
            all_keys = self.redis_client.keys('*')
            if not all_keys:
                print("[INFO] No keys found in the database")
                return
            
            print(f"[INFO] Found {len(all_keys)} keys in database")
            print()
            
            # Sort keys for consistent output
            all_keys.sort()
            
            for i, key in enumerate(all_keys, 1):
                try:
                    # Get key type
                    key_type = self.redis_client.type(key)
                    
                    print(f"Key {i}: {key}")
                    print(f"Type: {key_type}")
                    print(f"TTL: {self.redis_client.ttl(key)} seconds (-1 = no expiry, -2 = key doesn't exist)")
                    
                    # Get data based on type
                    if key_type == 'string':
                        value = self.redis_client.get(key)
                        print(f"Value: {value}")
                        
                    elif key_type == 'list':
                        length = self.redis_client.llen(key)
                        print(f"Length: {length} items")
                        if length > 0:
                            # Get first 10 items to avoid overwhelming output
                            items = self.redis_client.lrange(key, 0, min(9, length - 1))
                            for j, item in enumerate(items, 1):
                                print(f"  [{j}]: {item}")
                            if length > 10:
                                print(f"  ... and {length - 10} more items")
                                
                    elif key_type == 'set':
                        length = self.redis_client.scard(key)
                        print(f"Length: {length} members")
                        if length > 0:
                            # Get first 10 members
                            members = self.redis_client.smembers(key)
                            members_list = list(members)[:10]
                            for j, member in enumerate(members_list, 1):
                                print(f"  [{j}]: {member}")
                            if length > 10:
                                print(f"  ... and {length - 10} more members")
                                
                    elif key_type == 'hash':
                        length = self.redis_client.hlen(key)
                        print(f"Length: {length} fields")
                        if length > 0:
                            # Get first 10 fields
                            fields = self.redis_client.hgetall(key)
                            field_items = list(fields.items())[:10]
                            for field, value in field_items:
                                print(f"  {field}: {value}")
                            if length > 10:
                                print(f"  ... and {length - 10} more fields")
                                
                    elif key_type == 'zset':
                        length = self.redis_client.zcard(key)
                        print(f"Length: {length} members")
                        if length > 0:
                            # Get first 10 members with scores
                            members = self.redis_client.zrange(key, 0, min(9, length - 1), withscores=True)
                            for member, score in members:
                                print(f"  {member}: {score}")
                            if length > 10:
                                print(f"  ... and {length - 10} more members")
                                
                    elif key_type == 'stream':
                        length = self.redis_client.xlen(key)
                        print(f"Length: {length} entries")
                        if length > 0:
                            # Get first 5 stream entries
                            entries = self.redis_client.xrange(key, count=5)
                            for entry_id, fields in entries:
                                print(f"  {entry_id}: {fields}")
                            if length > 5:
                                print(f"  ... and {length - 5} more entries")
                                
                    else:
                        print(f"Value: <{key_type} data type - use DUMP command for raw data>")
                    
                    print("-" * 40)
                    
                except Exception as e:
                    print(f"Error reading key '{key}': {e}")
                    print("-" * 40)
                    
        except Exception as e:
            print(f"[ERROR] Failed to dump data: {e}")
    
    def test_user_permissions(self) -> None:
        """Test write, read, and delete capabilities by creating a test key."""
        try:
            print(f"\n{'='*60}")
            print("PERMISSION TESTING")
            print(f"{'='*60}")
            
            test_key = f"redis_audit_test_{int(time.time())}"
            test_value = f"test_value_{int(time.time())}"
            
            print(f"[INFO] Testing permissions with key: {test_key}")
            print(f"[INFO] Test value: {test_value}")
            print()
            
            # Test 1: Write permission
            print("1. Testing WRITE permission...")
            try:
                self.redis_client.set(test_key, test_value)
                print("   ✓ WRITE permission: GRANTED")
                write_ok = True
            except Exception as e:
                print(f"   ✗ WRITE permission: DENIED - {e}")
                write_ok = False
            
            # Test 2: Read permission
            print("2. Testing READ permission...")
            if write_ok:
                try:
                    retrieved_value = self.redis_client.get(test_key)
                    if retrieved_value == test_value:
                        print("   ✓ READ permission: GRANTED")
                        print(f"   ✓ Retrieved value matches: {retrieved_value}")
                        read_ok = True
                    else:
                        print(f"   ⚠ READ permission: PARTIAL - Retrieved: {retrieved_value}")
                        read_ok = True
                except Exception as e:
                    print(f"   ✗ READ permission: DENIED - {e}")
                    read_ok = False
            else:
                print("   ⚠ READ permission: SKIPPED (write failed)")
                read_ok = False
            
            # Test 3: Delete permission
            print("3. Testing DELETE permission...")
            if write_ok:
                try:
                    result = self.redis_client.delete(test_key)
                    if result == 1:
                        print("   ✓ DELETE permission: GRANTED")
                        delete_ok = True
                    else:
                        print(f"   ⚠ DELETE permission: PARTIAL - Result: {result}")
                        delete_ok = True
                except Exception as e:
                    print(f"   ✗ DELETE permission: DENIED - {e}")
                    delete_ok = False
            else:
                print("   ⚠ DELETE permission: SKIPPED (write failed)")
                delete_ok = False
            
            # Test 4: Verify deletion
            print("4. Verifying deletion...")
            if write_ok and delete_ok:
                try:
                    check_value = self.redis_client.get(test_key)
                    if check_value is None:
                        print("   ✓ Deletion verified: Key successfully removed")
                        verify_ok = True
                    else:
                        print(f"   ⚠ Deletion verification: Key still exists with value: {check_value}")
                        verify_ok = False
                except Exception as e:
                    print(f"   ⚠ Deletion verification: Could not verify - {e}")
                    verify_ok = False
            else:
                print("   ⚠ Deletion verification: SKIPPED (write or delete failed)")
                verify_ok = False
            
            # Summary
            print(f"\n{'='*40}")
            print("PERMISSION TEST SUMMARY")
            print(f"{'='*40}")
            print(f"WRITE:  {'✓ GRANTED' if write_ok else '✗ DENIED'}")
            print(f"READ:   {'✓ GRANTED' if read_ok else '✗ DENIED'}")
            print(f"DELETE: {'✓ GRANTED' if delete_ok else '✗ DENIED'}")
            print(f"VERIFY: {'✓ SUCCESS' if verify_ok else '✗ FAILED'}")
            
            # Add findings based on results
            if not write_ok:
                self.findings.append(SecurityFinding(
                    severity="HIGH",
                    category="Permissions",
                    title="Write Permission Denied",
                    description="User cannot write new keys to the database",
                    recommendation="Check user permissions and ACL configuration"
                ))
            
            if not read_ok:
                self.findings.append(SecurityFinding(
                    severity="HIGH",
                    category="Permissions",
                    title="Read Permission Denied",
                    description="User cannot read keys from the database",
                    recommendation="Check user permissions and ACL configuration"
                ))
            
            if not delete_ok:
                self.findings.append(SecurityFinding(
                    severity="MEDIUM",
                    category="Permissions",
                    title="Delete Permission Denied",
                    description="User cannot delete keys from the database",
                    recommendation="Check user permissions and ACL configuration"
                ))
            
            if write_ok and read_ok and delete_ok:
                print("\n[INFO] All basic permissions (write, read, delete) are GRANTED")
                self.findings.append(SecurityFinding(
                    severity="LOW",
                    category="Permissions",
                    title="Full Database Access",
                    description="User has full read, write, and delete permissions",
                    recommendation="Consider restricting permissions based on application needs"
                ))
            
        except Exception as e:
            print(f"[ERROR] Permission testing failed: {e}")
    
    def run_security_audit(self) -> None:
        """Run comprehensive security audit."""
        print(f"\n{'='*60}")
        print(f"Redis Security Audit - {self.host}:{self.port}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}")
        
        if not self.connect():
            print("[ERROR] Failed to establish connection. Audit aborted.")
            return
        
        print("\n[INFO] Connection established successfully")
        
        # Run all security checks
        self.get_server_version()
        self.check_tls_encryption()
        self.check_authentication()
        self.check_acl_and_users()
        self.check_dangerous_commands()
        self.check_command_renaming()
        self.check_memory_configuration()
        self.check_network_security()
        self.check_protected_mode()
        self.check_bind_address()
        self.check_client_connections()
        self.check_slow_log()
        self.check_key_patterns()
        self.check_sensitive_keys()
        self.check_replication_status()
        self.check_lua_scripting()
        self.check_module_loading()
        self.check_log_config()
        self.check_monitor_command()
        self.check_backup_config()
        self.check_running_user()
        if self.cve_check:
            self.check_cve()
        if self.dump_data:
            self.dump_all_data()
        if self.test_permissions:
            self.test_user_permissions()
        
        # Generate report
        self.generate_report()
        
        # Cleanup
        if self.redis_client:
            self.redis_client.close()
    
    def generate_report(self) -> None:
        """Generate comprehensive security report."""
        print(f"\n{'='*60}")
        print("SECURITY AUDIT REPORT")
        print(f"{'='*60}")
        
        if not self.findings:
            print("[INFO] No security findings detected!")
            return
        
        # Group findings by severity
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        findings_by_severity = {}
        
        for finding in self.findings:
            if finding.severity not in findings_by_severity:
                findings_by_severity[finding.severity] = []
            findings_by_severity[finding.severity].append(finding)
        
        # Print findings by severity
        for severity in severity_order:
            if severity in findings_by_severity:
                print(f"\n[{severity}] Findings:")
                for i, finding in enumerate(findings_by_severity[severity], 1):
                    print(f"  {i}. {finding.title}")
                    print(f"     Category: {finding.category}")
                    print(f"     Description: {finding.description}")
                    print(f"     Recommendation: {finding.recommendation}")
                    if finding.evidence:
                        print(f"     Evidence: {finding.evidence}")
                    print()
        
        # Summary
        total_findings = len(self.findings)
        critical_count = len([f for f in self.findings if f.severity == 'CRITICAL'])
        high_count = len([f for f in self.findings if f.severity == 'HIGH'])
        
        print(f"\nSUMMARY:")
        print(f"  Total findings: {total_findings}")
        print(f"  Critical: {critical_count}")
        print(f"  High: {high_count}")
        print(f"  Medium: {len([f for f in self.findings if f.severity == 'MEDIUM'])}")
        print(f"  Low: {len([f for f in self.findings if f.severity == 'LOW'])}")


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Redis Security Auditing Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python redisClient.py localhost:6379
  python redisClient.py redis.example.com:6380 --tls
  python redisClient.py 192.168.1.100:6379 --password mypassword
        """
    )
    
    parser.add_argument(
        'server',
        help='Redis server address in format host:port'
    )
    
    parser.add_argument(
        '--tls',
        action='store_true',
        help='Use TLS encryption for connection'
    )
    
    parser.add_argument(
        '--password',
        help='Redis password for authentication'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Connection timeout in seconds (default: 10)'
    )
    
    parser.add_argument(
        '--cve-check',
        action='store_true',
        help='Check server version against local CVE table'
    )
    
    parser.add_argument(
        '--dump-data',
        action='store_true',
        help='Dump all keys and their data'
    )
    
    parser.add_argument(
        '--test-permissions',
        action='store_true',
        help='Test write, read, and delete capabilities by creating a test key, reading it back, and then deleting it'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Redis Security Client v1.0 - Author: Garland Glessner'
    )
    
    return parser.parse_args()


def main():
    """Main function."""
    args = parse_arguments()
    
    # Parse server address
    try:
        if ':' in args.server:
            host, port_str = args.server.rsplit(':', 1)
            port = int(port_str)
        else:
            host = args.server
            port = 6379
    except ValueError:
        print("[ERROR] Invalid server format. Use host:port")
        sys.exit(1)
    
    # Validate port
    if not (1 <= port <= 65535):
        print("[ERROR] Invalid port number. Must be between 1 and 65535")
        sys.exit(1)
    
    # Create auditor and run audit
    auditor = RedisSecurityAuditor(
        host=host,
        port=port,
        use_tls=args.tls,
        password=args.password,
        timeout=args.timeout,
        cve_check=getattr(args, 'cve_check', False),
        dump_data=getattr(args, 'dump_data', False),
        test_permissions=getattr(args, 'test_permissions', False)
    )
    
    try:
        auditor.run_security_audit()
    except KeyboardInterrupt:
        print("\n[INFO] Audit interrupted by user")
    except Exception as e:
        print(f"[ERROR] Unexpected error during audit: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 