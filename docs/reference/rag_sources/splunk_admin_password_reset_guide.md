# Splunk Admin Password Reset and Recovery Guide

---
tags: [splunk, admin, password, reset, recovery, user-seed, authentication, security]
category: administration
last_updated: 2026-02-20
related_docs: [splunk_tls_certificate_guide.md, admin_props_transforms.md]
---

## Overview

This guide covers methods to reset, recover, or create Splunk Enterprise administrator credentials when:
- You've forgotten or lost the admin password
- Initial installation didn't create admin credentials
- Automating deployments requiring pre-configured credentials

**Important:** All methods require physical/shell access to the Splunk server. You cannot reset passwords remotely through the web interface if you're locked out.

---

## Method 1: Reset Password Using REST API (Recommended for Lost Password)

**Best for:** Recovering access when you've forgotten the admin password

**Requirements:** Shell access to Splunk server, ability to write to `$SPLUNK_HOME/etc/passwd`

### Steps:

```bash
# Stop Splunk first (optional but recommended)
$SPLUNK_HOME/bin/splunk stop

# Reset the admin password
$SPLUNK_HOME/bin/splunk cmd splunkd rest --noauth POST /services/admin/users/admin "password=<your_new_password>"

# Start Splunk
$SPLUNK_HOME/bin/splunk start
```

**Security Note:** Delete your command line history immediately after running this command to prevent password exposure:
```bash
history -c  # Clear bash history
# Or remove specific line from ~/.bash_history
```

---

## Method 2: Using user-seed.conf File (Most Secure)

**Best for:** Initial installation, automated deployments, and password resets

**Requirements:** Shell access, ability to create/edit configuration files

### Option A: Using Hashed Password (Recommended)

1. **Generate a password hash:**
```bash
$SPLUNK_HOME/bin/splunk hash-passwd <your_password>
# Output: $6$hf3syG/qxy6REoBp...
```

2. **Create or edit the user-seed.conf file:**
```bash
vi $SPLUNK_HOME/etc/system/local/user-seed.conf
```

3. **Add the following content:**
```ini
[user_info]
USERNAME = admin
HASHED_PASSWORD = $6$hf3syG/qxy6REoBp...
```

4. **Delete the existing passwd file (if it exists):**
```bash
rm $SPLUNK_HOME/etc/passwd
```

5. **Restart Splunk:**
```bash
$SPLUNK_HOME/bin/splunk restart
```

### Option B: Using Plain Text Password (Less Secure)

```ini
[user_info]
USERNAME = admin
PASSWORD = your_password_here
```

**Note:** Plain text passwords are converted to hashes on first startup.

---

## Method 3: CLI Arguments During Startup

**Best for:** Fresh installations, scripted deployments

### Seed with Specific Password:
```bash
$SPLUNK_HOME/bin/splunk start --accept-license --answer-yes --no-prompt --seed-passwd <your_password>
```

### Generate Random Password:
```bash
$SPLUNK_HOME/bin/splunk start --accept-license --answer-yes --no-prompt --gen-and-print-passwd
```
This prints a randomly generated password to stdout - **save it immediately!**

---

## Method 4: Delete passwd File and Re-seed

**Best for:** Complete credential reset

### Steps:

1. **Stop Splunk:**
```bash
$SPLUNK_HOME/bin/splunk stop
```

2. **Delete the passwd file:**
```bash
rm $SPLUNK_HOME/etc/passwd
```

3. **Create user-seed.conf with new credentials:**
```bash
cat > $SPLUNK_HOME/etc/system/local/user-seed.conf << 'EOF'
[user_info]
USERNAME = admin
PASSWORD = NewSecurePassword123!
EOF
```

4. **Start Splunk:**
```bash
$SPLUNK_HOME/bin/splunk start
```

Splunk reads `user-seed.conf` only when `$SPLUNK_HOME/etc/passwd` does not exist.

---

## Password Validation

Validate that a password meets Splunk complexity requirements before setting it:

```bash
$SPLUNK_HOME/bin/splunk validate-passwd <your_password>

# Or from stdin:
echo "MyPassword123!" | $SPLUNK_HOME/bin/splunk validate-passwd -
```

**Default Password Requirements:**
- Minimum 8 printable ASCII characters
- Additional requirements may be configured in `authentication.conf`

---

## Key Files Reference

| File | Location | Purpose |
|------|----------|---------|
| `passwd` | `$SPLUNK_HOME/etc/passwd` | Stores user credentials (hashed) |
| `user-seed.conf` | `$SPLUNK_HOME/etc/system/local/user-seed.conf` | Seeds initial admin credentials |
| `authentication.conf` | `$SPLUNK_HOME/etc/system/local/authentication.conf` | Password policies and auth settings |

---

## user-seed.conf Specification

```ini
[user_info]
# Username for the admin account (default: admin)
USERNAME = admin

# Plain text password (converted to hash on first startup)
PASSWORD = <password>

# OR use pre-hashed password (more secure for distribution)
HASHED_PASSWORD = <password_hash>
```

**Important Notes:**
- `user-seed.conf` is only read when `$SPLUNK_HOME/etc/passwd` does NOT exist
- If both `PASSWORD` and `HASHED_PASSWORD` are set, `HASHED_PASSWORD` takes precedence
- Password file is created/seeded on first Splunk startup
- If the last character of a clear text password is `\`, add a trailing space

---

## Automated Deployment Example

For deploying Splunk to multiple servers with pre-configured credentials:

### Step 1: Generate Hash on Source System
```bash
splunk hash-passwd 'MySecureDeploymentPassword!'
# Output: $6$TOs.jXjSRTCsfPsw$2St.t9lH9fpXd9mCEmCizWbb67gMFfBIJU37QF8wsHKSGud1QNMCuUdWkD8IFSgCZr5.W6zkjmNACGhGafQZj1
```

### Step 2: Create Distributable user-seed.conf
```ini
[user_info]
USERNAME = admin
HASHED_PASSWORD = $6$TOs.jXjSRTCsfPsw$2St.t9lH9fpXd9mCEmCizWbb67gMFfBIJU37QF8wsHKSGud1QNMCuUdWkD8IFSgCZr5.W6zkjmNACGhGafQZj1
```

### Step 3: Include in Deployment Package
Place `user-seed.conf` in `$SPLUNK_HOME/etc/system/local/` before first startup.

---

## Troubleshooting

### Problem: user-seed.conf Not Being Read
**Cause:** `$SPLUNK_HOME/etc/passwd` already exists
**Solution:** Delete the passwd file and restart Splunk

### Problem: Password Doesn't Meet Complexity Requirements
**Solution:** Check requirements with `splunk validate-passwd` and adjust password

### Problem: "Password did not meet complexity requirements"
**Solution:** Ensure password has:
- At least 8 printable ASCII characters
- Check `authentication.conf` for additional requirements:
```ini
[splunk_auth]
minPasswordLength = 8
minPasswordUppercase = 0
minPasswordLowercase = 0
minPasswordDigit = 0
minPasswordSpecial = 0
```

### Problem: CLI History Exposes Password
**Solution:** 
```bash
# Clear entire history
history -c
history -w

# Or use heredoc/stdin to avoid history
cat << 'EOF' | splunk cmd splunkd rest --noauth POST /services/admin/users/admin
password=YourNewPassword
EOF
```

---

## Security Best Practices

1. **Use Hashed Passwords:** Always use `HASHED_PASSWORD` over `PASSWORD` in user-seed.conf
2. **Clear Command History:** Delete history after using CLI password commands
3. **Secure File Permissions:**
   ```bash
   chmod 600 $SPLUNK_HOME/etc/system/local/user-seed.conf
   chown splunk:splunk $SPLUNK_HOME/etc/system/local/user-seed.conf
   ```
4. **Remove user-seed.conf After Use:** Once credentials are seeded, consider removing the file
5. **Use Strong Passwords:** Follow organizational password policies
6. **Rotate Credentials:** Change admin password periodically

---

## Quick Reference Commands

| Task | Command |
|------|---------|
| Hash a password | `splunk hash-passwd <password>` |
| Validate password | `splunk validate-passwd <password>` |
| Reset password (REST) | `splunk cmd splunkd rest --noauth POST /services/admin/users/admin "password=<new>"` |
| Start with new password | `splunk start --seed-passwd <password>` |
| Generate random password | `splunk start --gen-and-print-passwd` |
| Delete passwd file | `rm $SPLUNK_HOME/etc/passwd` |

---

## References

- [Create Secure Administrator Credentials](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.2/install-splunk-enterprise-securely/create-secure-administrator-credentials)
- [user-seed.conf Configuration File](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/configuration-file-reference/10.2.0-configuration-file-reference/user-seed.conf)
- [Manage Splunk Platform Users and Roles](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.2/manage-splunk-platform-users-and-roles)

---

*Last Updated: February 2026*
*Source: Splunk Enterprise 10.2 Documentation*
