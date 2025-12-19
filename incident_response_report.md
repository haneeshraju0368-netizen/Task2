# SOC Incident Response Report

## Incident Summary
Date of Incident: October 1, 2023  
Reported By: SOC Analyst (Simulation)  
Incident ID: SOC-2023-001  

## Threat Description
Multiple security alerts were detected indicating potential cyber threats including brute force attacks, malware infection attempts, and suspicious network activity.

## Key Findings from Log Analysis

### 1. Brute Force Attack on Admin Account
- **Severity**: High
- **Details**: Multiple failed login attempts for user 'admin' from IP 10.0.0.5 between 08:10-08:20
- **Evidence**: 
  - Auth logs: 3 consecutive failures, account locked
  - Network logs: SSH connections (port 22) denied from 10.0.0.5
  - System logs: Failed login warnings
- **Impact**: Potential unauthorized access attempt

### 2. Malware Detection
- **Severity**: Critical
- **Details**: Trojan.Ransomware detected in downloads folder
- **Evidence**: 
  - Malware alert: file=/home/user/downloads/malware.exe from 203.0.113.1
  - Network logs: Blocked ICMP from 203.0.113.1
  - System logs: Unusual traffic warning from 203.0.113.1
- **Impact**: Risk of data encryption and ransomware deployment

### 3. Suspicious Process Execution
- **Severity**: High
- **Details**: Encoded PowerShell command executed from IP 10.0.0.5
- **Evidence**: Malware alert at 10:15 showing suspicious process
- **Impact**: Potential command and control or lateral movement

### 4. Phishing Attempt
- **Severity**: Medium
- **Details**: Phishing email blocked from malicious@bad.com
- **Evidence**: Malware alert at 11:00
- **Impact**: User protection, no delivery

### 5. Unusual Outbound Traffic
- **Severity**: Medium
- **Details**: Suspicious outbound connection to 185.199.108.153:443
- **Evidence**: Malware alert at 12:00
- **Impact**: Potential data exfiltration

### 6. Additional Failed Authentication Attempts
- **Severity**: Low-Medium
- **Details**: Failed logins from external IPs (203.0.113.1, 198.51.100.1)
- **Evidence**: Auth logs showing unknown user and invalid password attempts
- **Impact**: Probing/scanning activity

## Impact Assessment
- **Confidentiality**: Potential exposure of admin credentials
- **Integrity**: Malware could encrypt data
- **Availability**: Account lockout affects admin access
- **Overall Risk**: High - combination of brute force and malware indicates coordinated attack

## Recommended Actions
1. **Immediate Response**:
   - Block IP 10.0.0.5 and 203.0.113.1 at firewall
   - Quarantine affected systems
   - Change admin password and review other privileged accounts

2. **Investigation**:
   - Analyze malware sample in sandbox
   - Review user download history
   - Check for other compromised accounts

3. **Prevention**:
   - Implement multi-factor authentication
   - Update antivirus signatures
   - Enable account lockout policies
   - Train users on phishing awareness

4. **Monitoring**:
   - Increase log retention
   - Set up alerts for similar patterns
   - Monitor for data exfiltration

## Communication Plan
- **Internal Stakeholders**: IT Security Team, System Administrators
- **Management**: CISO, Department Heads
- **External**: If applicable, law enforcement for cybercrime reporting

## Timeline
- 08:10-08:20: Brute force attempts
- 09:30: Malware download
- 10:15: Suspicious process
- 11:00: Phishing block
- 12:00: Unusual traffic

## Conclusion
This incident demonstrates a multi-vector attack combining brute force, malware, and social engineering. Early detection through log monitoring prevented potential compromise. Enhanced security controls recommended.