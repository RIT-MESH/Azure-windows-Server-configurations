# Azure-windows-Server-configurations

# Comprehensive Windows Server Administration Guide

## Table of Contents
1. [Introduction to Windows Server](#introduction-to-windows-server)
2. [Installation and Initial Configuration](#installation-and-initial-configuration)
3. [Secure Windows Server Operating System](#secure-windows-server-operating-system)
4. [Secure a Hybrid Active Directory (AD) Infrastructure](#secure-a-hybrid-active-directory-ad-infrastructure)
5. [Identify and Remediate Windows Server Security Issues using Azure Services](#identify-and-remediate-windows-server-security-issues-using-azure-services)
6. [Secure Windows Server Networking](#secure-windows-server-networking)
7. [Secure Windows Server Storage](#secure-windows-server-storage)
8. [Implement a Windows Server Failover Cluster](#implement-a-windows-server-failover-cluster)
9. [Manage Failover Clustering](#manage-failover-clustering)
10. [Implement and Manage Storage Spaces Direct](#implement-and-manage-storage-spaces-direct)
11. [Manage Backup and Recovery for Windows Server](#manage-backup-and-recovery-for-windows-server)
12. [Implement Disaster Recovery using Azure Site Recovery](#implement-disaster-recovery-using-azure-site-recovery)
13. [Protect Virtual Machines using Hyper-V Replicas](#protect-virtual-machines-using-hyper-v-replicas)
14. [Migrate On-Premises Storage to On-Premises Servers or Azure](#migrate-on-premises-storage-to-on-premises-servers-or-azure)
15. [Migrate On-Premises Servers to Azure](#migrate-on-premises-servers-to-azure)
16. [Migrate Workloads from Previous Versions to Server 2022](#migrate-workloads-from-previous-versions-to-server-2022)
17. [Monitor Windows Server using Windows Server Tools and Azure Services](#monitor-windows-server-using-windows-server-tools-and-azure-services)
18. [Windows Server Roles and Features](#windows-server-roles-and-features)
19. [Group Policy Management](#group-policy-management)
20. [Windows Server Update Services (WSUS)](#windows-server-update-services-wsus)
21. [Remote Desktop Services](#remote-desktop-services)
22. [Windows Server Containers and Docker](#windows-server-containers-and-docker)
23. [Windows Admin Center](#windows-admin-center)
24. [PowerShell Automation for Windows Server](#powershell-automation-for-windows-server)

---

## Introduction to Windows Server

### Windows Server Editions
- **Windows Server 2022 Datacenter**: For highly virtualized datacenter and cloud environments
- **Windows Server 2022 Standard**: For physical or minimally virtualized environments
- **Windows Server 2022 Essentials**: For small businesses with up to 25 users and 50 devices

### System Requirements
- **Processor**: 1.4 GHz 64-bit processor
- **RAM**: 512 MB minimum, 2 GB for Server with Desktop Experience
- **Disk Space**: 32 GB minimum
- **Network**: Ethernet adapter capable of at least gigabit throughput
- **Internet**: Internet connectivity for updates

### Deployment Options
- Physical server
- Virtual machine
- Cloud (Azure)
- Containers

---

## Installation and Initial Configuration

### Installation Steps
1. **Boot from Installation Media**
   - Insert the media and restart the computer
   - Press any key when prompted to boot from DVD/USB

2. **Windows Setup**
   - Select language, time and currency format, keyboard
   - Click "Next" and then "Install now"

3. **Enter Product Key**
   - Enter your product key or select "I don't have a product key" to continue without activation

4. **Select Installation Option**
   - Choose between "Windows Server Standard/Datacenter (Desktop Experience)" or "Core"

5. **Accept License Terms**
   - Read and accept the license terms

6. **Choose Installation Type**
   - For a new server: "Custom: Install Windows only (advanced)"

7. **Select Disk**
   - Choose where to install Windows Server
   - Create partitions if needed

8. **Complete Installation**
   - Windows Server will install and restart

### Initial Configuration
1. **Set Administrator Password**
   ```
   <Password must meet complexity requirements>
   ```

2. **Configure Network Settings**
   ```powershell
   # Get network adapters
   Get-NetAdapter
   
   # Configure static IP address
   New-NetIPAddress -InterfaceIndex <index> -IPAddress 192.168.1.10 -PrefixLength 24 -DefaultGateway 192.168.1.1
   
   # Configure DNS servers
   Set-DnsClientServerAddress -InterfaceIndex <index> -ServerAddresses 192.168.1.2,8.8.8.8
   ```

3. **Rename Computer**
   ```powershell
   # Rename computer
   Rename-Computer -NewName "Server01" -Restart
   ```

4. **Join Domain (if applicable)**
   ```powershell
   # Join a domain
   Add-Computer -DomainName "contoso.com" -Credential (Get-Credential) -Restart
   ```

---

## Secure Windows Server Operating System

### Security Baselines
1. **Update Windows Server**
   ```powershell
   # Using sconfig (menu-driven)
   sconfig
   
   # Using PowerShell
   Install-Module PSWindowsUpdate
   Get-WindowsUpdate
   Install-WindowsUpdate -AcceptAll
   ```

2. **Enable Windows Defender Firewall**
   ```powershell
   # Enable all profiles
   Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
   
   # Check status
   Get-NetFirewallProfile | Select-Object Name, Enabled
   ```

3. **Configure User Account Control (UAC)**
   - Open `Local Security Policy` → Security Options → User Account Control
   - Or use PowerShell:
   ```powershell
   # Set UAC to highest level
   Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2
   ```

4. **Enable Windows Defender Antivirus**
   ```powershell
   # Enable real-time protection
   Set-MpPreference -DisableRealtimeMonitoring $false
   
   # Run a quick scan
   Start-MpScan -ScanType QuickScan
   ```

5. **Apply Security Policies**
   ```powershell
   # Import security templates
   Secedit /configure /db secedit.sdb /cfg C:\Templates\SecurityTemplate.inf
   ```

6. **Enable Credential Guard**
   ```powershell
   # Enable Credential Guard
   Enable-WindowsOptionalFeature -Online -FeatureName DeviceGuard
   ```

7. **Configure Windows Defender Application Control**
   ```powershell
   # Create and deploy AppLocker policies
   New-AppLockerPolicy -XmlPolicy C:\Policies\AppLockerPolicy.xml
   ```

### Password Policies
1. **Configure Password Complexity**
   ```powershell
   # Set minimum password length to 14 characters
   Set-ADDefaultDomainPasswordPolicy -Identity contoso.com -MinPasswordLength 14
   
   # Enable password complexity
   Set-ADDefaultDomainPasswordPolicy -Identity contoso.com -ComplexityEnabled $true
   
   # Set password history to 24
   Set-ADDefaultDomainPasswordPolicy -Identity contoso.com -PasswordHistoryCount 24
   ```

2. **Set Account Lockout Policies**
   ```powershell
   # Set account lockout threshold
   Set-ADDefaultDomainPasswordPolicy -Identity contoso.com -LockoutThreshold 5
   
   # Set account lockout duration (minutes)
   Set-ADDefaultDomainPasswordPolicy -Identity contoso.com -LockoutDuration 00:30:00
   
   # Set account lockout observation window (minutes)
   Set-ADDefaultDomainPasswordPolicy -Identity contoso.com -LockoutObservationWindow 00:30:00
   ```

3. **Enable Multi-Factor Authentication**
   - Configure Azure MFA for hybrid environments
   - Deploy smart cards or other physical tokens

### Audit Policies
1. **Configure Audit Policies**
   ```powershell
   # Enable audit policies
   auditpol /set /category:"Account Logon" /success:enable /failure:enable
   auditpol /set /category:"Account Management" /success:enable /failure:enable
   auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
   auditpol /set /category:"DS Access" /success:enable /failure:enable
   auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
   auditpol /set /category:"Object Access" /success:enable /failure:enable
   auditpol /set /category:"Policy Change" /success:enable /failure:enable
   auditpol /set /category:"Privilege Use" /success:enable /failure:enable
   auditpol /set /category:"System" /success:enable /failure:enable
   ```

2. **Review Audit Logs**
   ```powershell
   # Get security events
   Get-EventLog -LogName Security -Newest 50
   ```

---

## Secure a Hybrid Active Directory (AD) Infrastructure

### Prepare for Hybrid Identity
1. **Assess Current AD Environment**
   ```powershell
   # Check Domain Functional Level
   Get-ADDomain | Select-Object DomainMode
   
   # Check Forest Functional Level
   Get-ADForest | Select-Object ForestMode
   ```

2. **Clean Up AD Environment**
   ```powershell
   # Find inactive users
   Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00
   
   # Find and disable inactive computer accounts
   Get-ADComputer -Filter {LastLogonTimeStamp -lt $time -and Enabled -eq $true} -Properties LastLogonTimeStamp
   ```

### Install Azure AD Connect
1. **Prerequisites**
   - .NET Framework 4.5.1+
   - PowerShell 3.0+
   - Microsoft Azure AD Module
   - SQL Server 2012+ (Express or full version)

2. **Download and Install Azure AD Connect**
   ```
   # Download from Microsoft's site and run the installer
   AzureADConnect.msi
   ```

3. **Run the Azure AD Connect Wizard**
   - Choose "Express Settings" for typical scenarios
   - Choose "Customize" for advanced options including:
     - Alternate login ID
     - Group filtering
     - Password writeback
     - Device writeback

4. **Enable Password Hash Synchronization**
   ```powershell
   # Verify synchronization is enabled
   Get-ADSyncScheduler
   
   # Enable synchronization if disabled
   Set-ADSyncScheduler -SyncCycleEnabled $true
   ```

5. **Test Sync with Azure AD**
   ```powershell
   # Run a delta sync
   Start-ADSyncSyncCycle -PolicyType Delta
   
   # Run a full sync
   Start-ADSyncSyncCycle -PolicyType Initial
   ```

### Secure Active Directory
1. **Implement Tiered Administration Model**
   - Tier 0: Domain Controllers, Domain Admins
   - Tier 1: Server Administrators
   - Tier 2: Workstation Administrators

2. **Implement Privileged Access Management**
   ```powershell
   # Enable Privileged Access Management
   Enable-ADOptionalFeature 'Privileged Access Management Feature' -Scope ForestOrConfigurationSet -Target contoso.com
   ```

3. **Implement Administrative Forest Design**
   - Create separate administrative forest for privileged accounts
   - Set up one-way trust relationship

4. **Secure Domain Controllers**
   ```powershell
   # Verify secure boot is enabled on DCs
   Confirm-SecureBootUEFI
   
   # Check DC security settings
   Get-ADDomainController -Filter * | Select-Object Name, OperatingSystem
   ```

5. **Enable Protected Users Security Group**
   ```powershell
   # Add users to Protected Users group
   Add-ADGroupMember -Identity 'Protected Users' -Members User1,User2
   ```

6. **Implement Microsoft Defender for Identity**
   - Deploy sensors on Domain Controllers
   - Connect to Microsoft 365 Defender portal

---

## Identify and Remediate Windows Server Security Issues using Azure Services

### Azure Security Center / Microsoft Defender for Cloud
1. **Enable Azure Security Center**
   - Navigate to Azure Portal
   - Select "Security Center" or "Microsoft Defender for Cloud"
   - Complete onboarding process

2. **Install Monitoring Agent**
   ```powershell
   # Download and install monitoring agent
   $MMASetupConfig = "$env:SystemDrive\MMASetup-AMD64.exe"
   Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?LinkId=828603" -OutFile $MMASetupConfig
   & $MMASetupConfig /qn NOAPM=1 ADD_OPINSIGHTS_WORKSPACE=1 OPINSIGHTS_WORKSPACE_AZURE_CLOUD_TYPE=0 OPINSIGHTS_WORKSPACE_ID="<workspaceID>" OPINSIGHTS_WORKSPACE_KEY="<workspaceKey>"
   ```

3. **Run a Security Assessment**
   - Review Secure Score in Azure Security Center
   - Check recommendations by resource type

4. **Review and Implement Security Recommendations**
   ```powershell
   # Get security recommendations using PowerShell
   Get-AzSecurityRecommendation | Select-Object Name, ResourceId, RecommendationType, Severity
   
   # Get detailed information about a specific recommendation
   Get-AzSecurityRecommendation -Name "<recommendation-name>" | Select-Object Name, Description, Severity, State, TimeGenerated
   ```

5. **Remediate Issues**
   ```powershell
   # Example: Enable JIT VM Access
   $resource = Get-AzResource -ResourceId "<resourceId>"
   Set-AzJitNetworkAccessPolicy -ResourceGroupName $resource.ResourceGroupName -Location $resource.Location -Name $resource.Name -VirtualMachine "<vmConfig>"
   ```

### Azure Sentinel
1. **Deploy Azure Sentinel**
   - Create or select Log Analytics workspace
   - Add Azure Sentinel to the workspace

2. **Connect Data Sources**
   - Connect Windows Security Events
   - Connect Azure Activity logs
   - Connect Microsoft 365 Defender

3. **Create Custom Detection Rules**
   ```
   # Example KQL query for detecting brute force attempts
   SecurityEvent
   | where EventID == 4625
   | where TimeGenerated > ago(1h)
   | summarize count() by TargetAccount, IpAddress, Computer
   | where count_ > 10
   ```

4. **Implement Automated Response**
   - Create automation rules
   - Set up playbooks with Logic Apps

---

## Secure Windows Server Networking

### Windows Defender Firewall
1. **Enable Windows Defender Firewall**
   ```powershell
   # Enable firewall for all profiles
   Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
   
   # Check firewall status
   Get-NetFirewallProfile | Select-Object Name, Enabled
   ```

2. **Configure Firewall Rules**
   ```powershell
   # Allow RDP traffic
   New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow
   
   # Block specific IP addresses
   New-NetFirewallRule -DisplayName "Block Malicious IPs" -Direction Inbound -RemoteAddress 192.168.1.100,10.0.0.1/24 -Action Block
   ```

3. **Create Rule Groups**
   ```powershell
   # Create a rule group
   New-NetFirewallRule -DisplayName "SQL Server Rules" -Group "Database" -Direction Inbound -Protocol TCP -LocalPort 1433 -Action Allow
   
   # Enable or disable group
   Get-NetFirewallRule -Group "Database" | Enable-NetFirewallRule
   ```

### IPsec
1. **Configure IPsec**
   ```powershell
   # Create IPsec rule for secure communication
   New-NetIPsecRule -DisplayName "Secure Communication" -InboundSecurity Require -OutboundSecurity Request
   ```

2. **Create Connection Security Rules**
   ```powershell
   # Create a server-to-server rule
   New-NetIPsecRule -DisplayName "Server to Server" -Mode TransportMode -Authentication RequireComputer
   ```

### Network Segmentation
1. **Implement VLANs**
   ```powershell
   # Configure VLAN ID on network adapter
   Set-NetAdapterAdvancedProperty -Name "Ethernet" -RegistryKeyword VlanID -RegistryValue 10
   ```

2. **Configure Routing**
   ```powershell
   # Add static route
   New-NetRoute -DestinationPrefix "10.0.0.0/24" -NextHop "192.168.1.1" -InterfaceIndex 12
   ```

### VPN and Remote Access
1. **Install Remote Access Role**
   ```powershell
   # Install Remote Access role
   Install-WindowsFeature RemoteAccess -IncludeManagementTools
   
   # Install DirectAccess and VPN
   Install-WindowsFeature DirectAccess-VPN -IncludeManagementTools
   ```

2. **Configure VPN Settings**
   ```powershell
   # Install VPN components
   Install-RemoteAccess -VpnType RoutingOnly
   
   # Configure VPN server
   Set-VpnServerConfiguration -AuthenticationMethod EAP -TunnelType Automatic
   ```

3. **Configure SSL Certificate**
   ```powershell
   # Assign certificate to VPN server
   Set-VpnServerIPsecConfiguration -CustomPolicy -AuthenticationTransformConstants SHA256128 -CipherTransformConstants AES128
   ```

### Web Application Proxy
1. **Install Web Application Proxy**
   ```powershell
   Install-WindowsFeature Web-Application-Proxy -IncludeManagementTools
   ```

2. **Configure Web Application Proxy**
   ```powershell
   Install-WebApplicationProxy -FederationServiceName "sts.contoso.com" -CertificateThumbprint "<cert-thumbprint>"
   ```

---

## Secure Windows Server Storage

### BitLocker Drive Encryption
1. **Prerequisites**
   ```powershell
   # Install BitLocker feature
   Install-WindowsFeature BitLocker -IncludeManagementTools
   ```

2. **Enable TPM**
   - Configure TPM in BIOS/UEFI
   
3. **Encrypt System Drive**
   ```powershell
   # Enable BitLocker on system drive
   Enable-BitLocker -MountPoint "C:" -EncryptionMethod AES256 -UsedSpaceOnly -TpmProtector
   ```

4. **Encrypt Data Drives**
   ```powershell
   # Enable BitLocker on data drive
   Enable-BitLocker -MountPoint "D:" -EncryptionMethod AES256 -UsedSpaceOnly -PasswordProtector
   ```

5. **Back Up Recovery Keys**
   ```powershell
   # Back up recovery key to AD
   Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $(Get-BitLockerVolume -MountPoint "C:").KeyProtector[0].KeyProtectorId
   ```

6. **Verify Encryption Status**
   ```powershell
   # Check encryption status
   Get-BitLockerVolume
   ```

### Encrypting File System (EFS)
1. **Enable EFS Certificate**
   ```powershell
   # Generate EFS certificate
   cipher /r:EFSCert
   ```

2. **Encrypt Files or Folders**
   ```powershell
   # Encrypt a folder
   cipher /e /s:C:\ConfidentialData
   ```

3. **Back Up EFS Certificates**
   ```powershell
   # Export EFS certificate
   certmgr.msc
   # Navigate to Personal -> Certificates -> Export
   ```

### File System Security
1. **Set NTFS Permissions**
   ```powershell
   # Grant permissions to a folder
   $acl = Get-Acl "C:\Data"
   $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("CONTOSO\Finance","Modify","Allow")
   $acl.SetAccessRule($AccessRule)
   $acl | Set-Acl "C:\Data"
   ```

2. **Configure Auditing**
   ```powershell
   # Enable auditing on a folder
   $acl = Get-Acl "C:\ConfidentialData"
   $AuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone","ReadData","Success")
   $acl.AddAuditRule($AuditRule)
   $acl | Set-Acl "C:\ConfidentialData"
   ```

3. **Implement File Screening**
   ```powershell
   # Install File Server Resource Manager
   Install-WindowsFeature -Name FS-Resource-Manager -IncludeManagementTools
   
   # Create file screen
   New-FsrmFileScreen -Path "D:\SharedFolder" -Template "Block Audio and Video Files"
   ```

### Storage Encryption for Cloud
1. **Azure Storage Service Encryption**
   ```powershell
   # Enable encryption for Azure Storage Account
   Set-AzStorageAccount -ResourceGroupName "RG1" -Name "storage1" -EnableEncryptionService "Blob" -KeyType "Service"
   ```

2. **Azure Disk Encryption**
   ```powershell
   # Enable Azure Disk Encryption
   Set-AzVMDiskEncryptionExtension -ResourceGroupName "RG1" -VMName "VM1" -DiskEncryptionKeyVaultUrl "https://mykeyvault.vault.azure.net/" -DiskEncryptionKeyVaultId "/subscriptions/{subscriptionId}/resourceGroups/RG1/providers/Microsoft.KeyVault/vaults/mykeyvault"
   ```

---

## Implement a Windows Server Failover Cluster

### Prerequisites
1. **Verify Hardware Compatibility**
   - Check supported hardware on Windows Server Catalog
   - Ensure shared storage is available (SAN, iSCSI, etc.)

2. **Network Configuration**
   ```powershell
   # Configure dedicated NICs for cluster communication
   Rename-NetAdapter -Name "Ethernet" -NewName "Public"
   Rename-NetAdapter -Name "Ethernet 2" -NewName "Cluster"
   
   # Configure static IP addresses for cluster network
   New-NetIPAddress -InterfaceAlias "Cluster" -IPAddress 192.168.10.1 -PrefixLength 24
   ```

### Install Failover Clustering
1. **Install Failover Clustering Feature**
   ```powershell
   # Install on all nodes
   Install-WindowsFeature -Name Failover-Clustering -IncludeManagementTools
   ```

2. **Run Cluster Validation**
   ```powershell
   # Test cluster configuration
   Test-Cluster -Node Server1,Server2,Server3
   ```

3. **Create a Cluster**
   ```powershell
   # Create new cluster with static IP
   New-Cluster -Name ClusterName -Node Server1,Server2,Server3 -StaticAddress 192.168.1.100
   ```

4. **Configure Quorum Settings**
   ```powershell
   # Set quorum to Node Majority with File Share Witness
   Set-ClusterQuorum -FileShareWitness "\\fileserver\witness"
   ```

### Configure Cluster Networks
1. **Set Network Priority**
   ```powershell
   # Set cluster network priority
   (Get-ClusterNetwork -Name "Cluster").Metric = 100
   (Get-ClusterNetwork -Name "Public").Metric = 1000
   ```

2. **Configure Cluster Network Roles**
   ```powershell
   # Set network roles
   (Get-ClusterNetwork -Name "Cluster").Role = 1  # Cluster communications only
   (Get-ClusterNetwork -Name "Public").Role = 3   # Client and cluster communications
   ```

3. **Configure Cluster IP Address Settings**
   ```powershell
   # Add additional cluster IP addresses
   Add-ClusterResource -Name "IP Address 192.168.2.100" -ResourceType "IP Address" -Group "Cluster Group"
   ```

### Configure Cluster Storage
1. **Add Shared Storage**
   ```powershell
   # Add disk to cluster
   Add-ClusterDisk -InputObject (Get-Disk -Number 1)
   ```

2. **Configure Cluster Shared Volumes (CSV)**
   ```powershell
   # Enable CSV
   Enable-ClusterSharedVolume -Name "Cluster Disk 1"
   ```

3. **Configure Storage QoS**
   ```powershell
   # Create Storage QoS policy
   New-StorageQosPolicy -Name "VDI" -MinimumIops 100 -MaximumIops 500
   ```

---

## Manage Failover Clustering

### Monitor Cluster Health
1. **Check Cluster Node Status**
   ```powershell
   # Get node status
   Get-ClusterNode
   
   # Get detailed node information
   Get-ClusterNode | Format-List *
   ```

2. **Check Cluster Resource Status**
   ```powershell
   # Get resource status
   Get-ClusterResource
   
   # Get detailed resource information
   Get-ClusterResource -Name "SQL Server" | Format-List *
   ```

3. **View Cluster Events**
   ```powershell
   # Get cluster events
   Get-ClusterLog -Destination C:\Logs
   ```

### Manage Cluster Resources
1. **Add a Resource to the Cluster**
   ```powershell
   # Add a file server resource
   Add-ClusterFileServerRole -Name "FileServer" -Storage "Cluster Disk 2" -StaticAddress 192.168.1.101
   ```

2. **Configure Resource Dependencies**
   ```powershell
   # Set resource dependency
   Set-ClusterResourceDependency -Resource "SQL Server" -Dependency "[Cluster Disk 3] AND [SQL IP Address]"
   ```

3. **Failover a Cluster Role**
   ```powershell
   # Move cluster group to another node
   Move-ClusterGroup -Name "SQL Server Group" -Node "Server2"
   ```

4. **Configure Preferred Owners**
   ```powershell
   # Set preferred owners
   Set-ClusterOwnerNode -Group "SQL Server Group" -Owners Server1,Server2
   ```

### Upgrade and Patch Clustering
1. **Apply Windows Updates**
   ```powershell
   # Drain node for maintenance
   Suspend-ClusterNode -Name "Server1" -Drain
   
   # Install updates
   Install-WindowsUpdate -AcceptAll
   
   # Resume node
   Resume-ClusterNode -Name "Server1"
   ```

2. **Upgrade Cluster Functional Level**
   ```powershell
   # Check current functional level
   Get-Cluster | Select ClusterFunctionalLevel
   
   # Update functional level
   Update-ClusterFunctionalLevel
   ```

3. **Add a Node to Existing Cluster**
   ```powershell
   # Add new node
   Add-ClusterNode -Name "Server4" -Cluster "ClusterName"
   ```

4. **Remove a Node from Cluster**
   ```powershell
   # Remove node
   Remove-ClusterNode -Name "Server3"
   ```

### Cluster-Aware Updating (CAU)
1. **Configure CAU**
   ```powershell
   # Install CAU features
   Install-WindowsFeature -Name RSAT-Clustering-PowerShell
   
   # Add CAU clustered role
   Add-CauClusterRole -ClusterName "ClusterName" -Force
   ```

2. **Run CAU Updates**
   ```powershell
   # Invoke CAU scanning
   Invoke-CauScan -ClusterName "ClusterName"
   
   # Invoke CAU run
   Invoke-CauRun -ClusterName "ClusterName"
   ```

3. **Schedule Automatic Updates**
   ```powershell
   # Create a scheduled task for CAU
   Add-CauClusterRole -ClusterName "ClusterName" -DaysOfWeek Sunday -StartTime "3:00 AM" -Force
   ```

---

## Implement and Manage Storage Spaces Direct

### Prerequisites
1. **Hardware Requirements**
   - Minimum of 2 servers (4+ recommended)
   - Each server needs:
     - CPU: 1.4 GHz 64-bit processor
     - RAM: 16GB minimum (32GB+ recommended)
     - Network: RDMA capable NICs
     - Storage: NVMe, SSD, HDD in tiered configuration

2. **Software Requirements**
   ```powershell
   # Install required features on all nodes
   Install-WindowsFeature -Name "Failover-Clustering", "Data-Center-Bridging", "RSAT-Clustering-PowerShell", "Hyper-V", "FS-FileServer"
   ```

3. **Network Configuration**
   ```powershell
   # Configure RDMA
   Enable-NetAdapterRDMA -Name "RDMA1", "RDMA2"
   
   # Configure QoS for SMB
   New-NetQosPolicy "SMB" -NetDirectPortMatchCondition 445 -PriorityValue8021Action 3
   ```

### Enable Storage Spaces Direct
1. **Create a Failover Cluster**
   ```powershell
   # Create cluster
   New-Cluster -Name "S2DCluster" -Node "Server1", "Server2", "Server3", "Server4" -NoStorage
   ```

2. **Enable Storage Spaces Direct**
   ```powershell
   # Enable S2D
   Enable-ClusterStorageSpacesDirect -CimSession "S2DCluster"
   ```

3. **Verify S2D Health**
   ```powershell
   # Check pool health
   Get-StoragePool -CimSession "S2DCluster" -FriendlyName "S2D*"
   
   # Check physical disk health
   Get-PhysicalDisk -CimSession "S2DCluster"
   ```

### Create and Manage Volumes
1. **Create a Virtual Disk**
   ```powershell
   # Create a three-way mirror virtual disk
   New-Volume -CimSession "S2DCluster" -StoragePoolFriendlyName "S2D*" -FriendlyName "Volume1" -FileSystem CSVFS_ReFS -Size 1TB -ResiliencySettingName Mirror
   ```

2. **Create a Volume with Storage Tiers**
   ```powershell
   # Create volume with auto-tiering
   New-Volume -CimSession "S2DCluster" -StoragePoolFriendlyName "S2D*" -FriendlyName "Volume2" -FileSystem CSVFS_ReFS -Size 2TB -ResiliencySettingName Mirror -MediaType HDD, SSD
   ```

3. **Extend a Volume**
   ```powershell
   # Extend existing volume
   Resize-Volume -CimSession "S2DCluster" -Path "C:\ClusterStorage\Volume1" -Size 2TB
   ```

### Configure Caching and Tiering
1. **Configure Caching**
   ```powershell
   # Set caching behavior
   Set-ClusterStorageSpacesDirect -CimSession "S2DCluster" -CacheMode ReadWrite
   ```

2. **Optimize Storage Tiers**
   ```powershell
   # Set performance tier reservation
   Set-StorageTier -CimSession "S2DCluster" -FriendlyName "Performance" -MinimumSize 200GB
   ```

3. **Monitor Storage Tiers**
   ```powershell
   # Get tier usage statistics
   Get-StorageTier

   ## Implement and Manage Storage Spaces Direct (Continued)

### Performance Monitoring and Optimization
1. **Monitor Storage Performance**
   ```powershell
   # Get performance counters
   Get-Counter -Counter "\Cluster Storage Hybrid Disks(*)\*" -CimSession "S2DCluster"
   
   # Check IO latency
   Get-StorageSubSystem -CimSession "S2DCluster" | Get-StorageHealthReport -CimSession "S2DCluster" -Name "IOLatency"
   ```

2. **Monitor Cache Performance**
   ```powershell
   # Check cache hit ratio
   Get-ClusterPerf -MetricName "Cache*"
   
   # Check cache health
   Get-StorageHealthReport -CimSession "S2DCluster" -Name "CacheState"
   ```

3. **Optimize Deduplication**
   ```powershell
   # Enable deduplication on volume
   Enable-DedupVolume -Volume "C:\ClusterStorage\Volume1" -UsageType HyperV
   
   # Set deduplication schedule
   Set-DedupSchedule -Name "WeeklyOptimization" -Days Saturday -Start 01:00 -DurationHours 12
   ```

### Maintenance and Repair
1. **Replace a Failed Disk**
   ```powershell
   # Identify failed disk
   Get-PhysicalDisk -CimSession "S2DCluster" | Where-Object HealthStatus -eq "Unhealthy"
   
   # Remove failed disk
   Remove-PhysicalDisk -PhysicalDisk (Get-PhysicalDisk -SerialNumber "XYZ123456" -CimSession "S2DCluster")
   
   # Add new disk
   Add-PhysicalDisk -PhysicalDisks (Get-PhysicalDisk -SerialNumber "ABC789012" -CimSession "S2DCluster") -StoragePoolFriendlyName "S2D*" -CimSession "S2DCluster"
   ```

2. **Repair Virtual Disk**
   ```powershell
   # Check repair status
   Get-StorageJob -CimSession "S2DCluster"
   
   # Repair virtual disk
   Repair-VirtualDisk -FriendlyName "Volume1" -CimSession "S2DCluster"
   ```

3. **Suspend and Resume a Node**
   ```powershell
   # Suspend node for maintenance
   Suspend-ClusterNode -Name "Server1" -Drain
   
   # Resume node after maintenance
   Resume-ClusterNode -Name "Server1"
   ```

---

## Manage Backup and Recovery for Windows Server

### Windows Server Backup
1. **Install Windows Server Backup**
   ```powershell
   # Install feature
   Install-WindowsFeature -Name Windows-Server-Backup -IncludeManagementTools
   ```

2. **Create a One-Time Backup**
   ```powershell
   # Backup system state
   wbadmin start systemstatebackup -backupTarget:E:
   
   # Backup full server
   wbadmin start backup -backupTarget:E: -include:C: -allCritical
   ```

3. **Create a Backup Schedule**
   ```powershell
   # Schedule daily backup
   wbadmin enable backup -addtarget:E: -schedule:12:00 -include:C:,D: -systemState -vssFull
   
   # Using PowerShell
   $policy = New-WBPolicy
   $fileSpec = New-WBFileSpec -FileSpec "C:\Data"
   Add-WBFileSpec -Policy $policy -FileSpec $fileSpec
   $backupLocation = New-WBBackupTarget -VolumePath "E:"
   Add-WBBackupTarget -Policy $policy -Target $backupLocation
   Set-WBSchedule -Policy $policy -Schedule 12:00
   ```

4. **Recover from Backup**
   ```powershell
   # List available backups
   wbadmin get versions
   
   # Recover specific files
   wbadmin start recovery -version:01/01/2023-12:00 -itemPath:"C:\Data" -recoverytarget:"D:\Restored"
   
   # Recover system state
   wbadmin start systemstaterecovery -version:01/01/2023-12:00
   ```

### System Center Data Protection Manager (DPM)
1. **Install DPM Server**
   - Prerequisites: SQL Server, Windows Assessment and Deployment Kit

2. **Configure Protection Groups**
   ```powershell
   # Create a new protection group
   New-DPMProtectionGroup -DPMServerName "DPMServer" -Name "FileServers"
   
   # Add data sources
   Add-DPMDatasource -ProtectionGroup $pg -DatasourceName "FileServer" -Path "\\FileServer\Share"
   ```

3. **Configure Backup Schedule**
   ```powershell
   # Set protection schedule
   Set-DPMPolicySchedule -ProtectionGroup $pg -LongTerm -Day Friday -Time "20:00"
   ```

4. **Perform Recovery**
   ```powershell
   # Recover data to original location
   Get-DPMRecoveryPoint -DatasourceName "FileServer" | Restore-DPMRecoverableItem -OriginalLocation
   ```

### Azure Backup
1. **Install Azure Backup Agent**
   ```powershell
   # Download and install agent
   $wc = New-Object System.Net.WebClient
   $wc.DownloadFile("https://aka.ms/azurebackup_agent", "$env:TEMP\MARSAgentInstaller.exe")
   & "$env:TEMP\MARSAgentInstaller.exe" /q
   ```

2. **Register Server with Azure Backup**
   ```powershell
   # Register server
   Start-Process "C:\Program Files\Microsoft Azure Recovery Services Agent\bin\OBRegistrationUI.exe"
   ```

3. **Configure Backup Schedule**
   ```powershell
   # Set backup schedule
   $pol = New-OBPolicy
   $include = New-OBFileSpec -FileSpec "C:\Data"
   Add-OBFileSpec -Policy $pol -FileSpec $include
   Set-OBSchedule -Policy $pol -Schedule ([DateTime]::Parse("6:00 PM"))
   Set-OBRetentionPolicy -Policy $pol -RetentionPolicy ([DateTime]::Parse("30 days"))
   ```

4. **Perform Recovery from Azure**
   ```powershell
   # Start recovery wizard
   Start-Process "C:\Program Files\Microsoft Azure Recovery Services Agent\bin\OBRecoveryUI.exe"
   ```

### Windows System State Backup and Recovery
1. **Backup System State**
   ```powershell
   # Create system state backup
   wbadmin start systemstatebackup -backupTarget:E:
   ```

2. **Schedule System State Backup**
   ```powershell
   # Enable scheduled backup
   wbadmin enable systemstatebackup -addtarget:E: -schedule:02:00
   ```

3. **Recover System State**
   ```powershell
   # Perform system state recovery
   wbadmin start systemstaterecovery -version:01/01/2023-02:00 -backupTarget:E:
   ```

---

## Implement Disaster Recovery using Azure Site Recovery

### Prerequisites
1. **Azure Requirements**
   - Azure subscription
   - Azure Recovery Services vault
   - Virtual network (for failover)
   - Storage account

2. **On-Premises Requirements**
   - Windows Server 2016 or later
   - Hardware that meets Hyper-V requirements
   - Network connectivity to Azure

### Set Up Azure Site Recovery
1. **Create Recovery Services Vault**
   ```powershell
   # Create new vault
   New-AzRecoveryServicesVault -Name "ASRVault" -ResourceGroupName "RG1" -Location "East US"
   
   # Set vault context
   Set-AzRecoveryServicesVaultContext -Vault $vault
   ```

2. **Set Up Protection Goals**
   ```powershell
   # Set protection goal
   Set-AzRecoveryServicesAsrProtectionContainerMapping -Name "OnPremToAzure" -PrimaryProtectionContainer $primaryContainer -RecoveryProtectionContainer $recoveryContainer -Policy $policy
   ```

3. **Deploy Configuration Server**
   - Download unified setup from Azure portal
   - Install configuration server on-premises

### Protection and Replication
1. **Enable Replication for VMs**
   ```powershell
   # Enable replication for VM
   New-AzRecoveryServicesAsrReplicationProtectedItem -VMType Hyper-V -Name "VM1" -ProtectionContainer $primaryContainer -RecoveryAzureStorageAccountId $storageAccountID -OSDiskName "VM1-OS" -OS Windows
   ```

2. **Configure Replication Settings**
   ```powershell
   # Set replication policy
   $policy = New-AzRecoveryServicesAsrPolicy -Name "ReplicationPolicy" -RecoveryPoint 24 -RecoveryPointRetentionInHours 24
   ```

3. **Monitor Replication Health**
   ```powershell
   # Check replication status
   Get-AzRecoveryServicesAsrReplicationProtectedItem -ProtectionContainer $container | Select FriendlyName, ProtectionState, ReplicationHealth
   ```

### Failover and Failback
1. **Create Recovery Plan**
   ```powershell
   # Create plan
   $plan = New-AzRecoveryServicesAsrRecoveryPlan -Name "RecoveryPlan1" -PrimaryFabric $primaryFabric -RecoveryFabric $recoveryFabric
   ```

2. **Run Test Failover**
   ```powershell
   # Start test failover
   Start-AzRecoveryServicesAsrTestFailoverJob -RecoveryPlan $plan -Direction PrimaryToRecovery
   ```

3. **Perform Planned Failover**
   ```powershell
   # Start planned failover
   Start-AzRecoveryServicesAsrPlannedFailoverJob -RecoveryPlan $plan -Direction PrimaryToRecovery
   ```

4. **Perform Unplanned Failover**
   ```powershell
   # Start unplanned failover
   Start-AzRecoveryServicesAsrUnplannedFailoverJob -RecoveryPlan $plan -Direction PrimaryToRecovery
   ```

5. **Commit Failover**
   ```powershell
   # Commit
   Start-AzRecoveryServicesAsrCommitFailoverJob -RecoveryPlan $plan
   ```

6. **Failback to Primary**
   ```powershell
   # Start reprotect
   Start-AzRecoveryServicesAsrReProtectionJob -RecoveryPlan $plan
   
   # Start failback
   Start-AzRecoveryServicesAsrPlannedFailoverJob -RecoveryPlan $plan -Direction RecoveryToPrimary
   ```

---

## Protect Virtual Machines using Hyper-V Replicas

### Configure Hyper-V Replica
1. **Install Hyper-V Role**
   ```powershell
   # Install on primary and replica servers
   Install-WindowsFeature -Name Hyper-V -IncludeManagementTools
   ```

2. **Configure Hyper-V Replica**
   ```powershell
   # Enable replication on source server
   Enable-VmReplication -VMName "VM1" -ReplicaServerName "Server2" -ReplicaServerPort 80 -AuthenticationType Kerberos -ComputerName "Server1"
   ```

3. **Enable Extended Replication**
   ```powershell
   # Set up tertiary replica
   Enable-VmReplication -VMName "VM1" -ReplicaServerName "Server3" -ReplicaServerPort 80 -AuthenticationType Kerberos -ComputerName "Server2" -AsExtendedReplica
   ```

### Configure Replication Settings
1. **Set Replication Frequency**
   ```powershell
   # Set 30-second replication
   Set-VMReplication -VMName "VM1" -ReplicationFrequencySec 30
   ```

2. **Configure Recovery Points**
   ```powershell
   # Keep 12 recovery points
   Set-VMReplication -VMName "VM1" -RecoveryHistory 12
   ```

3. **Configure Network Bandwidth**
   ```powershell
   # Limit bandwidth usage
   Set-VMReplication -VMName "VM1" -CompressionEnabled $true -ReplicateHostKvpItems $true
   ```

### Perform Failover
1. **Planned Failover**
   ```powershell
   # Start planned failover
   Start-VMFailover -VMName "VM1" -ComputerName "Server1" -Prepare
   
   # Complete failover
   Start-VMFailover -VMName "VM1" -ComputerName "Server2"
   
   # Start replica VM
   Start-VM -VMName "VM1" -ComputerName "Server2"
   ```

2. **Test Failover**
   ```powershell
   # Create test VM
   Start-VMFailover -VMName "VM1" -ComputerName "Server2" -AsTest
   
   # Start test VM
   Start-VM -VMName "VM1 - Test" -ComputerName "Server2"
   ```

3. **Unplanned Failover**
   ```powershell
   # Start unplanned failover
   Start-VMFailover -VMName "VM1" -ComputerName "Server2"
   
   # Start VM
   Start-VM -VMName "VM1" -ComputerName "Server2"
   ```

4. **Failback to Primary**
   ```powershell
   # Reverse replication
   Set-VMReplication -VMName "VM1" -Reverse -ComputerName "Server2"
   
   # Perform failback
   Start-VMFailover -VMName "VM1" -ComputerName "Server2" -Prepare
   Start-VMFailover -VMName "VM1" -ComputerName "Server1"
   ```

---

## Migrate On-Premises Storage to On-Premises Servers or Azure

### Storage Migration Service
1. **Install Storage Migration Service**
   ```powershell
   # Install feature
   Install-WindowsFeature -Name SMS -IncludeManagementTools
   ```

2. **Create a Migration Job**
   ```powershell
   # Create new job
   New-SmsJob -Name "FileServerMigration"
   ```

3. **Run Inventory**
   ```powershell
   # Inventory source servers
   Invoke-SmsJobInventory -JobName "FileServerMigration" -SourceComputer "OldServer"
   ```

4. **Run Transfer**
   ```powershell
   # Transfer data to destination
   Invoke-SmsJobTransfer -JobName "FileServerMigration" -DestinationComputer "NewServer"
   ```

5. **Complete Cutover**
   ```powershell
   # Perform cutover
   Invoke-SmsJobCutover -JobName "FileServerMigration"
   ```

### Azure File Sync
1. **Deploy Storage Sync Service in Azure**
   ```powershell
   # Create storage sync service
   New-AzStorageSyncService -ResourceGroupName "RG1" -Name "StorageSync1" -Location "East US"
   ```

2. **Create Sync Group**
   ```powershell
   # Create new sync group
   New-AzStorageSyncGroup -ParentObject $service -Name "FileShare1"
   ```

3. **Add Cloud Endpoint**
   ```powershell
   # Add cloud endpoint
   New-AzStorageSyncCloudEndpoint -ParentObject $syncGroup -Name "CloudEndpoint" -StorageAccountId $storageAccount.Id -FileShareName "share1"
   ```

4. **Install Azure File Sync Agent**
   ```powershell
   # Download and install agent
   Invoke-WebRequest -Uri "https://aka.ms/afs/agent/Server2022" -OutFile "$env:TEMP\AzureFileSync.msi"
   Start-Process -FilePath "$env:TEMP\AzureFileSync.msi" -ArgumentList "/qn" -Wait
   ```

5. **Register Server with Storage Sync Service**
   ```powershell
   # Register server
   Register-AzStorageSyncServer -ParentObject $service
   ```

6. **Add Server Endpoint**
   ```powershell
   # Create server endpoint
   New-AzStorageSyncServerEndpoint -ParentObject $syncGroup -Name "ServerEndpoint" -ServerResourceId $server.Id -ServerLocalPath "D:\Data"
   ```

### Windows Server Migration Tools
1. **Install Migration Tools**
   ```powershell
   # Install tools
   Install-WindowsFeature -Name Migration
   ```

2. **Register Source Server**
   ```powershell
   Register-SmigServerSetting -InputFile C:\Source.xml
   ```

3. **Export Server Settings**
   ```powershell
   Export-SmigServerSetting -FeatureID FileServices -Path C:\FileServices.xml
   ```

4. **Import Server Settings**
   ```powershell
   Import-SmigServerSetting -FeatureID FileServices -Path C:\FileServices.xml -Force
   ```

---

## Migrate On-Premises Servers to Azure

### Azure Migrate
1. **Set Up Azure Migrate Project**
   ```powershell
   # Create project
   New-AzMigrateProject -Name "ServerMigration" -ResourceGroupName "RG1" -Location "East US"
   ```

2. **Deploy Appliance**
   - Download Azure Migrate appliance
   - Set up as a VM on-premises
   - Register with Azure Migrate project

3. **Discover Servers**
   ```powershell
   # Start discovery
   Start-AzMigrateDiskReplication -ResourceGroupName "RG1" -ProjectName "ServerMigration" -DiscoverySourceID $source.Id
   ```

4. **Assess Servers**
   ```powershell
   # Create assessment
   New-AzMigrateAssessment -Name "ServerAssessment" -Group $group -Project $project -AssessmentProperties $props
   ```

5. **Migrate Servers**
   ```powershell
   # Start replication
   New-AzMigrateServerReplication -ResourceGroupName "RG1" -ProjectName "ServerMigration" -MachineId $machine.Id -TargetResourceGroupId $targetRG.Id -TargetNetworkId $targetNetwork.Id -TargetSubnetName "default"
   
   # Test migration
   Start-AzMigrateTestMigration -ResourceGroupName "RG1" -ProjectName "ServerMigration" -MachineId $machine.Id
   
   # Start migration
   Start-AzMigrateMigration -ResourceGroupName "RG1" -ProjectName "ServerMigration" -MachineId $machine.Id
   ```

### Azure Site Recovery for VMware/Physical Servers
1. **Set Up Configuration Server**
   - Download unified setup
   - Install on VMware/Physical environment
   - Register with Recovery Services vault

2. **Install Mobility Service**
   ```powershell
   # Install on each server
   .\MobilityServiceInstaller.exe /q /x:C:\Temp\Extracted
   cd C:\Temp\Extracted
   .\installmobilityservice.ps1 ConfigurationServer IpAddress Password
   ```

3. **Enable Replication**
   ```powershell
   # Enable VM replication
   New-AzRecoveryServicesAsrReplicationProtectedItem -VMType VMware -Name "Server1" -ProtectionContainer $container -RecoveryVmName "Server1-Azure" -RecoveryAzureStorageAccountId $storage.Id -OSDiskName "Server1-OS" -OS Windows
   ```

4. **Perform Migration**
   ```powershell
   # Start migration
   Start-AzRecoveryServicesAsrUnplannedFailoverJob -ReplicationProtectedItem $rpi -Direction PrimaryToRecovery
   
   # Complete migration
   Start-AzRecoveryServicesAsrCommitFailoverJob -ReplicationProtectedItem $rpi
   ```

### Azure Database Migration Service
1. **Create Migration Service**
   ```powershell
   # Create service
   New-AzDataMigrationService -ResourceGroupName "RG1" -Name "DBMigration" -Location "East US" -Sku "Premium_4vCores"
   ```

2. **Create Migration Project**
   ```powershell
   # Create project
   New-AzDataMigrationProject -ResourceGroupName "RG1" -ServiceName "DBMigration" -ProjectName "SQLMigration" -SourceType SQL -TargetType SQLDB
   ```

3. **Run Assessment**
   ```powershell
   # Assess database compatibility
   Start-AzDataMigrationAssessment -ResourceGroupName "RG1" -ServiceName "DBMigration" -ProjectName "SQLMigration" -SourceConnectionInfo $sourceConnection -DatabaseNames "DB1"
   ```

4. **Migrate Database**
   ```powershell
   # Start migration
   New-AzDataMigrationTask -ResourceGroupName "RG1" -ServiceName "DBMigration" -ProjectName "SQLMigration" -TaskName "MigrateDB" -SourceConnectionInfo $sourceConnection -TargetConnectionInfo $targetConnection -TaskType OnlineMigration
   ```

---

## Migrate Workloads from Previous Versions to Server 2022

### In-Place Upgrade
1. **Assess Upgrade Readiness**
   ```powershell
   # Install Windows Assessment Services
   Import-Module ServerManager
   Install-WindowsFeature Windows-Assessment-Services
   
   # Run assessment
   Test-WindowsServerUpgradability
   ```

2. **Perform In-Place Upgrade**
   - Mount Windows Server 2022 ISO
   - Run setup.exe
   - Choose "Upgrade" option

3. **Post-Upgrade Tasks**
   ```powershell
   # Verify server features
   Get-WindowsFeature | Where-Object {$_.Installed -eq $true}
   
   # Install updates
   Install-WindowsUpdate -AcceptAll
   ```

### Side-by-Side Migration
1. **Export Server Configuration**
   ```powershell
   # Export server roles
   Export-SmigServerSetting -FeatureID DNS,DHCP -Path C:\ServerConfig.xml
   ```

2. **Deploy New Server**
   - Install clean Windows Server 2022
   - Join to same domain
   - Configure networking

3. **Import Server Configuration**
   ```powershell
   # Import server roles
   Import-SmigServerSetting -FeatureID DNS,DHCP -Path C:\ServerConfig.xml -Force
   ```

4. **Migrate Data**
   ```powershell
   # Use robocopy to transfer data
   robocopy \\OldServer\Share D:\Share /E /COPYALL /DCOPY:DAT /MIR /R:3 /W:3 /MT:32 /LOG:C:\Logs\RobocopyLog.txt
   ```

### IIS Workload Migration
1. **Export IIS Configuration**
   ```powershell
   # Export configuration
   Export-IISConfiguration -PhysicalPath C:\IISExport.xml
   ```

2. **Install IIS on New Server**
   ```powershell
   # Install IIS role
   Install-WindowsFeature -Name Web-Server -IncludeManagementTools
   
   # Install required features
   Install-WindowsFeature -Name Web-Asp-Net45,Web-Net-Ext45,Web-ISAPI-Ext,Web-ISAPI-Filter,Web-Mgmt-Console
   ```

3. **Import IIS Configuration**
   ```powershell
   # Import configuration
   Import-IISConfiguration -PhysicalPath C:\IISExport.xml
   ```

4. **Migrate Website Content**
   ```powershell
   # Copy website files
   robocopy \\OldServer\c$\inetpub\wwwroot C:\inetpub\wwwroot /E /COPYALL /R:3 /W:3
   ```

### AD DS Migration
1. **Prepare for Active Directory Migration**
   ```powershell
   # Check domain and forest functional levels
   Get-ADDomain | Select-Object DomainMode
   Get-ADForest | Select-Object ForestMode
   ```

2. **Add Domain Controller to Existing Domain**
   ```powershell
   # Install AD DS role
   Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
   
   # Promote to DC
   Install-ADDSDomainController -DomainName "contoso.com" -Credential (Get-Credential) -InstallDns
   ```

3. **Transfer FSMO Roles**
   ```powershell
   # Move Schema Master
   Move-ADDirectoryServerOperationMasterRole -Identity "NewDC" -OperationMasterRole SchemaMaster
   
   # Move Domain Naming Master
   Move-ADDirectoryServerOperationMasterRole -Identity "NewDC" -OperationMasterRole DomainNamingMaster
   
   # Move RID, PDC, and Infrastructure Master
   Move-ADDirectoryServerOperationMasterRole -Identity "NewDC" -OperationMasterRole RIDMaster,PDCEmulator,InfrastructureMaster
   ```

4. **Demote Old Domain Controllers**
   ```powershell
   # Demote DC
   Uninstall-ADDSDomainController -Credential (Get-Credential) -DemoteOperationMasterRole
   ```

---

## Windows Server Roles and Features

### Active Directory Certificate Services (AD CS)
1. **Install AD CS**
   ```powershell
   # Install role
   Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools
   
   # Configure CA
   Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName "Contoso Enterprise CA" -KeyLength 4096 -ValidityPeriod Years -ValidityPeriodUnits 10
   ```

2. **Deploy Certificate Templates**
   ```powershell
   # Copy template
   Copy-CATemplate -Name WebServer -DisplayName "Contoso Web Server"
   
   # Modify template permissions
   dsacls "CN=Contoso Web Server,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com" /G "CONTOSO\Web Administrators:RPWP;WRITE_PROPERTY"
   ```

3. **Issue Certificates**
   ```powershell
   # Enable template
   Add-CATemplate -Name "Contoso Web Server"
   
   # Request certificate
   Get-Certificate -Template "Contoso Web Server" -CertStoreLocation Cert:\LocalMachine\My
   ```

### DNS Server
1. **Install DNS Server**
   ```powershell
   # Install role
   Install-WindowsFeature -Name DNS -IncludeManagementTools
   ```

2. **Create Forward Lookup Zone**
   ```powershell
   # Create primary zone
   Add-DnsServerPrimaryZone -Name "contoso.com" -ZoneFile "contoso.com.dns"
   ```

3. **Create Reverse Lookup Zone**
   ```powershell
   # Create reverse lookup zone
   Add-DnsServerPrimaryZone -NetworkID "192.168.1.0/24" -ZoneFile "1.168.192.in-addr.arpa.dns"
   ```

4. **Create DNS Records**
   ```powershell
   # Add A record
   Add-DnsServerResourceRecordA -ZoneName "contoso.com" -Name "server1" -IPv4Address "192.168.1.10"
   
   # Add CNAME record
   Add-DnsServerResourceRecordCName -ZoneName "contoso.com" -Name "www" -HostNameAlias "server1.contoso.com"
   ```

5. **Configure Forwarders**
   ```powershell
   # Set forwarders
   Set-DnsServerForwarder -IPAddress 8.8.8.8, 8.8.4.4
   ```

### DHCP Server
1. **Install DHCP Server**
   ```powershell
   # Install role
   Install-WindowsFeature -Name DHCP -IncludeManagementTools
   ```

2. **Authorize DHCP Server**
   ```powershell
   # Authorize in AD
   Add-DhcpServerInDC -DnsName "dhcp1.contoso.com" -IPAddress 192.168.1.10
   ```

3. **Create DHCP Scope**
   ```powershell
   # Create IPv4 scope
   Add-DhcpServerv4Scope -Name "Corporate" -StartRange 192.168.1.100 -EndRange 192.168.1.200 -SubnetMask 255.255.255.0
   ```

4. **Configure DHCP Options**
   ```powershell
   # Set scope options
   Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 -Router 192.168.1.1 -DnsServer 192.168.1.10 -DnsDomain "contoso.com"
   ```

5. **Configure DHCP Reservations**
   ```powershell
   # Add reservation
   Add-DhcpServerv4Reservation -ScopeId 192.168.1.0 -IPAddress 192.168.1.50 -ClientId "00-11-22-33-44-55" -Description "Printer"
   ```

### File Server
1. **Install File Server Role**
   ```powershell
   # Install role
   Install-WindowsFeature -Name FS-FileServer -IncludeManagementTools
   ```

2. **Create Shares**
   ```powershell
   # Create SMB share
   New-SmbShare -Name "Public" -Path "D:\Shares\Public" -FullAccess "Everyone"
   ```

3. **Configure Share Permissions**
   ```powershell
   # Set share permissions
   Grant-SmbShareAccess -Name "Public" -AccountName "CONTOSO\Sales" -AccessRight Change
   Revoke-SmbShareAccess -Name "Public" -AccountName "Everyone"
   ```

4. **Configure NTFS Permissions**
   ```powershell
   # Set NTFS permissions
   $acl = Get-Acl -Path "D:\Shares\Public"
   $permission = "CONTOSO\Sales","Modify","Allow"
   $accessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $permission
   $acl.SetAccessRule($accessRule)
   $acl | Set-Acl -Path "D:\Shares\Public"
   ```

5. **Configure DFS Namespaces**
   ```powershell
   # Install DFS
   Install-WindowsFeature -Name FS-DFS-Namespace,FS-DFS-Replication -IncludeManagementTools
   
   # Create namespace
   New-DfsnRoot -TargetPath "\\Server1\Public" -Type DomainV2 -Path "\\contoso.com\shares"
   ```

### Web Server (IIS)
1. **Install IIS**
   ```powershell
   # Install role with common features
   Install-WindowsFeature -Name Web-Server -IncludeManagementTools
   
   # Install additional features
   Install-WindowsFeature -Name Web-Asp-Net45,Web-Net-Ext

# Windows Server Administration Guide - Selected Topics

## Group Policy Management

### Overview and Installation
1. **Install Group Policy Management Tools**
   ```powershell
   # Install GPMC
   Install-WindowsFeature -Name GPMC
   ```

2. **Open Group Policy Management Console**
   ```powershell
   # Open GPMC
   gpmc.msc
   ```

### Creating and Managing GPOs
1. **Create a New GPO**
   ```powershell
   # Create a new GPO
   New-GPO -Name "Security Settings"
   
   # Create and link in one step
   New-GPO -Name "Desktop Settings" | New-GPLink -Target "OU=Marketing,DC=contoso,DC=com"
   ```

2. **Link a GPO to an OU**
   ```powershell
   # Link existing GPO to OU
   New-GPLink -Name "Security Settings" -Target "OU=IT,DC=contoso,DC=com"
   ```

3. **Set GPO Processing Order**
   ```powershell
   # Set link order (lower number = higher priority)
   Set-GPLink -Name "Security Settings" -Target "OU=IT,DC=contoso,DC=com" -Order 1
   ```

4. **Disable a GPO Link**
   ```powershell
   # Disable a GPO link
   Set-GPLink -Name "Security Settings" -Target "OU=IT,DC=contoso,DC=com" -LinkEnabled No
   ```

### Configuring Common Policies
1. **Password Policy**
   - Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Password Policy
   ```powershell
   # Configure password policy
   Set-GPRegistryValue -Name "Security Settings" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "MaximumPasswordAge" -Type DWord -Value 30
   ```

2. **Lockout Policy**
   - Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Account Lockout Policy

3. **Audit Policy**
   - Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Audit Policy

4. **Software Restriction**
   - Computer Configuration → Policies → Windows Settings → Security Settings → Software Restriction Policies

### Group Policy Processing
1. **Force Policy Update**
   ```powershell
   # Force update on local computer
   gpupdate /force
   
   # Force update on remote computer
   Invoke-GPUpdate -Computer "Server1" -Force
   ```

2. **View Applied Policies**
   ```powershell
   # Get applied GPOs
   gpresult /r
   
   # Generate HTML report
   gpresult /h C:\Reports\GPReport.html /f
   ```

3. **Configure Policy Processing**
   ```powershell
   # Configure slow link detection
   Set-GPRegistryValue -Name "Policy Processing" -Key "HKLM\Software\Policies\Microsoft\Windows\System\GroupPolicy" -ValueName "SlowLinkDetectionEnabled" -Type DWord -Value 1
   ```

### Advanced GPO Management
1. **Back Up GPOs**
   ```powershell
   # Back up all GPOs
   Backup-GPO -All -Path "C:\GPOBackups" -Comment "Full Backup $(Get-Date)"
   
   # Back up specific GPO
   Backup-GPO -Name "Security Settings" -Path "C:\GPOBackups"
   ```

2. **Restore GPOs**
   ```powershell
   # Restore a specific GPO
   Restore-GPO -Name "Security Settings" -Path "C:\GPOBackups\{GUID}"
   ```

3. **Import/Export Settings**
   ```powershell
   # Export GPO settings
   Export-GPO -Name "Security Settings" -Path "C:\GPOExports"
   
   # Import GPO settings
   Import-GPO -BackupId {GUID} -TargetName "New Security Settings" -Path "C:\GPOBackups"
   ```

4. **GPO Delegation**
   ```powershell
   # Set delegation permissions
   Set-GPPermission -Name "Security Settings" -TargetName "CONTOSO\IT Admins" -TargetType Group -PermissionLevel GpoEditDeleteModifySecurity
   ```

5. **Create WMI Filters**
   ```powershell
   # Create WMI filter for Windows 10 computers
   $wmif = New-ADObject -Name "Windows 10 Computers" -Type "msWMI-Som" -Path "CN=SOM,CN=WMIPolicy,CN=System,DC=contoso,DC=com" -OtherAttributes @{"msWMI-Name"="Windows 10 Computers";"msWMI-Parm1"="Select * from Win32_OperatingSystem WHERE Version LIKE '10.%'";"msWMI-Author"="Administrator";"msWMI-ID"="{$((New-Guid).Guid)}"} -PassThru
   ```

---

## Windows Server Update Services (WSUS)

### WSUS Installation and Configuration
1. **Install WSUS Role**
   ```powershell
   # Install WSUS role with Management Tools
   Install-WindowsFeature -Name UpdateServices, UpdateServices-UI -IncludeManagementTools
   ```

2. **Post-Installation Configuration**
   ```powershell
   # Configure WSUS post-installation
   & "C:\Program Files\Update Services\Tools\WsusUtil.exe" postinstall CONTENT_DIR=D:\WSUS
   ```

3. **Configure WSUS Server Settings**
   ```powershell
   # Use PowerShell to configure WSUS
   $wsus = Get-WsusServer
   $wsusConfig = $wsus.GetConfiguration()
   
   # Configure sync schedule
   $wsusConfig.SyncScheduleEnabled = $true
   $wsusConfig.SynchronizeAutomatically = $true
   $wsusConfig.SynchronizeAutomaticallyTimeOfDay = (New-TimeSpan -Hours 3)
   $wsusConfig.Save()
   ```

### Configure Update Synchronization
1. **Select Products and Classifications**
   ```powershell
   # Get WSUS server
   $wsus = Get-WsusServer
   
   # Get update categories
   $wsusConfig = $wsus.GetSubscription()
   
   # Configure products to update
   $products = @("Windows Server 2022", "Windows Server 2019", "Windows 10")
   
   # Clear current product selections
   $wsusConfig.SetUpdateCategories(@())
   
   # Get available products
   $allProducts = $wsus.GetUpdateCategories()
   
   # Select products
   $selectedProducts = $allProducts | Where-Object {$_.Title -in $products}
   
   # Set selected products
   $wsusConfig.SetUpdateCategories($selectedProducts)
   
   # Configure update classifications
   $wsusConfig.SetUpdateClassifications(@("Critical Updates", "Security Updates", "Service Packs"))
   
   # Save configuration
   $wsusConfig.Save()
   ```

2. **Synchronize Updates**
   ```powershell
   # Start synchronization
   $wsus.GetSubscription().StartSynchronization()
   
   # Check synchronization status
   $wsus.GetSubscription().GetSynchronizationStatus()
   ```

3. **Configure Automatic Synchronization**
   ```powershell
   # Enable automatic synchronization
   $wsusConfig = $wsus.GetSubscription()
   $wsusConfig.SynchronizeAutomatically = $true
   $wsusConfig.SynchronizeAutomaticallyTimeOfDay = (New-TimeSpan -Hours 1)
   $wsusConfig.NumberOfSynchronizationsPerDay = 24
   $wsusConfig.Save()
   ```

### Configure Client-Side Targeting
1. **Enable Client-Side Targeting**
   ```powershell
   # Get WSUS server
   $wsus = Get-WsusServer
   
   # Get configuration
   $wsusConfig = $wsus.GetConfiguration()
   
   # Enable client-side targeting
   $wsusConfig.TargetingMode = "Client"
   $wsusConfig.Save()
   ```

2. **Create Computer Groups**
   ```powershell
   # Create computer groups
   $wsus.CreateComputerTargetGroup("Production Servers")
   $wsus.CreateComputerTargetGroup("Test Servers")
   $wsus.CreateComputerTargetGroup("Workstations")
   ```

3. **Configure Group Policy for Client Targeting**
   ```powershell
   # Create GPO for WSUS targeting
   New-GPO -Name "WSUS Client Settings" | New-GPLink -Target "DC=contoso,DC=com"
   
   # Configure GPO settings
   Set-GPRegistryValue -Name "WSUS Client Settings" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "WUServer" -Type String -Value "http://wsus.contoso.com:8530"
   Set-GPRegistryValue -Name "WSUS Client Settings" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "WUStatusServer" -Type String -Value "http://wsus.contoso.com:8530"
   Set-GPRegistryValue -Name "WSUS Client Settings" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "NoAutoUpdate" -Type DWord -Value 0
   Set-GPRegistryValue -Name "WSUS Client Settings" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "AUOptions" -Type DWord -Value 4
   Set-GPRegistryValue -Name "WSUS Client Settings" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "TargetGroupEnabled" -Type DWord -Value 1
   Set-GPRegistryValue -Name "WSUS Client Settings" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "TargetGroup" -Type String -Value "Production Servers"
   ```

### Approve and Deploy Updates
1. **Review Available Updates**
   ```powershell
   # Get all updates
   $wsus = Get-WsusServer
   $allUpdates = $wsus.GetUpdates()
   
   # Get updates that haven't been approved
   $notApprovedUpdates = $allUpdates | Where-Object {-not $_.IsApproved}
   ```

2. **Approve Updates for Installation**
   ```powershell
   # Approve critical updates for Production Servers
   $criticalUpdates = $allUpdates | Where-Object {$_.UpdateClassificationTitle -eq "Critical Updates" -and -not $_.IsApproved}
   $productionGroup = $wsus.GetComputerTargetGroups() | Where-Object {$_.Name -eq "Production Servers"}
   
   foreach ($update in $criticalUpdates) {
     $update.Approve("Install", $productionGroup)
   }
   ```

3. **Decline Superseded Updates**
   ```powershell
   # Decline superseded updates
   $supersededUpdates = $allUpdates | Where-Object {$_.IsSuperseded -and -not $_.IsDeclined}
   
   foreach ($update in $supersededUpdates) {
     $update.Decline()
   }
   ```

### Monitor Update Deployment
1. **Check Update Status**
   ```powershell
   # Get update status
   $wsus = Get-WsusServer
   $updateStatus = $wsus.GetSummariesPerUpdate()
   
   # Get computers that need updates
   $computersNeedingUpdates = $wsus.GetComputerTargets() | Where-Object {$_.GetUpdateInstallationSummary().NotInstalledCount -gt 0}
   ```

2. **Generate Reports**
   ```powershell
   # Generate status report
   $reportFolder = "C:\Reports"
   if (-not (Test-Path $reportFolder)) { New-Item -ItemType Directory -Path $reportFolder }
   
   $report = @()
   foreach ($computer in $wsus.GetComputerTargets()) {
     $summary = $computer.GetUpdateInstallationSummary()
     $report += [PSCustomObject]@{
       ComputerName = $computer.FullDomainName
       IPAddress = $computer.IPAddress
       LastReported = $computer.LastReportedStatusTime
       InstalledCount = $summary.InstalledCount
       FailedCount = $summary.FailedCount
       NotInstalledCount = $summary.NotInstalledCount
     }
   }
   $report | Export-Csv -Path "$reportFolder\UpdateReport.csv" -NoTypeInformation
   ```

3. **Clean Up WSUS**
   ```powershell
   # Run WSUS cleanup wizard
   $wsusCleanup = $wsus.GetCleanupManager()
   $wsusCleanup.PerformCleanup($true, $true, $true, $true, $true)
   ```

---

## Remote Desktop Services

### Installing Remote Desktop Services
1. **Install RDS Core Components**
   ```powershell
   # Install RD Connection Broker
   Install-WindowsFeature -Name RDS-Connection-Broker -IncludeManagementTools
   
   # Install RD Web Access
   Install-WindowsFeature -Name RDS-Web-Access -IncludeManagementTools
   
   # Install RD Session Host
   Install-WindowsFeature -Name RDS-RD-Server -IncludeManagementTools
   ```

2. **Deploy Using Server Manager**
   - Open Server Manager
   - Select "Add Roles and Features"
   - Choose "Remote Desktop Services installation"
   - Select deployment type:
     - Standard: Multiple servers for each role
     - Quick Start: Single server for all roles

3. **Deploy Using PowerShell**
   ```powershell
   # Deploy RDS farm with PowerShell
   New-RDSessionDeployment -ConnectionBroker "rdcb.contoso.com" -WebAccessServer "rdwa.contoso.com" -SessionHost "rdsh1.contoso.com","rdsh2.contoso.com"
   ```

### Configure RDS Collections
1. **Create a Session Collection**
   ```powershell
   # Create a collection for task workers
   New-RDSessionCollection -CollectionName "TaskWorkers" -SessionHost "rdsh1.contoso.com","rdsh2.contoso.com" -ConnectionBroker "rdcb.contoso.com"
   ```

2. **Configure Collection Properties**
   ```powershell
   # Set user logon settings
   Set-RDSessionCollectionConfiguration -CollectionName "TaskWorkers" -ConnectionBroker "rdcb.contoso.com" -UserGroup "CONTOSO\Task Workers" -DisconnectedSessionLimitMin 60 -IdleSessionLimitMin 60
   
   # Configure RDP properties
   Set-RDSessionCollectionConfiguration -CollectionName "TaskWorkers" -ConnectionBroker "rdcb.contoso.com" -ClientDeviceRedirectionOptions "AudioVideoPlayBack,AudioRecording,Clipboard,Drives,Printers"
   ```

3. **Configure RemoteApp Programs**
   ```powershell
   # Add applications to collection
   New-RDRemoteApp -CollectionName "TaskWorkers" -ConnectionBroker "rdcb.contoso.com" -DisplayName "Microsoft Word" -FilePath "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
   New-RDRemoteApp -CollectionName "TaskWorkers" -ConnectionBroker "rdcb.contoso.com" -DisplayName "Microsoft Excel" -FilePath "C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"
   ```

### Configure Virtual Desktop Infrastructure (VDI)
1. **Install Required Components**
   ```powershell
   # Install Hyper-V
   Install-WindowsFeature -Name Hyper-V -IncludeManagementTools
   
   # Install RD Virtualization Host
   Install-WindowsFeature -Name RDS-Virtualization -IncludeManagementTools
   ```

2. **Create a VDI Deployment**
   ```powershell
   # Add RD Virtualization Host role
   Add-RDVirtualizationHostServer -VirtualizationHost "vhost.contoso.com" -ConnectionBroker "rdcb.contoso.com"
   ```

3. **Create a Pooled Virtual Desktop Collection**
   ```powershell
   # Create a pooled VDI collection
   New-RDVirtualDesktopCollection -CollectionName "PooledVDI" -PooledManaged -VirtualDesktopTemplate "Win10Template" -VirtualDesktopTemplateStoragePath "C:\VHDs" -ConnectionBroker "rdcb.contoso.com" -VirtualizationHost "vhost.contoso.com"
   ```

4. **Create a Personal Virtual Desktop Collection**
   ```powershell
   # Create a personal VDI collection
   New-RDVirtualDesktopCollection -CollectionName "PersonalVDI" -PersonalUnmanaged -ConnectionBroker "rdcb.contoso.com" -VirtualizationHost "vhost.contoso.com"
   ```

### Configure RD Gateway
1. **Install RD Gateway Role**
   ```powershell
   # Install RD Gateway role
   Install-WindowsFeature -Name RDS-Gateway -IncludeManagementTools
   ```

2. **Configure RD Gateway**
   ```powershell
   # Add RD Gateway to deployment
   Add-RDServer -Server "rdgw.contoso.com" -Role "RDS-GATEWAY" -ConnectionBroker "rdcb.contoso.com"
   
   # Configure Gateway properties
   Set-RDDeploymentGatewayConfiguration -GatewayMode Custom -GatewayExternalFqdn "gateway.contoso.com" -LogonMethod Password -UseCachedCredentials $true -BypassLocal $true -ConnectionBroker "rdcb.contoso.com"
   ```

3. **Create Authorization Policies**
   ```powershell
   # Create CAP (Connection Authorization Policy)
   New-RDGatewayCAP -Name "RDG CAP" -UserGroups "CONTOSO\RDS Users" -GatewayServer "rdgw.contoso.com"
   
   # Create RAP (Resource Authorization Policy)
   New-RDGatewayRAP -Name "RDG RAP" -ResourceGroup "CONTOSO\RDS Servers" -ComputerGroupType Domain -GatewayServer "rdgw.contoso.com"
   ```

### Configure RD Licensing
1. **Install RD Licensing Role**
   ```powershell
   # Install RD Licensing role
   Install-WindowsFeature -Name RDS-Licensing -IncludeManagementTools
   ```

2. **Configure RD Licensing Server**
   ```powershell
   # Add RD Licensing to deployment
   Add-RDServer -Server "rdls.contoso.com" -Role "RDS-LICENSING" -ConnectionBroker "rdcb.contoso.com"
   
   # Set licensing mode
   Set-RDLicenseConfiguration -LicenseServer "rdls.contoso.com" -Mode PerUser -ConnectionBroker "rdcb.contoso.com"
   ```

3. **Activate Licensing Server**
   ```powershell
   # Activate via UI: Remote Desktop Licensing Manager
   # No direct PowerShell cmdlet available for activation
   ```

### Configure High Availability
1. **Configure Connection Broker HA**
   ```powershell
   # Set up RD Connection Broker HA
   Set-RDConnectionBrokerHighAvailability -DatabaseConnectionString "DRIVER=SQL Server Native Client 11.0;SERVER=sql.contoso.com;Trusted_Connection=Yes;APP=Remote Desktop Services Connection Broker;DATABASE=RDCBDatabase" -DatabaseFilePath "\\fileserver\RDSConfig\RDCB.mdf" -ClientAccessName "rdcb.contoso.com"
   ```

2. **Add Secondary Connection Broker**
   ```powershell
   # Add a secondary Connection Broker
   Add-RDServer -Server "rdcb2.contoso.com" -Role "RDS-CONNECTION-BROKER" -ConnectionBroker "rdcb.contoso.com"
   ```

3. **Configure Session Host HA**
   ```powershell
   # Add additional Session Hosts
   Add-RDServer -Server "rdsh3.contoso.com" -Role "RDS-RD-SERVER" -ConnectionBroker "rdcb.contoso.com"
   
   # Configure session host load balancing
   Set-RDSessionCollectionConfiguration -CollectionName "TaskWorkers" -ConnectionBroker "rdcb.contoso.com" -LoadBalancing Level -SessionHost "rdsh1.contoso.com","rdsh2.contoso.com","rdsh3.contoso.com"
   ```

---

## Windows Server Containers and Docker

### Installing Container Support
1. **Install Container Feature**
   ```powershell
   # Install containers feature
   Install-WindowsFeature -Name Containers
   ```

2. **Install Docker**
   ```powershell
   # Configure package provider
   Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
   
   # Install Docker provider
   Install-Module -Name DockerMsftProvider -Repository PSGallery -Force
   
   # Install Docker package
   Install-Package -Name Docker -ProviderName DockerMsftProvider -Force
   
   # Restart computer
   Restart-Computer -Force
   ```

3. **Configure Docker Service**
   ```powershell
   # Start Docker service
   Start-Service Docker
   
   # Configure Docker to start automatically
   Set-Service -Name Docker -StartupType Automatic
   ```

### Container Base Images
1. **Download Windows Container Images**
   ```powershell
   # List available images
   docker images
   
   # Pull Windows Server Core image
   docker pull mcr.microsoft.com/windows/servercore:ltsc2022
   
   # Pull Nano Server image
   docker pull mcr.microsoft.com/windows/nanoserver:ltsc2022
   
   # Pull Windows image
   docker pull mcr.microsoft.com/windows:ltsc2022
   ```

2. **View Downloaded Images**
   ```powershell
   # List all images
   docker images
   ```

### Creating and Managing Containers
1. **Create a Container**
   ```powershell
   # Run a container interactively
   docker run -it mcr.microsoft.com/windows/servercore:ltsc2022 cmd
   
   # Run a detached container
   docker run -d --name web1 -p 80:80 mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2022
   ```

2. **Manage Container Lifecycle**
   ```powershell
   # List running containers
   docker ps
   
   # List all containers
   docker ps -a
   
   # Stop a container
   docker stop web1
   
   # Start a container
   docker start web1
   
   # Remove a container
   docker rm web1
   ```

3. **Container Networking**
   ```powershell
   # Create a Docker network
   docker network create --driver nat contoso-net
   
   # Run container on specific network
   docker run -d --name web2 --network contoso-net -p 8080:80 mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2022
   
   # Inspect container networking
   docker network inspect contoso-net
   ```

### Creating Custom Container Images
1. **Create a Dockerfile**
   ```
   # Create a directory for your project
   mkdir C:\Docker\webapp
   cd C:\Docker\webapp
   
   # Create a Dockerfile
   notepad Dockerfile
   ```

2. **Sample Dockerfile Contents**
   ```dockerfile
   FROM mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2022
   
   # Install ASP.NET
   RUN powershell -Command Add-WindowsFeature Web-Asp-Net45
   
   # Copy application files
   COPY . /inetpub/wwwroot
   
   # Set working directory
   WORKDIR /inetpub/wwwroot
   
   # Expose port 80
   EXPOSE 80
   
   # Start IIS
   ENTRYPOINT ["C:\\ServiceMonitor.exe", "w3svc"]
   ```

3. **Build the Docker Image**
   ```powershell
   # Build image
   docker build -t contoso/webapp:v1 .
   
   # Verify image
   docker images
   ```

4. **Run the Custom Container**
   ```powershell
   # Run the container
   docker run -d --name webapp -p 80:80 contoso/webapp:v1
   
   # Check if container is running
   docker ps
   ```

### Container Orchestration with Kubernetes
1. **Install Kubernetes on Windows**
   ```powershell
   # Install Kubernetes CLI (kubectl)
   Invoke-WebRequest -Uri "https://dl.k8s.io/release/v1.25.0/bin/windows/amd64/kubectl.exe" -OutFile "C:\Windows\System32\kubectl.exe"
   ```

2. **Connect to a Kubernetes Cluster**
   ```powershell
   # Set Kubernetes configuration
   $env:KUBECONFIG = "C:\Users\Administrator\.kube\config"
   
   # Test connection
   kubectl cluster-info
   ```

3. **Deploy a Windows Container to Kubernetes**
   ```powershell
   # Create a deployment YAML file
   @"
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: iis-deployment
     labels:
       app: iis
   spec:
     replicas: 3
     selector:
       matchLabels:
         app: iis
     template:
       metadata:
         labels:
           app: iis
       spec:
         containers:
         - name: iis
           image: mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2022
           ports:
           - containerPort: 80
   "@ | Out-File -FilePath "iis-deployment.yaml"
   
   # Apply the deployment
   kubectl apply -f iis-deployment.yaml
   ```

---

## Windows Admin Center

### Installation and Configuration
1. **Download Windows Admin Center**
   ```powershell
   # Download Windows Admin Center
   Invoke-WebRequest -UseBasicParsing -Uri https://aka.ms/WACDownload -OutFile "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
   ```

2. **Install Windows Admin Center**
   ```powershell
   # Install Windows Admin Center
   Start-Process msiexec.exe -ArgumentList "/i $env:USERPROFILE\Downloads\WindowsAdminCenter.msi /qn /L*v log.txt SME_PORT=443 SSL_CERTIFICATE_OPTION=generate" -Wait
   ```

3. **Configure HTTPS**
   ```powershell
   # Create and install a self-signed certificate
   $cert = New-SelfSignedCertificate -DnsName "adminserver.contoso.com" -CertStoreLocation "cert:\LocalMachine\My"
   
   # Export certificate
   Export-Certificate -Cert $cert -FilePath "C:\Certificates\admincenter.cer"
   ```

### Adding Servers and Managing Connections
1. **Add Servers to Windows Admin Center**
   - Open Windows Admin Center (https://localhost or https://servername)
   - Click "Add" under "All connections"
   - Choose "Add server connection"
   - Enter server name or IP address
   - Choose authentication method

2. **Create a Server Group**
   - Click "Add" under "All connections"
   - Choose "Add server group"
   - Name the group and add servers

3. **Manage Connection Credentials**
   - Click on "Settings" (gear icon)
   - Select "User Accounts"
   - Configure saved credentials

### Managing Servers with Windows Admin Center
1. **Overview Dashboard**
   - Connect to a server
   - View system information, performance, and events

2. **Managing Server Roles and Features**
   - Navigate to "Roles & Features"
   - Install or remove roles and features

3. **Managing Certificates**
   - Navigate to "Certificates"
   - View, create, and manage certificates

4. **Managing Storage**
   - Navigate to "Storage"
   - Manage volumes, disks, and shares

5. **Managing Hyper-V**
   - Navigate to "Virtual Machines"
   - Create, configure, and manage VMs

### PowerShell in Windows Admin Center
1. **Using PowerShell Tools**
   - Navigate to "PowerShell"
   - Run PowerShell commands directly on the remote server

2. **Script Library**
   - Navigate to "PowerShell" > "Script Library"
   - Save and run common scripts

### Extensions and Updates
1. **Install Extensions**
   - Navigate to "Settings" > "Extensions"
   - Browse available extensions
   - Install required extensions

2. **Update Windows Admin Center**
   - Navigate to "Settings" > "About"
   - Check for updates and install if available

---

## PowerShell Automation for Windows Server

### PowerShell Basics for Server Administration
1. **PowerShell Execution Policy**
   ```powershell
   # Check current execution policy
   Get-ExecutionPolicy
   
   # Set execution policy
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

2. **PowerShell Modules**
   ```powershell
   # List available modules
   Get-Module -ListAvailable
   
   # Import a module
   Import-Module ServerManager
   
   # Find commands in a module
   Get-Command -Module ServerManager
   ```

3. **Remote PowerShell Sessions**
   ```powershell
   # Enable PowerShell remoting (run on target server)
   Enable-PSRemoting -Force
   
   # Create a remote session
   $session = New-PSSession -ComputerName "Server1"
   
   # Run commands on remote session
   Invoke-Command -Session $session -ScriptBlock { Get-Service | Where-Object { $_.Status -eq "Running" } }
   
   # Enter interactive session
   Enter-PSSession -ComputerName "Server1"
   ```

### Server Management Automation
1. **Managing Server Roles and Features**
   ```powershell
   # Get installed roles and features
   Get-WindowsFeature | Where-Object {$_.Installed -eq $true}
   
   # Install a role or feature
   Install-WindowsFeature -Name DHCP -IncludeManagementTools
   
   # Remove a role or feature
   Uninstall-WindowsFeature -Name Web-Server
   ```

2. **Managing Services**
   ```powershell
   # Get service status
   Get-Service -Name DHCP
   
   # Start a service
   Start-Service -Name DHCP
   
   # Stop a service
   Stop-Service -Name DHCP
   
   # Configure service startup type
   Set-Service -Name DHCP -StartupType Automatic
   ```

3. **Managing Scheduled Tasks**
   ```powershell
   # Create a scheduled task
   $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\Backup.ps1"
   $trigger = New-ScheduledTaskTrigger -Daily -At 3am
   Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Daily Backup" -Description "Daily backup task"
   
   # Get scheduled tasks
   Get-ScheduledTask | Where-Object {$_.TaskName -like "*Backup*"}
   
   # Disable a scheduled task
   Disable-ScheduledTask -TaskName "Daily Backup"
   ```

