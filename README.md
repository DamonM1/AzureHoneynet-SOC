# Azure SOC w/ Honeynet: Cyber attacks in real time 
## Introduction
![image](https://github.com/DamonM1/AzureHoneynet-Soc/assets/62221702/694ce035-93b2-4cbd-a016-d1b5c52300a4)

In this project, I build a mini honeynet in Azure and ingest log sources from various resources into a Log Analytics workspace, which is then used by Microsoft Sentinel to build attack maps, trigger alerts, and create incidents. I measured some security metrics in the insecure environment for 24 hours, apply some security controls to harden the environment, measure metrics for another 24 hours, then show the results below. The metrics we will show are:

- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Log Analytics Alerts Triggered)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (Malicious Flows allowed into our honeynet)

## Architecture Before Hardening / Security Controls
![BeforeArch](https://github.com/DamonM1/AzureHoneynet-Soc/assets/62221702/7693b35b-2f68-4b3c-aaec-9d19bf12b158)



The architecture of the mini honeynet in Azure consists of the following components:

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 windows, 1 linux)
- Log Analytics Workspace
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel

For the "BEFORE" metrics, all resources were originally deployed, exposed to the internet. The Virtual Machines had both their Network Security Groups and built-in firewalls wide open, and all other resources are deployed with public endpoints visible to the Internet; aka, no use for Private Endpoints.

## Attack Maps Before Hardening / Security Controls
![NSG_Unsecure](https://github.com/DamonM1/AzureHoneynet-Soc/assets/62221702/644d506c-1049-4d4c-8f5a-bdef9b6c188a)<br>
![RDP_Unsecure](https://github.com/DamonM1/AzureHoneynet-Soc/assets/62221702/fc8e9c3b-0f93-4447-8d65-0faffeedafc7)<br>
![LSSH_Unsecure](https://github.com/DamonM1/AzureHoneynet-Soc/assets/62221702/3f7dd677-5fc5-47ac-b23e-3421f1072f4e)<br>
![SQL_Unsecure](https://github.com/DamonM1/AzureHoneynet-Soc/assets/62221702/c48bf513-a2e8-46b8-987f-fbc4bad4af42)<br>


## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:
Start Time 2023-09-20 23:44:00
Stop Time 2023-09-21 23:44:00

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 17756
| Syslog                   | 5209
| SecurityAlert            | 3
| SecurityIncident         | 217
| AzureNetworkAnalytics_CL | 3355

## Sentinel Incidents Before Hardening / Security Controls 
![SentinelUnsecure](https://github.com/DamonM1/AzureHoneynet-Soc/assets/62221702/3f8ffc4a-a875-444a-82c0-bffb0aa1179e)<br>

## Utilizing NIST 800.61 Revision 2 Computer Incident Handling Guide
 <br>
For each simualated 'High Severity' atttack was handled using the Incident Response Life Cycle

<b>Preparation</b>
  - The Azure lab was set up to ingest all of the logs into Log Analytics Workspace, Sentinel and Defender were configured, and alert rules were put in place.
<br></br>
   ![NIST_IRCYCLE](https://github.com/DamonM1/AzureHoneynet-Soc/assets/62221702/debc0084-2c9a-4b66-8686-f32883145beb)<br>

<b>Detection & Analysis</b>
  - Malware has been detected on a workstation
  - Incident has been assigned to IRUser, set the severity to ‘High’ and the status has been set to ‘Active’
![Incident](https://github.com/DamonM1/AzureHoneynet-Soc/assets/62221702/aa7570fc-a4f7-4bec-907c-bfc263eea0ac)<br>

  - Identified the entities involved(i.e windows-vm) and other possible systems that were involved
  - Verified the authenticity of the alert, which resulted in a “False Positive”
  - User was testing with EICAR files. Here is the query used: 
SecurityAlert
| where AlertType == “AntimalwareActionTaken”
| where CompromisedEntity == “windows-vm”
![FalsePositive](https://github.com/DamonM1/AzureHoneynet-Soc/assets/62221702/d7bfe0d8-d237-4efe-b7f3-ef7328faa749)<br>

<b>Containment, Eradication & Recovery</b>
  - Malware was removed from users workstation
  - User’s workstation restored with last known backup 

<b>Post-Incident Activity</b>
  - Corrective action was implemented to remediate the root cause.
  - Microsoft Sentinel Incident was closed.
  - The detection rule was edited to determine if a possible EICAR file is being used.
  - Lessons-learning review of the incident was conducted.


## Implementing Hardening Measures & Security Controls using NIST 800-53
  Using Microsoft Defender's built-in Security Benchmark tool to follow NIST 800-53 standards
  ![NistBenchmark](https://github.com/DamonM1/AzureHoneynet-Soc/assets/62221702/ce62a595-9e52-45bf-bc9d-c32b6f3673f5)<br>

  Specifically will be fulfilling the compliance standards associated with SC.7.* - Boundary Protection
![NIST80053SC7_Before](https://github.com/DamonM1/AzureHoneynet-Soc/assets/62221702/17e97400-c867-4af7-8cbc-e6fecd01421f)<br>

  <b>Hardening Measures</b>: 
   - <b>Network Security Groups (NSGs)</b>: NSGs were hardened by blocking all inbound and outbound traffic with the exception of designated public IP addresses that required access to the virtual machines. This ensured that only authorized traffic from a trusted source was allowed to access the virtual machines.

  - <b>Built-in Firewalls</b>: Azure's built-in firewalls were configured on the virtual machines to restrict unauthorized access and protect the resources from malicious connections. This step involved fine-tuning the firewall rules based on the service and responsibilities of each VM which mitigated the attack surface bad actors had access to.

  - <b>Private Endpoints</b>: To enhance the security of Azure Key Vault and Storage Containers, Public Endpoints were replaced with Private Endpoints. This ensured that access to these sensitive resources was limited to the virtual network and not the public internet.

## Architecture After Hardening / Security Controls
![Architecture Diagram](https://i.imgur.com/YQNa9Pp.jpg)

## Attack Maps Before Hardening / Security Controls

```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.```

## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls:
Start Time 2023-09-23 12:13:02
Stop Time	2023-09-24 12:13:02

| Metric                   | Count | % Change
| ------------------------ | ----- | --------
| SecurityEvent            | 9106  | -48.72%
| Syslog                   | 1     | -99.98%
| SecurityAlert            | 0     | -100.00%
| SecurityIncident         | 0     | -100.00%
| AzureNetworkAnalytics_CL | 0     | -100.00%

## Sentinel Incidents After Hardening / Security Controls 
![SentinelSafe](https://github.com/DamonM1/AzureHoneynet-Soc/assets/62221702/53ddf495-dd36-4faa-9aeb-85fca9f4f432)<br>

## Conclusion

In this project, a mini honeynet was constructed in Microsoft Azure and log sources were integrated into a Log Analytics workspace. Microsoft Sentinel was employed to trigger alerts and create incidents based on the ingested logs. Additionally, metrics were measured in the insecure environment before security controls were applied, and then again after implementing security measures. It is noteworthy that the number of security events and incidents were drastically reduced after the security controls were applied, demonstrating their effectiveness.

It is worth noting that if the resources within the network were heavily utilized by regular users, it is likely that more security events and alerts may have been generated within the 24-hour period following the implementation of the security controls.
