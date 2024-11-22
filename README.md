<img src="https://github.com/rabobank-cdc/DeTTECT/wiki/images/logo_dark.png#gh-dark-mode-only" alt="DeTT&CT" width=30% height=30%>
<img src="https://github.com/rabobank-cdc/DeTTECT/wiki/images/logo.png#gh-light-mode-only" alt="DeTT&CT" width=30% height=30%>

#### Detect Tactics, Techniques & Combat Threats
Latest version: [2.0.0](https://github.com/rabobank-cdc/DeTTECT/wiki/Changelog#version-200)

To get started with DeTT&CT, check out one of these resources:
- This [page](https://github.com/rabobank-cdc/DeTTECT/wiki/Getting-started) on the Wiki.
- This [blog](https://blog.nviso.eu/2022/03/09/dettct-mapping-detection-to-mitre-attck/) written by [Renaud Frère](https://twitter.com/Azotium) from NVISO has a comprehensive and recent description on the capabilities of DeTT&CT.
- Blog: [mbsecure.nl/blog/2019/5/dettact-mapping-your-blue-team-to-mitre-attack](https://www.mbsecure.nl/blog/2019/5/dettact-mapping-your-blue-team-to-mitre-attack) or
- Blog: [siriussecurity.nl/blog/2019/5/8/mapping-your-blue-team-to-mitre-attack](https://www.siriussecurity.nl/blog/2019/5/8/mapping-your-blue-team-to-mitre-attack).

**Videos**
- Our [talk](https://www.youtube.com/watch?v=_kWpekkhomU) at hack.lu 2019.
- The [video](https://www.youtube.com/watch?v=EXnutTLKS5o) from [Justin Henderson](https://twitter.com/SecurityMapper) on data source visibility and mapping.

DeTT&CT aims to assist blue teams in using ATT&CK to score and compare data log source quality, visibility coverage, detection coverage and threat actor behaviours. All of which can help, in different ways, to get more resilient against attacks targeting your organisation. The DeTT&CT framework consists of a Python tool (DeTT&CT CLI), YAML administration files, the [DeTT&CT Editor](https://rabobank-cdc.github.io/dettect-editor) (to create and edit the YAML administration files) and [scoring tables](https://github.com/rabobank-cdc/DeTTECT/raw/master/scoring_table.xlsx) for [detections](https://github.com/rabobank-cdc/DeTTECT/wiki/How-to-use-the-framework#detection), [data sources](https://github.com/rabobank-cdc/DeTTECT/wiki/How-to-use-the-framework#data-source) and [visibility](https://github.com/rabobank-cdc/DeTTECT/wiki/How-to-use-the-framework#visibility).

DeTT&CT provides the following functionality for the ATT&CK domains Enterprise, ICS and Mobile:

- Administrate and score the quality of your data sources.
- Get insight on the visibility you have on for example endpoints.
- Map your detection coverage.
- Map threat actor behaviours.
- Compare visibility, detection coverage and threat actor behaviours to uncover possible improvements in detection and visibility (which is based on your available data sources). This can help you to prioritise your blue teaming efforts.
- Get statistics (per platform) on the number of techniques covered per data source.

The coloured visualisations are created with the help of MITRE's [ATT&CK™ Navigator](https://mitre-attack.github.io/attack-navigator/#comment_underline=false&metadata_underline=false). *For layer files created by DeTT&CT, we recommend using this URL to the Navigator as it will make sure metadata in the layer file does not have a yellow underline: [https://mitre-attack.github.io/attack-navigator/#comment_underline=false&metadata_underline=false](https://mitre-attack.github.io/attack-navigator/#comment_underline=false&metadata_underline=false)*

## Authors and contributions
This project is developed and maintained by [Marcus Bakker](https://github.com/marcusbakker) (Twitter: [@Bakk3rM](https://twitter.com/Bakk3rM)) and [Ruben Bouman](https://github.com/rubinatorz) (Twitter: [@rubinatorz](https://twitter.com/rubinatorz/)). Feel free to contact, DMs are open. We do appreciate if you ask any question on how to use DeTT&CT by making a GitHub issue. Having the questions and answers over there will greatly help others having similar questions and challenges.

We welcome contributions! Contributions can be both in code and in ideas you might have for further development, usability improvements, etc.

### Sponsors
The following parties have supported the development of DeTT&CT in time or financially.

- **[Rabobank](https://www.rabobank.com/en/home/index.html)** - *Dutch multinational banking and financial services company. Food and agribusiness constitute the primary international focus of the Rabobank.*

  Significant parts of DeTT&CT have been developed in the time that we worked as contractors at Rabobank.
- **[Cyber Security Sharing & Analytics (CSSA)](https://cssa.de/en/index.html#top)** - *Founded in November 2014 by seven major German companies as an alliance for jointly facing cyber security challenges in a proactive, fast and effective manner. Currently, CSSA has 13 member companies.*

  With the financial sponsorship of the CSSA, we added support for [ATT&CK ICS](https://collaborate.mitre.org/attackics/index.php/Main_Page) to DeTT&CT.

- **[Dutch National Police](https://www.politie.nl/en)**. With the financial sponsorship of the Dutch National Police, we added support for ATT&CK Mobile to DeTT&CT.


### Work of others
The work of others inspired some functionality within DeTT&CT:
- Roberto Rodriguez's work on data quality and scoring of MITRE ATT&CK™ techniques ([How Hot Is Your Hunt Team?](https://cyberwardog.blogspot.com/2017/07/how-hot-is-your-hunt-team.html), [Ready to hunt? First, Show me your data!](https://cyberwardog.blogspot.com/2017/12/ready-to-hunt-first-show-me-your-data.html)).
- The MITRE ATT&CK Mapping project on GitHub:
  https://github.com/siriussecurity/mitre-attack-mapping.

### Third party tool: Dettectinator
<i>The Python library to your DeTT&CT YAML files.</i>

Dettectinator is built to be included in your SOC automation tooling. It can be included as a Python library or it can be used via the command line.

Dettectinator provides plugins to read detections from your SIEM or EDR and create/update the DeTT&CT YAML file, so that you can use it to visualize your ATT&CK detection coverage in the ATT&CK Navigator.

More information can be found on Github: [Dettectinator](https://github.com/siriussecurity/dettectinator/).

## Example

YAML files are used for administrating scores and relevant properties. All of which can be visualised by loading JSON layer files into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/#comment_underline=false&metadata_underline=false) (some types of scores and properties can also be exported to Excel).

See below an example of mapping your data sources to ATT&CK, which gives you a rough overview of your visibility coverage:

 <img src="https://raw.githubusercontent.com/wiki/rabobank-cdc/DeTTECT/images/example_data_sources.png" alt="DeTT&CT - Data quality">

\
Using the command `python dettect.py generic -ds`, you can determine which data sources within ATT&CK cover the most techniques. This can, for example, be useful to guide you in identifying which data sources will provide you with a lot of visibility and are hence a good candidate to have available in a SIEM (like) solution.

```
Count  Data Source
--------------------------------------------------
255    Command Execution
206    Process Creation
98     File Modification
88     File Creation
82     Network Traffic Flow
78     OS API Execution
70     Network Traffic Content
58     Windows Registry Key Modification
58     Network Connection Creation
55     Application Log Content
50     Module Load
46     File Access
46     Web [DeTT&CT data source]
37     File Metadata
32     Logon Session Creation
26     Script Execution
22     Response Content
21     Internal DNS [DeTT&CT data source]
20     User Account Authentication
18     Process Access
17     Windows Registry Key Creation
17     Email [DeTT&CT data source]
15     Service Creation
15     Host Status
13     Active Directory Object Modification
12     Service Metadata
11     Process Metadata
10     Driver Load
10     File Deletion
9      Firmware Modification
9      Logon Session Metadata
9      Process Modification
8      User Account Metadata
7      Windows Registry Key Access
7      Scheduled Job Creation
7      Malware Metadata
7      Active Directory Credential Request
6      Container Creation
6      Web Credential Usage
6      Response Metadata
6      User Account Creation
6      Drive Modification
6      User Account Modification
5      Instance Creation
5      Active DNS
5      Passive DNS
5      Network Share Access
5      Drive Access
5      Service Modification
4      Image Creation
4      Instance Start
4      Active Directory Object Creation
4      Malware Content
4      Social Media
4      Domain Registration
4      Drive Creation
4      Windows Registry Key Deletion
3      Active Directory Object Access
3      Instance Metadata
3      Container Start
3      Web Credential Creation
3      Firewall Rule Modification
3      Firewall Disable
3      Instance Deletion
3      Snapshot Creation
3      Process Termination
2      Cloud Storage Enumeration
2      Cloud Storage Access
2      Pod Metadata
2      Active Directory Object Deletion
2      Cloud Service Modification
2      Cloud Service Disable
2      Certificate Registration
2      Cloud Storage Metadata
2      Instance Modification
2      Instance Stop
2      Firewall Metadata
2      Firewall Enumeration
2      Group Enumeration
2      Group Metadata
2      Image Metadata
2      Scheduled Job Metadata
2      Scheduled Job Modification
2      Kernel Module Load
2      WMI Creation
2      Group Modification
2      Driver Metadata
2      Snapshot Modification
2      Snapshot Deletion
2      Volume Deletion
2      Cloud Storage Modification
2      Cloud Service Enumeration
1      Cluster Metadata
1      Container Enumeration
1      Container Metadata
1      Pod Enumeration
1      Pod Creation
1      Pod Modification
1      Instance Enumeration
1      Snapshot Metadata
1      Snapshot Enumeration
1      Volume Metadata
1      Volume Enumeration
1      Named Pipe Metadata
1      User Account Deletion
1      Image Modification
1      Volume Creation
1      Volume Modification
1      Cloud Storage Creation
1      Cloud Service Metadata
1      Image Deletion
1      Cloud Storage Deletion
1      DHCP [DeTT&CT data source]
```

## Installation and requirements

See our GitHub Wiki: [Installation and requirements](https://github.com/rabobank-cdc/DeTTECT/wiki/Installation-and-requirements).

## License: GPL-3.0
[DeTT&CT's GNU General Public License v3.0](https://github.com/rabobank-cdc/DeTTECT/blob/master/LICENSE)
