<img src="https://github.com/rabobank-cdc/Blue-ATTACK/wiki/images/logo.png" alt="Blue ATT&CK" width=20% height=20%>

# Blue ATT&CK
#### Mapping your blue team to ATT&CK

To get started with Blue ATT&CK, check out the
[Wiki](https://github.com/rabobank-cdc/Blue-ATTACK/wiki/Getting-started).

Blue ATT&CK will help blue teams in scoring and comparing data source quality, visibility coverage, detection coverage and threat actor behaviours. The Blue ATT&CK framework consists of a Python tool, YAML administration files and [scoring tables](https://github.com/rabobank-cdc/Blue-ATTACK/raw/master/scoring_table.xlsx) for the different aspects.

Blue ATT&CK will help you to:

- Administrate and score the quality of your data sources.
- Get insight on the visibility you have on for example endpoints.
- Map your detection coverage.
- Map threat actor behaviours.
- Compare visibility, detections and threat actor behaviours in order to uncover possible improvements in detection and visibility. This can help you to prioritise your blue teaming efforts.

The colored visualisations are created using MITRE's [ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator) .

## Authors and contribution
This project is developed and maintained by [Marcus Bakker](https://github.com/marcusbakker) (Twitter: [@bakker3m](https://twitter.com/bakk3rm)) and [Ruben Bouman](https://github.com/rubinatorz) (Twitter: [@rubenb_2](https://twitter.com/rubenb_2/)). Feel free to contact, DMs are open.

We welcome contributions! Contributions can be both in code, as well as in ideas you might have for further development, usability improvements, etc.

### Work of others
Some functionality within Blue ATT&CK was inspired by work of
others:
- Roberto Rodriguez's work on data quality and scoring of ATT&CK techniques ([How Hot Is Your Hunt Team?](https://cyberwardog.blogspot.com/2017/07/how-hot-is-your-hunt-team.html), [Ready to hunt? First, Show me your data!](https://cyberwardog.blogspot.com/2017/12/ready-to-hunt-first-show-me-your-data.html)).
- The MITRE ATT&CK Mapping project on GitHub:
  https://github.com/siriussecurity/mitre-attack-mapping.

## Example

YAML files are used for administrating scores and relevant metadata. All
of which can be visualised by loading JSON layer files into the [ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator) (some types of scores and metadata can also be written to Excel).

See below an example of mapping your data sources to ATT&CK which gives you a rough overview of your visibility coverage:

<img src="https://github.com/rabobank-cdc/Blue-ATTACK/wiki/images/example_data_sources.png" alt="Blue ATT&CK"><br>


## Installation and requirements

See our GitHub Wiki: [Installation and requirements](https://github.com/rabobank-cdc/Blue-ATTACK/wiki/Installation-and-requirements).

## Future developments

-  Add more graphs:
   - [ ]  Detections: improvement based on newly added detections and improvements on the level/score of existing detections. Possibly with a changelog.
   - [ ]  Visibility: improvement in the quality of an existing data source.
- Groups:
  - [ ]   Have a group YAML file type that contains a count on how popular a certain technique is. This can be very useful to map things such as Red Canary's [Threat Detection Report 2019](https://redcanary.com/resources/guides/threat-detection-report/).
- Excel output for:
   - [ ]  Techniques administration YAML file: visibility coverage.
   - [ ]  Techniques administration YAML file: detection coverage.
- Data quality Excel sheet:
  - [ ]  Add colors to the data quality scores in the Excel sheet.
- YAML files:
  - [ ]  Create an option within the tool to migrate an old administration YAML file version to a new version (such as adding specific key-value pairs).
- MITRE ATT&CK updates
  - [ ]  Have a smart way of knowing what to update in your data source and technique administration files once MITRE publishes updates.
  - [ ]  Data sources: check for missing data sources in data sources administration files.
- Minimal visibility
  - [ ]  Integrate information into the framework on what a minimal set of visibility for a technique should be, before you can say to have useful visibility (e.g. technique X requires at least to have visibility on process monitoring, process command line monitoring and DLL monitoring).

## License: GPL-3.0
[Blue ATT&CK's GNU General Public License v3.0](https://github.com/rabobank-cdc/Blue-ATTACK/blob/master/LICENSE)

