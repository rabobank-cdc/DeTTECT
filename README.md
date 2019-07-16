<img src="https://github.com/rabobank-cdc/DeTTECT/wiki/images/logo.png" alt="DeTT&CT" width=30% height=30%>

#### Detect Tactics, Techniques & Combat Threats
Latest version: [1.1.2](https://github.com/rabobank-cdc/DeTTECT/wiki/Changelog#version-112)

To get started with DeTT&CT, check out the
[Wiki](https://github.com/rabobank-cdc/DeTTECT/wiki/Getting-started).

DeTT&CT aims to assist blue teams using ATT&CK to score and compare data log source quality, visibility coverage, detection coverage and threat actor behaviours. All of which can help, in different ways, to get more resilient against attacks targeting your organisation. The DeTT&CT framework consists of a Python tool, YAML administration files and [scoring tables](https://github.com/rabobank-cdc/DeTTECT/raw/master/scoring_table.xlsx) for the different aspects.

DeTT&CT provides the following functionality:

- Administrate and score the quality of your data sources.
- Get insight on the visibility you have on for example endpoints.
- Map your detection coverage.
- Map threat actor behaviours.
- Compare visibility, detections and threat actor behaviours to uncover possible improvements in detection and visibility. This can help you to prioritise your blue teaming efforts.

The coloured visualisations are created with the help of MITRE's [ATT&CK™ Navigator](https://github.com/mitre-attack/attack-navigator).

## Authors and contribution
This project is developed and maintained by [Marcus Bakker](https://github.com/marcusbakker) (Twitter: [@bakk3rm](https://twitter.com/bakk3rm)) and [Ruben Bouman](https://github.com/rubinatorz) (Twitter: [@rubenb_2](https://twitter.com/rubenb_2/)). Feel free to contact, DMs are open.

We welcome contributions! Contributions can be both in code, as well as in ideas you might have for further development, usability improvements, etc.

### Work of others
Some functionality within DeTT&CT was inspired by the work of
others:
- Roberto Rodriguez's work on data quality and scoring of MITRE ATT&CK™ techniques ([How Hot Is Your Hunt Team?](https://cyberwardog.blogspot.com/2017/07/how-hot-is-your-hunt-team.html), [Ready to hunt? First, Show me your data!](https://cyberwardog.blogspot.com/2017/12/ready-to-hunt-first-show-me-your-data.html)).
- The MITRE ATT&CK Mapping project on GitHub:
  https://github.com/siriussecurity/mitre-attack-mapping.

## Example

YAML files are used for administrating scores and relevant metadata. All
of which can be visualised by loading JSON layer files into the [ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator) (some types of scores and metadata can also be written to Excel).

See below an example of mapping your data sources to ATT&CK, which gives you a rough overview of your visibility coverage:

 <img src="https://raw.githubusercontent.com/wiki/rabobank-cdc/DeTTECT/images/example_data_sources.png" alt="DeTT&CT - Data quality">


## Installation and requirements

See our GitHub Wiki: [Installation and requirements](https://github.com/rabobank-cdc/DeTTECT/wiki/Installation-and-requirements).


## License: GPL-3.0
[DeTT&CT's GNU General Public License v3.0](https://github.com/rabobank-cdc/DeTTECT/blob/master/LICENSE)
