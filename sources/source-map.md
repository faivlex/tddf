# Source Map

`source-map.yaml` maps every shipped trap class to its academic sources, benchmark repositories, and import candidates. It tracks license status and attribution requirements so imported payloads carry clear provenance.

The InjecAgent importer (`tddf import injecagent`) was built on top of these mappings. Future importers (AgentDojo, garak) should use the same priority ranking and provenance rules defined here.
