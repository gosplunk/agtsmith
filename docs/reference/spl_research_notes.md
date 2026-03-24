# SPL Research Notes (Authoritative References)

This note summarizes the key external guidance used to improve SPL quality in this lab.

## Primary References
- Splunk Search Reference (SPL command syntax and command catalog):  
  `https://docs.splunk.com/Documentation/SplunkCloud/latest/SearchReference/`
- `search` command reference (command behavior and syntax):  
  `https://docs.splunk.com/Documentation/Splunk/9.4.2/SearchReference/Search`
- Splunk Search optimization guidance:  
  `https://help.splunk.com/en/splunk-enterprise/search/search-manual/9.1/optimizing-searches/write-better-searches`
- Quick optimization tips (filter early, use indexed/default fields):  
  `https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.0/optimizing-searches/quick-tips-for-optimization`
- Time modifier references:  
  `https://docs.splunk.com/Documentation/SplunkCloud/latest/SearchReference/SearchTimeModifiers`  
  `https://docs.splunk.com/Documentation/Splunk/9.4.2/Search/Specifytimemodifiersinyoursearch`
- Pretrained sourcetypes list:  
  `https://docs.splunk.com/Documentation/Splunk/9.4.2/Data/Listofpretrainedsourcetypes`
- CIM normalization/search-time mapping:  
  `https://help.splunk.com/en/splunk-enterprise/common-information-model/6.1/using-the-common-information-model/use-the-cim-to-normalize-data-at-search-time`

## Practical Rules Applied in This Project
- Filter early with indexed/default fields (`index`, `sourcetype`, `host`, `source`) before expensive transforms.
- Keep time windows explicit (`earliest_time`, `latest_time`) and narrow by default.
- Prefer deterministic field normalization with `coalesce(...)` for mixed Windows/Linux/web data.
- Keep queries read-only and bounded (`row_limit <= 200`).
- Unless explicitly requested, exclude internal indexes by default (`NOT index=_*`).
- Use discovered Data Domain constraints (index+sourcetype inventory) to prevent invalid pairings.
- Use CIM/tag hints as assistive context, but keep deterministic policy gates as final authority.
