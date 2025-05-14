# About

This project contains a connector to push MISP IOCs to Azure Sentinel. An alternative to <https://github.com/microsoftgraph/security-api-solutions/tree/master/Samples/MISP>. This connector uses the Sentinel API to push the IOCs to Sentinel.

## Crontab example

```bash

WORK_FOLDER=/home/misp-to-sentinel-syncher/misp-to-sentinel-and-defender-connector/
0 * * * * misp-to-sentinel-syncher cd ${WORK_FOLDER} ; export PYTHONPATH=${WORK_FOLDER}/src ; ${HOME}/miniforge3/envs/misp-connector/bin/python -m misp_to_sentinel.main || echo "misp_to_sentinel.main cronjob failed." | mail -s "ERROR: cronjob for misp_to_sentinel connector failed" secops_team@ilo.org
```
