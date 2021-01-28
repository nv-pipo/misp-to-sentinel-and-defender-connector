#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""In-house script for pushing ICC MISP IOCs onto Sentinel and Defender. MS' tool is overly complex and buggy."""

import logging
from misp import get_misp_attributes
from msgraph import MSGraphConnector
from converter import transform_misp_to_msgraph
import config

logging.basicConfig(level=logging.INFO)

def main():
    '''Main script/function of the whole project.'''
    logging.info("Filter start time : %s, filter end time -> %s", config.start, config.end)
    msgraph_connector = MSGraphConnector()
    misp_attributes = get_misp_attributes()
    combined_misp_msgraph_dicts = list(map(lambda misp_attr: transform_misp_to_msgraph(misp_attr, config), misp_attributes))
    transform_counters = {
        'SUCCESS': 0,
        'IGNORED': 0,
        'IGNORE DEFENDER': 0,
        'UNKNOWN': 0,
        'CORRUPT': 0
    }
    push_to_msgraph = 0
    for combined_misp_msgraph_dict in combined_misp_msgraph_dicts:
        transform_counters[combined_misp_msgraph_dict['transform_status']] += 1
        if combined_misp_msgraph_dict['transform_status'] == "SUCCESS":
            msgraph_connector.post_one_ioc_to_graph(combined_misp_msgraph_dict)
            push_to_msgraph += 1 if combined_misp_msgraph_dict['post_status'] == "SUCCESS" else 0

    misp_attrs = len(combined_misp_msgraph_dicts)
    logging.info(
        "(%s, %s, %s, %s, %s, %s) - "
        '(MISP attrs, as MSGraph IOC, pushed to MSGraph, ignored, ignored defender, corrupt/unknown)',
        misp_attrs,
        transform_counters['SUCCESS'],
        push_to_msgraph,
        transform_counters['IGNORED'],
        transform_counters['IGNORE DEFENDER'],
        transform_counters['UNKNOWN']
    )

if __name__ == "__main__":
    main()
