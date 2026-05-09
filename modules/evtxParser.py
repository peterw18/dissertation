import Evtx.Evtx as evtx
import pandas as pd
from pathlib import Path
import logging as lg
from lxml import etree

def extract_evtx(filename):
    with evtx.Evtx(filename) as log_file:
        for record in log_file.records():
            raw_xml = record.xml()
            clean_xml = raw_xml.replace('\x00', '')
            try:
                yield etree.fromstring(clean_xml.encode("utf-8"))
            except etree.XMLSyntaxError:
                continue

def collate_lxml(generator):
    logs = []
    for record in generator:
        thisRecordObj = {}
        for cmpt in record.iterchildren():
            tagName = cmpt.tag.split("}")[-1]
            processed = _process_element(cmpt, parent_tag=tagName)
            thisRecordObj[tagName] = processed
        logs.append(thisRecordObj)
    return logs

def _process_element(element, parent_tag=None):
    """Process an XML element, capturing attributes and children"""
    tagName = element.tag.split("}")[-1]
    res = {}
    
    # 1. Capture attributes directly as keys
    for attr, val in element.attrib.items():
        res[attr] = val
    
    # 2. Handle Children
    if len(element) > 0:
        for child in element.iterchildren():
            child_tag = child.tag.split("}")[-1]
            
            # Only use 'Name' attribute as key for EventData/UserData elements
            # For System elements, always use the tag name
            if parent_tag in ['EventData', 'UserData'] and 'Name' in child.attrib:
                key = child.attrib['Name']
            else:
                key = child_tag
            
            child_value = _process_element(child, parent_tag=child_tag)
            
            if key in res:
                if not isinstance(res[key], list):
                    res[key] = [res[key]]
                res[key].append(child_value)
            else:
                res[key] = child_value
    
    # 3. Handle Text Content
    if element.text and element.text.strip():
        text_val = element.text.strip()
        if not res:
            # If there are no attributes or children, just return the text
            return text_val
        # If there are attributes/children, add text as 'value'
        res['value'] = text_val
    
    return res if res else None

def flatten_dict(d, parent_key='', sep='.'):
    """Recursively flatten nested dictionaries"""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            # Recursively flatten nested dicts
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            # Convert lists to strings or handle first element
            if len(v) == 1 and isinstance(v[0], dict):
                items.extend(flatten_dict(v[0], new_key, sep=sep).items())
            else:
                items.append((new_key, str(v)))
        else:
            items.append((new_key, v))
    return dict(items)

def json_to_csv(json_data, csv_file, logger):
    Path(csv_file).parent.mkdir(parents=True, exist_ok=True)
    flattened_records = [flatten_dict(record) for record in json_data]
    df = pd.DataFrame(flattened_records)
    df.to_csv(csv_file, index=False)
    logger.info(f"Converted {len(flattened_records)} records to {csv_file}")

def parseEVTX(filename:str, outputfile:str, logger:lg.Logger):
    log_data = collate_lxml(extract_evtx(filename))
    json_to_csv(log_data, outputfile, logger)