import requests 
from dataclasses import dataclass ,asdict
import os 
import time
import json 
from pathlib import Path

path =Path(__file__).resolve().parent.parent
@dataclass
class KEVdata:
    cve_id:str=""
    date:str=" "



def fetchpage():
    response=requests.get(url='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
    response.raise_for_status()
    return response.json()


def parser():
    kev_RAW_data=fetchpage()
    kev_data=kev_RAW_data["vulnerabilities"]
    with open(path/"data"/"normalised"/"kev_data.jsonl","a") as f:
        for item in kev_data:
            obj=KEVdata() 
            obj.cve_id=item["cveID"]
            obj.date=item["dateAdded"]
        
      
            json.dump(asdict(obj),f)
            f.write("\n")


parser()