import os 
from dataclasses import dataclass ,field ,asdict
import time
import requests
import json
from pathlib import Path

path = Path(__file__).resolve().parent.parent

@dataclass
class epss_obj:
    cve_id:str=""
    epss:float=0.0
    percentile:float=0.0
    date:str=""





def fetchpage(offset:int,limit) ->dict:
    param={"offset":offset,"limit":limit}
    response = requests.get("https://api.first.org/data/v1/epss",params=param,timeout=30)
    response.raise_for_status()  
    print(response.json(),type(response))
    return response.json() 




def parsing(offset,limit):
    epsrecord=[]
    response=fetchpage(offset,limit)
    data=response["data"]
    for item in data:
        epo= epss_obj()
        epo.cve_id=item.get("cve","")
        epo.epss=float(item.get("epss",0.0))
        epo.percentile=float(item.get("percentile",0.0))
        epo.date=item.get("date","")
        epsrecord.append(epo)
    return epsrecord

def pagination():
    offset=0
    limit=3000
    total=fetchpage(1,1).get("total",35000)
    
    while True:
        epss_records=parsing(offset,limit)
        with open(path/"data"/"normalised"/'epss_data.jsonl',"a") as f:
            for item in epss_records:
                 json.dump(asdict(item),f)
                 f.write("\n")
        offset+=limit 
        time.sleep(0.5)
        if offset>=total :
            break
       

pagination()
