import requests
import os
from dataclasses import dataclass, field ,asdict
from datetime import date 
import time
import json
from pathlib import Path
from dotenv import load_dotenv
from pathlib import Path

path=Path(__file__).resolve().parent.parent


env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

api_key = os.environ.get("NVD_API_KEY")
@dataclass
class NvdCveRecord:
    cve_id: str
    description: str
    published: str
    cvss_score: float
    cvss_version: float
    severity: str | None
    cwe_ids: list[str] = field(default_factory=list)
    cpe_list: list[str] = field(default_factory=list)
    vuln_status: str = ""
    last_modified: str | None = None


url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
resultperpage=2000




def fetchpage(startidx: int,resultperpage:int,api_key) -> dict:

    if api_key:
        header={'api_key':api_key}
    else:
        header={}


    params = {"resultsPerPage":resultperpage,"startIndex":startidx}
    response = requests.get(url,params=params,headers=header,timeout=60)
    response.raise_for_status()
    data = response.json()
    return data


def dataparser(data):

    vulndata = data["vulnerabilities"]
    Nvd_record = []

    for item in vulndata:
        cv = NvdCveRecord(
                cve_id="",
                description="",
                published="",
                cvss_score=0.0,
                cvss_version=0.0,
                severity=None,
                last_modified=""
                     )


        cv.cve_id = item["cve"]["id"]
        cv.description = item["cve"]["descriptions"][0]["value"]
        cv.published = item["cve"]["published"]
        metrics=item["cve"].get("metrics",{})
        print(cv.cve_id, metrics.keys())
        for metversion in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"]:
            if metversion in metrics and metrics[metversion]:
                metric2 = metrics[metversion][0]
                cvss_data = metric2.get("cvssData", {})
                cv.cvss_version = cvss_data.get("version")
                cv.cvss_score = cvss_data.get("baseScore")
                cv.severity = metric2.get("baseSeverity")
                break
        cv.cpe_list = []   
        for config in item["cve"].get("configurations", []):
            for nodea in config.get("nodes", []):
                for match in nodea.get("cpeMatch", []):
                    cv.cpe_list.append(match.get("criteria", ""))
      
        cv.cwe_ids = []   
        
        for weakness in item["cve"].get("weaknesses",[]):
            disc=weakness.get("description",[])
            for description in disc:
                if description.get("lang")=="en":
                    cv.cwe_ids.append(description.get("value",""))
        
                

        cv.vuln_status = item["cve"]["vulnStatus"]
        cv.last_modified = item["cve"]["lastModified"]

        Nvd_record.append(cv)
    return Nvd_record

def pagination(resultperpage:int):
    startidx=170000
    delay = 0.6 if api_key else 6.0 
    print("ENV PATH:", env_path)
    print("API KEY LOADED:", bool(api_key))

    while(True):
       
        page=fetchpage(startidx,resultperpage,api_key);
        Totalresult=page["totalResults"]
        
    
        recordobt= dataparser(page)
        with open(path/"data"/"normalised"/"nvd_data.jsonl","a") as f:
            for record in recordobt:
                json.dump(asdict(record),f)
                f.write("\n")
        startidx+=resultperpage ;
        if startidx>=Totalresult :
            break ;

        time.sleep(delay)

pagination(resultperpage)