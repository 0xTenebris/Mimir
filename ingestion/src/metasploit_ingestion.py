import requests
import pandas as pd 
import numpy as np 
import os 
from pathlib import Path
path = Path(__file__).resolve().parent.parent


url = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
resp = requests.get(url)
data = resp.json()

df = pd.DataFrame.from_dict(data, orient='index')

df = df.reset_index()
df = df.rename(columns={'index':'module_path'})
print(len(df))
df= df.dropna(subset=['references'])

df = df[df['references'].str.len() > 0]
df=df.rename(columns={'references':"cve_id"})
df=df.explode('cve_id')
df=df[df['cve_id'].str.match(r'^CVE-\d{4}-\d+$')]
func=lambda df: {'count':len(df),'modules':df[['module_path','name','rank','type']].to_dict('records')}
df=df.groupby('cve_id').apply(func)
df = df.apply(pd.Series).reset_index()
print(df.head())
print(df.columns.to_list())

df.to_json(path/"data"/"normalised"/"metasploit.jsonl",orient='records',lines=True)