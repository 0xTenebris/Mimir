import pandas as pd
from pathlib import Path


path=Path(__file__).resolve().parent.parent / "data"
# load all 5 into dataframes
nvd_df = pd.read_json(path/"nvd_data.jsonl", lines=True)
epss_df = pd.read_json(path/"epss_data.jsonl", lines=True)
kev_df = pd.read_json(path/"kev_data.jsonl", lines=True)
exploitdb_df = pd.read_json(path/"exploitdb_data.jsonl", lines=True)
exploitdb_df['exploits'] = exploitdb_df['exploits'].apply(
    lambda exps: [
        {"source": "exploit-db", "ref": f"https://www.exploit-db.com/exploits/{e['id']}",
         "rank": None, "type": e['type'], "platform": e['platform'],
         "date_published": e['date_published']}
        for e in exps
    ]
)
exploitdb_df = exploitdb_df[['cve_id', 'exploits']]


metasploit_df = pd.read_json(path/"metasploit_data.jsonl", lines=True)
metasploit_df['exploits'] = metasploit_df['modules'].apply(
    lambda mods: [
        {"source": "metasploit", "ref": m['module_path'], "rank": m['rank'],
         "type": None, "platform": None, "date_published": None}
        for m in mods
    ]
)
metasploit_df = metasploit_df[['cve_id', 'exploits']]

# left-join chain, NVD as anchor
merged = nvd_df.merge(epss_df[['cve_id','epss','percentile']].rename(columns={'epss':'epss_score'}), on='cve_id', how='left')
merged = merged.merge(kev_df[['cve_id','date']].rename(columns={'date':'kev_date'}), on='cve_id', how='left')

print(len(merged))  # should match the row count from before this merge — left join on cve_id shouldn't add rows

merged=merged.merge(exploitdb_df[['cve_id','exploits']].rename(columns={'exploits':'edb_exploits'}),on="cve_id",how="left")


 # should match the row count from before this merge — left join on cve_id shouldn't add rows

merged=merged.merge(metasploit_df[['cve_id','exploits']].rename(columns={'exploits':'msf_exploits'}),on='cve_id',how='left')



# fill in_kev bool default False where no KEV match
merged['in_kev']=merged['kev_date'].notna()
print(len(merged)) 

#combining the exploit list as one 
def combined_exploits(row):
    edb=row['edb_exploits'] if isinstance(row['edb_exploits'],list) else []
    msf=row['msf_exploits'] if isinstance(row['msf_exploits'],list) else []
    return msf+edb

merged['exploits']=merged.apply(combined_exploits,axis=1)
merged['exploit_count'] = merged['exploits'].apply(len)
merged['exploit_available'] = merged['exploit_count'] > 0
merged = merged.drop(columns=['edb_exploits', 'msf_exploits'])

# resolve exploit_available/source/ref precedence (metasploit > exploit-db)
# write out as JSONL matching schema.md's Joined CVE Store Record
merged.to_json(path/"processed" / "joined_cve_store.jsonl", orient="records", lines=True)