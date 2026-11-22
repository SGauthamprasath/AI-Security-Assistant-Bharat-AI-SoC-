#!/usr/bin/env python3
"""Download the public datasets used for training/evaluation into data/raw/.   python3 data/fetch_data.py

Training/eval data is needed only to RE-TRAIN. The shipped models in models/ run without any of it.

| file | what | licence / source |
|---|---|---|
| sms_uci.tsv | UCI SMS Spam Collection (via public mirror) | CC BY 4.0, Almeida & Hidalgo |
| phishing_links_active.txt | Phishing.Database active phishing links | MIT, mitchellkrogza/Phishing.Database |
| opendns_top.txt | OpenDNS top domains (independent benign check) | public-domain-lists, CC0 |
| tranco_top1m.csv | Tranco top-1M ranking (benign hosts, trusted allow-list) | tranco-list.eu, free for research |
| KDDTrain+.txt, KDDTest+.txt | NSL-KDD intrusion-detection data | UNB, public research data |
| smishing_imc25.csv | MANUAL: user-reported smishing, Agarwal et al., "Fishing for Smishing", ACM IMC 2025 (CC BY 4.0) | obtain from the paper's artefact link (doi 10.1145/3730567.3764431) and save here |
"""
import io
import os
import sys
import urllib.request
import zipfile

RAW = os.path.join(os.path.dirname(os.path.abspath(__file__)), "raw")
G = "https://raw.githubusercontent.com"
FILES = {
    "sms_uci.tsv": G + "/justmarkham/pycon-2016-tutorial/master/data/sms.tsv",
    "phishing_links_active.txt": G + "/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "opendns_top.txt": G + "/opendns/public-domain-lists/master/opendns-top-domains.txt",
    "KDDTrain+.txt": G + "/defcom17/NSL_KDD/master/KDDTrain%2B.txt",
    "KDDTest+.txt": G + "/defcom17/NSL_KDD/master/KDDTest%2B.txt",
}


def get(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def main():
    os.makedirs(RAW, exist_ok=True)
    for name, url in FILES.items():
        dst = os.path.join(RAW, name)
        if os.path.exists(dst) and os.path.getsize(dst) > 1000:
            print("have", name)
            continue
        print("fetching", name)
        open(dst, "wb").write(get(url))
    dst = os.path.join(RAW, "tranco_top1m.csv")
    if not os.path.exists(dst):
        print("fetching tranco_top1m.csv")
        z = zipfile.ZipFile(io.BytesIO(get("https://tranco-list.eu/top-1m.csv.zip")))
        open(dst, "wb").write(z.read("top-1m.csv"))
    if not os.path.exists(os.path.join(RAW, "smishing_imc25.csv")):
        print("\nMANUAL STEP: save the IMC'25 smishing reports as data/raw/smishing_imc25.csv (see this file's docstring).")
        sys.exit(1)
    print("all datasets present")


if __name__ == "__main__":
    main()
