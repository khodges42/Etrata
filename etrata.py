from collections import defaultdict
import glob, json
import numpy as np
from IPython.display import clear_output
from bisect import bisect_left
from itertools import chain
import os.path

# Data found here https://nvd.nist.gov/vuln/data-feeds#JSON_FEED

class Vulndb:
    def __init__(self, loadfile_path='data/*.json',
                 save_sdb='searchdb.json', rebuild=False):
        self.data = []
        self.searchdb = None
        self.save_sdb=save_sdb
        if not rebuild or os.path.isfile(self.save_sdb):
            self.load_saved_dbs()
        else:
            self.load_data(loadfile_path)
            self.build_searchdb()
            self.save_dbs()
        
    def load_data(self, loadfile_path):
        dataset = []
        for idx, file in enumerate(glob.glob(loadfile_path)):
            clear_output(wait=True)
            print("Processing data {}%".format(np.round(idx/len(glob.glob(loadfile_path)))*100))
            with open(file) as json_file:
                dataset[0:0] = json.load(json_file)['CVE_Items']
        print("load finished")
        self.data = dataset

    def build_searchdb(self):
        nested_dict = lambda:defaultdict(nested_dict)
        searchdb = nested_dict()
        dtlength = len(self.data)
        for idx, item in enumerate(self.data):
            if idx%10 == 0:
                clear_output(wait=True)
                print("Processing search graph {}%".format(np.round(idx/dtlength)*100))
            for vendor in item['cve']['affects']['vendor']['vendor_data']:
                for product in vendor['product']['product_data']:
                    for version in product['version']['version_data']:
                        if not searchdb[product['product_name']]['{}_{}'.format(
                            version['version_affected'], version['version_value'])]:
                            searchdb[product['product_name']]['{}_{}'.format(
                            version['version_affected'], version['version_value'])] = [item['cve']['CVE_data_meta']['ID']]
                        else:
                            searchdb[product['product_name']]['{}_{}'.format(
                            version['version_affected'], version['version_value'])].append(
                                item['cve']['CVE_data_meta']['ID'])
        self.searchdb = searchdb
        
    def save_dbs(self):
        with open(self.save_sdb, 'w+') as f:
            print("Writing Search DB")
            f.write(json.dumps(self.searchdb))
            
    def load_saved_dbs(self):
        print("Loading data")
        with open(self.save_sdb, 'r') as f:
            self.searchdb = json.load(f)
            
    def version_lt_search(self, target, versions):
        ltversions = [vs[3:] for vs in versions if vs.startswith("<=_")]
        ltversions.append(target)
        svers = sorted(ltversions, key=lambda v: [int(i) for i in v.rstrip('@').split('.')])
        return ["<=_{}".format(s) for s in svers[svers.index(target)+1:]]
        
    def search_vuln(self, software, version=None):
        matches = []
        software = software.lower()
        if software in self.searchdb:
            versions = self.searchdb[software].keys()
            # match any
            if "=_*" in versions:
                matches.append(self.searchdb[software]["=_*"])
            # match exact
            if version and "=_{}".format(version) in versions:
                matches.append(self.searchdb[software]["=_{}".format(version)])
            # match less than
            if version:
                try:
                    ltmatches = self.version_lt_search(version, versions)
                    for m in ltmatches:
                        matches.append(self.searchdb[software][m])
                except ValueError:
                    pass
        return set(chain.from_iterable(matches))
    
    def python_requirements_parse(self, filename):
        reponame=re.compile('^[\w]+')
        version=re.compile('(\d+\.)?(\d+\.)?(\*|\d+)$')
        with open(filename, 'r') as f:
            reqs=f.readlines()
        for line in reqs:
            if len(line) > 1:
                repo = re.search(reponame, line)
                vs = re.search(version, line)
                if repo and vs:
                    vulnlist = self.search_vuln(repo.group(0), vs.group(0))
                    if not vulnlist:
                        vulnlist = "✓"
                    print("    {} {} : {}".format(repo.group(0), str(vs.group(0)), vulnlist))
