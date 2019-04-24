#!/bin/bash
mkdir -p data

if ! [ -x "$(command -v pip)" ]; then
  echo 'Error: pip is not installed.' >&2
  exit 1
fi

i=2009
end=2019
while [ $i -le $end ]; do
    wget https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-${i}json.zip -O ${i}.zip; unzip ${i}.zip -d data/; rm temp.zip
    i=$(($i+1))
done

pip install -r requirements.txt
