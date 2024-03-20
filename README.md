# temurin-vdr-generator
Scripts for generating Vulnerability Disclosure Reports


Currently the VDR is generated by aggregating data from 2 sources: the OpenJDK Vulnerability Group and the NIST API.
We use `ojvg_download.py` to download data from OpenJDK Vulnerability Group, and parse it into a more machine readable format .
We use `ojvg_convert.py` to generate CycloneDX format objects, enhance with data from NIST, and generate a vdr, which is saved in `data/vdr.json`

### Installation
To install the requirements:

`python3 -m pip install -r requirements.txt`

### Tests
There are some tests, in order to run them, you can do: 

`python3 -m pytest`

