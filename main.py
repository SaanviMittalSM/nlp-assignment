# import requests
# import matplotlib
# import plotly
#
# base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# from urllib.request import urlretrieve
# urlretrieve(base_url, )
import requests
import pandas as pd

# NVD API endpoint
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Parameters for fetching vulnerabilities
params = {
    "keyword": "Apache",  # Focus on Apache vulnerabilities
    "resultsPerPage": 20,  # Fetch 20 vulnerabilities
    "startIndex": 0,
    "pubStartDate": "2023-01-01T00:00:00.000Z",  # Start date for recent vulnerabilities
}

# Fetch data from NVD API
response = requests.get(NVD_API_URL, params=params)
if response.status_code == 200:
       data = response.json()
else:
     raise Exception(f"Failed to fetch data: {response.status_code}")

# Extract CVE details
records = []

for item in data.get("vulnerabilities", []):
    cve = item.get("cve", {})
    configurations = item.get("configurations", [])
    references = cve.get("references", [])

    # Extract affected versions from CPE
    affected_versions = []
    fixed_versions = []

    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpe_match", []):
                if match.get("vulnerable", False):
                    cpe_uri = match.get("cpe23Uri", "")
                    version = cpe_uri.split(":")[5]  # Extract version from CPE URI
                    affected_versions.append(version)
                else:
                    cpe_uri = match.get("cpe23Uri", "")
                    version = cpe_uri.split(":")[5]
                    fixed_versions.append(version)

    # If fixed versions not in CPE, check references for advisories
    advisory_links = [ref.get("url", "") for ref in references if "advisory" in ref.get("tags", [])]

    records.append({
        "CVE ID": cve.get("id"),
        "Description": cve.get("descriptions", [{}])[0].get("value", "No description available"),
        "Affected Versions": ", ".join(set(affected_versions)) if affected_versions else "Not specified",
        "Fixed Versions": ", ".join(set(fixed_versions)) if fixed_versions else "Refer to advisories",
        "Advisories": ", ".join(advisory_links),
    })

# Create DataFrame
df = pd.DataFrame(records)

# Display or save to CSV
print(df)
df.to_csv("apache_vulnerabilities_with_versions.csv", index=False)


