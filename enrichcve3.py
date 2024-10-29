import requests
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Replace 'YOUR_API_KEY' with your actual NVD API key
API_KEY = 'c56b7f35-2d4e-4c4d-af3a-c6391645eede'

def get_cve_details(cve_id):
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {
        'apiKey': API_KEY
    }
    response = requests.get(nvd_url, headers=headers)

    if response.status_code != 200:
        logger.error(f"Failed to fetch CVE details for {cve_id}. HTTP Status Code: {response.status_code}")
        logger.error(f"URL: {nvd_url}")
        return {"error": f"Failed to fetch CVE details for {cve_id}. HTTP Status Code: {response.status_code}"}

    try:
        cve_data = response.json()
    except requests.exceptions.JSONDecodeError:
        logger.error(f"Error: Unable to parse JSON response for CVE ID {cve_id}")
        logger.info(f"Raw response data: {response.text}")
        return {"error": f"Unable to parse JSON response for CVE ID {cve_id}"}

    if not cve_data.get("vulnerabilities"):
        logger.error(f"No vulnerabilities found for CVE ID {cve_id}")
        return {"error": f"No vulnerabilities found for CVE ID {cve_id}"}

    cve_info = cve_data["vulnerabilities"][0]["cve"]
    description = cve_info.get("descriptions", [{}])[0].get("value", "N/A")
    disputed = "disputed" in description.lower()
    references = cve_info.get("references", [])
    affected_products = [product.get("product", "N/A") for product in cve_info.get("affects", {}).get("vendor", {}).get("vendor_data", [{}])[0].get("product", {}).get("product_data", [{}])[0].get("version", {}).get("version_data", [])]

    cve_details = {
        "id": cve_info.get("id", "N/A"),
        "description": description,
        "disputed": disputed,
        "exploitability_score": cve_info.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("exploitabilityScore", "N/A"),
        "impact_score": cve_info.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("impactScore", "N/A"),
        "cvss_score_v2": cve_info.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("baseScore", "N/A"),
        "cvss_vector_v2": cve_info.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("vectorString", "N/A"),
        "cvss_score_v3": cve_info.get("metrics", {}).get("cvssMetricV3", [{}])[0].get("cvssData", {}).get("baseScore", "N/A"),
        "cvss_vector_v3": cve_info.get("metrics", {}).get("cvssMetricV3", [{}])[0].get("cvssData", {}).get("vectorString", "N/A"),
        "affected_products": affected_products,
        "references": references,
        "source": "NVD",
        "source_link": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    }

    return cve_details

def generate_html(cve_details):
    if "error" in cve_details:
        return f"<html><body><h1>Error</h1><p>{cve_details['error']}</p></body></html>"

    references_html = "".join([f"<li><a href='{ref.get('url', '#')}'>{ref.get('url', 'URL')}</a></li>" for ref in cve_details['references']])
    affected_products_html = ", ".join(cve_details['affected_products'])

    html_content = f"""
    <html>
    <head>
        <title>CVE Details for {cve_details['id']}</title>
    </head>
    <body>
        <h1>CVE Details for {cve_details['id']}</h1>
        <p><strong>Description:</strong> {cve_details['description']}</p>
        <p><strong>Disputed:</strong> {'Yes' if cve_details['disputed'] else 'No'}</p>
        <p><strong>Exploitability Score:</strong> {cve_details['exploitability_score']}</p>
        <p><strong>Impact Score:</strong> {cve_details['impact_score']}</p>
        <p><strong>CVSS v2 Score:</strong> {cve_details['cvss_score_v2']}</p>
        <p><strong>CVSS v2 Vector:</strong> {cve_details['cvss_vector_v2']}</p>
        <p><strong>CVSS v3 Score:</strong> {cve_details['cvss_score_v3']}</p>
        <p><strong>CVSS v3 Vector:</strong> {cve_details['cvss_vector_v3']}</p>
        <p><strong>Affected Products:</strong> {affected_products_html}</p>
        <p><strong>References:</strong></p>
        <ul>{references_html}</ul>
        <p><strong>Source:</strong> <a href="{cve_details['source_link']}">{cve_details['source']}</a></p>
    </body>
    </html>
    """

    return html_content

if __name__ == "__main__":
    cve_id = input("Enter CVE ID: ")
    details = get_cve_details(cve_id)
    html_output = generate_html(details)

    with open(f"{cve_id}.html", "w") as file:
        file.write(html_output)

    print(f"HTML report generated: {cve_id}.html")

