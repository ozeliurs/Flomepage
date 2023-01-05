import requests

from urllib.parse import urlencode


class Widget:
    def __init__(self, config):
        self.config = config

    def render(self):
        if self.config["type"] == "link":
            return self.render_link()
        elif self.config["type"] == "cve":
            return self.render_cve()
        elif self.config["type"] == "xkcd":
            return self.render_xkcd()
        elif self.config["type"] == "ip":
            return self.render_ip()
        else:
            return """<div class="elem-link is-vertical-align"><i class="fas fa-exclamation-triangle fa-2xl"></i>Invalid Widget Type</div>"""

    def render_link(self):
        return f"""<a href="{self.config['link']}" class="elem link is-vertical-align" target="_blank" rel="nofollow"><i class="{self.config['icon']} fa-2xl"></i>{self.config['title']}</a>"""

    def render_cve(self):
        kwargs = {"orderby": 1}

        if "limit" in self.config:
            kwargs["numrows"] = self.config["limit"]

        if "min_score" in self.config:
            kwargs["cvssscoremin"] = self.config["min_score"]

        if "vendor" in self.config:
            kwargs["vendor_id"] = self.config["vendor_id"]

        if "product" in self.config:
            kwargs["product_id"] = self.config["product_id"]

        if "has_exploit" in self.config:
            kwargs["hasexp"] = self.config["has_exploit"]

        req = requests.get(f"https://www.cvedetails.com/json-feed.php?{urlencode(kwargs)}")

        if not req.ok or not req.json():
            return """<div class="elem-link is-vertical-align"><i class="fas fa-exclamation-triangle fa-2xl"></i>Error with CVE</div>"""

        cves = req.json()
        cve_list = []

        for cve in cves:
            cve_list.append(
                f"""<div>
                    {cve['cvss_score']} - <a href="{cve['url']}" target="_blank" rel="nofollow">{cve['cve_id']}</a> - {cve['summary'][:100]} ...
                </div>"""
            )

        return f"""<div class="elem cve"><h4>CVEs{" (" + str(self.config["min_score"]) + "+)" if "min_score" in self.config else ""}</h4>{"<hr>".join(cve_list)}</div>"""

    def render_xkcd(self):
        req = requests.get("https://xkcd.com/info.0.json")

        if not req.ok or not req.json():
            return """<div class="elem-link is-vertical-align"><i class="fas fa-exclamation-triangle fa-2xl"></i>Error with XKCD</div>"""

        xkcd = req.json()
        return f"""<div class="elem xkcd">
            <h4>{xkcd['title']}</h4>
            <a href="https://xkcd.com/{xkcd['num']}"><img src="{xkcd['img']}" alt="{xkcd['alt']}" /></a>
        </div>"""

    def render_ip(self):
        return """<div class="elem ip">
            <h4><span id="ip">IP</span>  <img id="flag" style="height: 1.5rem"></h3>
            <p style="margin: 0;"><span id="city">Country</span>, <span id="region">Region</span></p>
            <p><span id="org">Organization</span> - <span id="asn">ASN</span></p>
        </div>
        <script>
            fetch("https://ipapi.co/json/")
                .then(response => response.json())
                .then(data => {
                    document.getElementById("ip").innerHTML = data.ip;
                    document.getElementById("city").innerHTML = data.city;
                    document.getElementById("region").innerHTML = data.region;
                    document.getElementById("org").innerHTML = data.org;
                    document.getElementById("asn").innerHTML = data.asn;
                    document.getElementById("flag").src = `https://flagcdn.com/64x48/${data.country_code.toLowerCase()}.png`;
                });
        </script>"""
