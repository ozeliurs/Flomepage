import subprocess

import requests

from urllib.parse import urlencode

import whois


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
        elif self.config["type"] == "domains":
            return self.render_domains()
        elif self.config["type"] == "ping":
            return self.render_ping()
        else:
            return """<div class="elem-link is-vertical-align"><i class="fas fa-exclamation-triangle fa-2xl"></i>Invalid Widget Type</div>"""

    def render_link(self):
        return f"""<a href="{self.config['link']}" class="elem link is-vertical-align" target="_blank" rel="nofollow"><i class="{self.config['icon']} fa-2xl"></i>{self.config['title']}</a>"""

    def render_cve(self):
        kwargs = {
            "orderby": self.config["orderby"] if "orderby" in self.config else 1,
            "numrows": self.config["limit"] if "limit" in self.config else 5,
            "cvssscoremin": self.config["min_score"] if "min_score" in self.config else None,
            "vendor_id": self.config["vendor_id"] if "vendor_id" in self.config else None,
            "product_id": self.config["product"] if "product" in self.config else None,
            "hasexp": self.config["has_exploit"] if "has_exploit" in self.config else None
        }

        kwargs = {k: v for k, v in kwargs.items() if v is not None}

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
            <a href="https://www.explainxkcd.com/wiki/index.php/{xkcd['num']}"><img src="{xkcd['img']}" alt="{xkcd['alt']}" /></a>
        </div>"""

    def render_ip(self):
        return """<div class="elem ip">
            <h4><span id="ip">IP</span>  <img id="flag" style="height: 1.5rem"></h4>
            <p style="margin: 0;"><span id="city">Country</span>, <span id="region">Region</span></p>
            <p><span id="org">Organization</span> - <span id="asn">ASN</span></p>
        </div>
        <script>
            fetch("http://ip-api.com/json/")
                .then(response => response.json())
                .then(data => {
                    document.getElementById("ip").innerHTML = data.query;
                    document.getElementById("city").innerHTML = data.city;
                    document.getElementById("region").innerHTML = data.region;
                    document.getElementById("org").innerHTML = data.org;
                    document.getElementById("asn").innerHTML = data.as;
                    document.getElementById("flag").src = `https://flagcdn.com/64x48/${data.countryCode.toLowerCase()}.png`;
                });
        </script>"""

    def render_domains(self):
        domains = []

        for domain in self.config["domains"]:
            try:
                site = whois.query(domain)

                domains.append(f"""<div>
                <p><span class="h5">{site.name}</span> <span class="tag is-small">{site.registrar}</span></p>
                <p><code class="tag is-small">{site.creation_date}</code> to <code style="margin-left: 0px" class="tag is-small">{site.expiration_date}</code></p>
                <code class="small_p">{", ".join(site.name_servers)}</code>
                
                </div>""")
            except Exception as e:
                print(e)
                domains.append(f"""<div><h5>{domain}</h5><p class="small_p">{e}</p></div>""")

        return f"""<div class="elem domains"><h4>Domains</h4>{"<hr>".join(domains)}</div>"""

    def render_ping(self):
        # use subprocess to ping
        req = subprocess.run(["ping", "-c", "1", self.config["ip"]],
                             stdout=subprocess.PIPE)

        # if ping fails, return error
        if req.returncode != 0:
            return f"""<a href="https://{self.config['ip']}/" class="elem ping is-vertical-align" target="_blank" rel="nofollow"><i class="fas fa-xmark fa-2xl"></i>{self.config['ip']}</a>"""

        latency = req.stdout.splitlines()[-1].decode().split(" ")[-2].split("/")[1]
        return f"""<a href="https://{self.config['ip']}/" class="elem ping is-vertical-align" target="_blank" rel="nofollow"><i class="fas fa-check fa-2xl"></i>{self.config['ip']} ({latency} ms)</a>"""
