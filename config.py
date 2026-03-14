# ─────────────────────────────────────────────
#  RedVect0r — Central Configuration
# ─────────────────────────────────────────────

# ── Threading ────────────────────────────────
THREADS = 20
TIMEOUT = 10          # seconds, used for HTTP requests / resolver

# ── Subdomain Enumeration ─────────────────────
SUBFINDER_TIMEOUT = 120   # seconds before subfinder is killed

# ── Port Scanning ─────────────────────────────
NMAP_ARGS       = "-T4 --top-ports 100"
NMAP_FULL_ARGS  = "-T4 -p-"

# ── HTTP Probing ──────────────────────────────
HTTP_TIMEOUT    = 5
USER_AGENT      = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
INTERESTING_STATUS_CODES = {200, 201, 301, 302, 401, 403, 405, 500}

# ── Endpoint Checking ─────────────────────────
COMMON_ENDPOINTS = [
    "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env",
    "/admin", "/admin/login", "/login", "/dashboard",
    "/api", "/api/v1", "/api/v2", "/swagger", "/swagger-ui.html",
    "/openapi.json", "/graphql", "/config", "/backup",
    "/wp-admin", "/wp-login.php", "/phpmyadmin",
    "/server-status", "/server-info", "/.htaccess",
    "/web.config", "/crossdomain.xml", "/security.txt",
    "/.well-known/security.txt", "/actuator", "/actuator/health",
    "/actuator/env", "/console", "/manager/html",
    "/xmlrpc.php", "/README.md", "/CHANGELOG.md",
]

# ── WAF Detection ─────────────────────────────
WAF_PAYLOAD = "<script>alert('waf-probe')</script>"

WAF_SIGNATURES = {
    "Cloudflare":       ["cloudflare", "__cfduid", "cf-ray"],
    "AWS WAF":          ["x-amzn-requestid", "awselb", "x-amz-cf-id"],
    "Akamai":           ["akamai", "akamaighost", "x-akamai-transformed"],
    "Imperva/Incapsula":["x-iinfo", "x-cdn=incapsula", "incap_ses"],
    "Sucuri":           ["x-sucuri-id", "sucuri"],
    "Barracuda":        ["barra_counter_session", "barracudabypass"],
    "F5 BIG-IP ASM":    ["ts=", "f5-trafficshield", "bigipserver"],
    "Fortinet":         ["fortigate", "fortiwafsid"],
    "ModSecurity":      ["mod_security", "modsecurity", "owasp crs"],
    "Wordfence":        ["wordfence"],
    "Reblaze":          ["rbzid", "reblaze"],
    "Nginx":            ["nginx"],
}

# ── DNS Enumeration ───────────────────────────
DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]

# ── Subdomain Takeover ────────────────────────
TAKEOVER_SIGNATURES = {
    "github.io":             "There isn't a GitHub Pages site here",
    "herokuapp.com":         "No such app",
    "s3.amazonaws.com":      "NoSuchBucket",
    "amazonaws.com":         "NoSuchBucket",
    "netlify.app":           "Not Found - Request ID",
    "netlify.com":           "Not Found - Request ID",
    "myshopify.com":         "Sorry, this shop is currently unavailable",
    "azurewebsites.net":     "404 Web Site not found",
    "ghost.io":              "The thing you were looking for is no longer here",
    "surge.sh":              "project not found",
    "bitbucket.io":          "Repository not found",
    "fastly.net":            "Fastly error: unknown domain",
    "helpscoutdocs.com":     "No settings were found for this company",
    "zendesk.com":           "Help Center Closed",
    "uservoice.com":         "This UserVoice subdomain is currently available",
    "tumblr.com":            "There's nothing here",
    "wpengine.com":          "The site you were looking for couldn't be found",
    "readme.io":             "Project doesnt exist",
    "statuspage.io":         "Better Uptime",
    "unbouncepages.com":     "The requested URL was not found",
    "freshdesk.com":         "There is no helpdesk here",
    "pingdom.com":           "Sorry, couldn't find the status page",
    "tenderapp.com":         "Tender no longer exists",
    "teamwork.com":          "Oops - We didn't find your site",
    "hubspot.com":           "does not exist",
    "pantheon.io":           "The gods are wise",
    "webflow.io":            "The page you are looking for doesn't exist",
}

# ── CORS Check ────────────────────────────────
CORS_TEST_ORIGIN = "https://evil.com"

# ── SSL / TLS ─────────────────────────────────
SSL_WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "ADH", "AECDH", "MD5"
]
SSL_EXPIRY_WARN_DAYS = 30

# ── Open Redirect ─────────────────────────────
OPEN_REDIRECT_PARAMS  = [
    "next", "url", "redirect", "return", "returnUrl",
    "goto", "target", "redir", "redirect_uri", "callback",
    "continue", "destination", "forward", "location", "link",
    "to", "out", "view", "dir",
]
OPEN_REDIRECT_PAYLOAD = "https://evil.com"

# ── Screenshots ───────────────────────────────
SCREENSHOT_TIMEOUT = 15   # seconds per page load before giving up

# ── Risk Scoring ──────────────────────────────
RISK_WEIGHTS = {
    "open_port_critical":     15,
    "open_port_medium":        5,
    "sensitive_endpoint":     20,
    "no_https":               10,
    "waf_absent":              5,
    "tech_disclosed":          5,
    "status_500":             10,
    "auth_bypass_hint":       25,
    "subdomain_takeover":     80,
    "cors_with_credentials":  35,
    "cors_reflect":           20,
    "ssl_expired":            25,
    "ssl_expiring_soon":      10,
    "ssl_weak_cipher":        15,
    "open_redirect":          15,
}

CRITICAL_PORTS = {22, 23, 3389, 5900, 21, 1433, 3306, 5432, 6379, 27017}

SENSITIVE_PATHS = {
    "/.env", "/.git/HEAD", "/backup", "/config",
    "/web.config", "/actuator/env", "/server-status",
    "/phpmyadmin", "/wp-login.php",
}

# ── Reporting ─────────────────────────────────
# OUTPUT_DIR is intentionally NOT set here.
# reporter.py resolves it at runtime:
#   • defaults to  <cwd>/output
#   • overridden by --output <dir> flag
REPORT_FORMATS = ["txt", "json"]