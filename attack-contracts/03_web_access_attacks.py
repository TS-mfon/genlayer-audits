# {"Depends": "py-genlayer:test"}
"""
ATTACK VECTOR 3: Web Data Access Exploitation
==============================================
Target: gl.nondet.web.render(), external data dependencies

Threat Model:
  Attacker manipulates external data sources or exploits the web
  fetching mechanism to compromise contract behavior.

Scenarios:
  A) SSRF (Server-Side Request Forgery) - access internal services via validator nodes
  B) DNS rebinding - resolve to internal IPs after initial validation
  C) Data source poisoning - compromise or MitM the data source
  D) TOCTOU (Time-of-Check / Time-of-Use) - data changes between fetch and use
  E) Response bombing - return massive payloads to exhaust resources
  F) Redirect chains - exploit HTTP redirects to reach restricted endpoints
"""

from genlayer import *


# ============================================================================
# ATTACK A: SSRF (Server-Side Request Forgery)
# ============================================================================
class SSRFVulnerableContract(gl.Contract):
    """
    Allows arbitrary URL fetching, enabling SSRF attacks against
    validator node infrastructure.

    Attack: Call fetch_data("http://169.254.169.254/latest/meta-data/")
    to access cloud metadata service from the validator's network.

    Attack: Call fetch_data("http://localhost:6379/INFO") to probe
    internal Redis instances on validator nodes.
    """

    @gl.public.write
    def fetch_data(self, url: str) -> str:
        def task() -> str:
            # VULNERABILITY: No URL validation - any URL is accepted
            data = gl.nondet.web.render(url, mode="text")
            return data[:1000]

        result = gl.eq_principle.strict_eq(task)
        return result


class SSRFHardenedContract(gl.Contract):
    """
    Defense: URL allowlisting, scheme restriction, IP blocking.
    """
    allowed_domains: TreeMap[str, bool]

    def __init__(self):
        self.allowed_domains = TreeMap[str, bool]()

    @gl.public.write
    def add_allowed_domain(self, domain: str):
        if gl.message.sender_address != self.owner:
            raise gl.vm.UserError("Owner only")
        self.allowed_domains[domain] = True

    def _validate_url(self, url: str):
        """Validate URL against allowlist and block dangerous patterns."""
        # Scheme validation
        if not url.startswith("https://"):
            raise gl.vm.UserError("Only HTTPS URLs allowed")

        # Block internal/private IPs and metadata endpoints
        blocked_patterns = [
            "169.254.",        # AWS metadata
            "metadata.google", # GCP metadata
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "10.",             # Private Class A
            "172.16.",         # Private Class B
            "192.168.",        # Private Class C
            "[::1]",           # IPv6 loopback
            "file://",
            "gopher://",
            "ftp://",
        ]
        url_lower = url.lower()
        for pattern in blocked_patterns:
            if pattern in url_lower:
                raise gl.vm.UserError(f"Blocked URL pattern: {pattern}")

        # Domain allowlist check
        # In production, properly parse the URL to extract the domain
        domain_found = False
        for allowed_domain in self.allowed_domains:
            if allowed_domain in url:
                domain_found = True
                break
        if not domain_found:
            raise gl.vm.UserError("Domain not in allowlist")

    @gl.public.write
    def fetch_data(self, url: str) -> str:
        self._validate_url(url)

        def task() -> str:
            data = gl.nondet.web.render(url, mode="text")
            # Truncate response to prevent memory exhaustion
            return data[:5000]

        result = gl.eq_principle.strict_eq(task)
        return result


# ============================================================================
# ATTACK B: Data Source Poisoning
# ============================================================================
class DataPoisoningTarget(gl.Contract):
    """
    Demonstrates vulnerability when a contract relies on a single data source.

    Attack: Compromise or MitM the single API endpoint. All validators
    fetch the same poisoned data, so consensus passes on the manipulated value.

    This is especially dangerous because consensus HELPS the attacker:
    if all validators see the same poisoned data, they all agree on the wrong answer.
    """
    oracle_value: u256

    def __init__(self):
        self.oracle_value = u256(0)

    @gl.public.write
    def update_oracle(self) -> str:
        def task() -> str:
            # VULNERABILITY: Single source of truth
            data = gl.nondet.web.render(
                "https://api.single-source.com/price", mode="text"
            )
            return data

        result = gl.eq_principle.strict_eq(task)
        self.oracle_value = u256(int(result))
        return result


class PoisonResistantOracle(gl.Contract):
    """
    Defense: Multi-source aggregation with outlier detection.
    No single compromised source can move the oracle.
    """
    oracle_value: u256
    source_count: u256

    def __init__(self):
        self.oracle_value = u256(0)
        self.source_count = u256(5)

    @gl.public.write
    def update_oracle(self) -> str:
        def task() -> str:
            sources = [
                "https://api.source-a.com/price",
                "https://api.source-b.com/price",
                "https://api.source-c.com/price",
                "https://api.source-d.com/price",
                "https://api.source-e.com/price",
            ]

            values = []
            for url in sources:
                try:
                    data = gl.nondet.web.render(url, mode="text")
                    price = float(
                        gl.nondet.exec_prompt(
                            f"Extract price number from: {data[:200]}. Return only the number."
                        )
                    )
                    values.append(price)
                except Exception:
                    continue

            if len(values) < 3:
                raise Exception("Need at least 3 valid sources")

            # Remove outliers (values more than 2 std devs from mean)
            mean = sum(values) / len(values)
            variance = sum((v - mean) ** 2 for v in values) / len(values)
            std_dev = variance ** 0.5

            filtered = [v for v in values if abs(v - mean) <= 2 * std_dev]

            if len(filtered) < 2:
                raise Exception("Too many outliers detected - possible manipulation")

            # Use median of filtered values
            filtered.sort()
            median = filtered[len(filtered) // 2]
            return str(median)

        result = gl.eq_principle.prompt_comparative(
            task,
            principle="Median of filtered values from 5 sources should be within 0.5%"
        )

        self.oracle_value = u256(int(float(result)))
        return result


# ============================================================================
# ATTACK C: Response Bombing (Resource Exhaustion)
# ============================================================================
class ResourceExhaustionTarget(gl.Contract):
    """
    Attacker points the contract at a URL that returns massive payloads,
    causing memory exhaustion or gas limit breach on validator nodes.

    Attack vectors:
    - URL returning multi-GB response
    - Compression bombs (small compressed payload that expands massively)
    - Infinite streaming responses
    - URLs that redirect in loops
    """

    @gl.public.write
    def process_url(self, url: str) -> str:
        def task() -> str:
            # VULNERABILITY: No response size limit
            data = gl.nondet.web.render(url, mode="text")
            # Processing entire response in LLM prompt
            result = gl.nondet.exec_prompt(f"Summarize: {data}")
            return result

        result = gl.eq_principle.strict_eq(task)
        return result


class ResourceSafeContract(gl.Contract):
    """
    Defense: Strict resource limits, timeout handling, content validation.
    """

    @gl.public.write
    def process_url(self, url: str) -> str:
        MAX_RESPONSE_SIZE = 10000  # 10KB max

        def task() -> str:
            data = gl.nondet.web.render(url, mode="text")

            # Defense 1: Truncate immediately
            if len(data) > MAX_RESPONSE_SIZE:
                data = data[:MAX_RESPONSE_SIZE]

            # Defense 2: Validate content isn't just padding/garbage
            if len(set(data)) < 10:
                raise Exception("Suspicious low-entropy content detected")

            # Defense 3: Only send manageable chunk to LLM
            result = gl.nondet.exec_prompt(
                f"Summarize in 2 sentences: {data[:3000]}"
            )
            return result[:500]  # Cap output too

        result = gl.eq_principle.strict_eq(task)
        return result


# ============================================================================
# ATTACK D: TOCTOU via Redirect Manipulation
# ============================================================================
class RedirectExploitNotes:
    """
    TOCTOU via HTTP Redirects

    Scenario: An attacker controls a URL that initially passes validation
    (e.g., returns benign content) but uses server-side logic to return
    different content on subsequent requests.

    Step 1: Leader validator fetches URL -> benign content returned
    Step 2: Attacker detects leader fetch, switches payload
    Step 3: Validators fetch URL -> malicious content returned
    Step 4: Consensus fails OR validators accept manipulated data

    Alternatively with comparative validation:
    Step 1: Leader gets price $100
    Step 2: Attacker changes response to $110 (within tolerance)
    Step 3: Validators get $110
    Step 4: Comparative consensus passes at ~$105 (midpoint)
    Step 5: Actual market price was $100 but oracle reports $105

    Mitigation: Multi-source aggregation, historical deviation checks,
    and content hashing to detect mid-consensus changes.
    """
    pass
