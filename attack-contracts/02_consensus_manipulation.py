# {"Depends": "py-genlayer:test"}
"""
ATTACK VECTOR 2: Consensus Manipulation
========================================
Target: Optimistic Democracy, Equivalence Principle validation, leader/validator roles

Threat Model:
  Attacker(s) attempt to manipulate the consensus process to force
  acceptance of incorrect results or prevent legitimate transactions
  from finalizing.

Scenarios:
  A) Tolerance exploitation in comparative validation
  B) Ambiguity exploitation in non-comparative validation
  C) Forced consensus failure (griefing / DoS via perpetual disagreement)
  D) Leader bias amplification
  E) Time-dependent consensus divergence
  F) Cascading consensus failure across dependent contracts
"""

from genlayer import *
import json


# ============================================================================
# ATTACK A: Tolerance Exploitation (Comparative Validation)
# ============================================================================
class ToleranceExploitContract(gl.Contract):
    """
    Exploits the tolerance parameter in prompt_comparative.

    If tolerance is 0.01 (1%), an attacker can systematically push results
    to the edge of the tolerance band. Over many transactions, this
    accumulates into significant price manipulation.

    Example: Real price = $100. With 1% tolerance, any value $99-$101 passes.
    Attacker repeatedly pushes price to $101, then uses $101 as the new
    baseline, getting $102.01 accepted, and so on (ratchet attack).
    """
    price_history: DynArray[str]
    current_price: u256

    def __init__(self):
        self.current_price = u256(0)

    @gl.public.write
    def update_price(self, symbol: str) -> str:
        def price_task() -> str:
            # In a real attack, the leader validator would return
            # a price at the upper tolerance bound
            url = f"https://api.example.com/price/{symbol}"
            data = gl.nondet.web.render(url, mode="text")
            return gl.nondet.exec_prompt(
                f"Extract the USD price from: {data}. Return only the number."
            )

        # VULNERABILITY: tolerance of 10% is exploitable
        result = gl.eq_principle.prompt_comparative(
            price_task,
            principle="The asset price should be within 10% tolerance"
        )

        self.current_price = u256(int(float(result)))
        self.price_history.append(result)
        return result


class HardenedPriceOracle(gl.Contract):
    """
    Defense against tolerance exploitation:
    - Tight tolerance
    - Historical deviation checks (circuit breaker)
    - Multi-source median
    - Time-weighted average pricing
    """
    price_history: DynArray[u256]
    last_price: u256
    max_deviation_pct: u256  # basis points (100 = 1%)

    def __init__(self):
        self.last_price = u256(0)
        self.max_deviation_pct = u256(200)  # 2% max deviation between updates

    def _check_circuit_breaker(self, new_price: u256):
        """Reject prices that deviate too far from the last known price."""
        if self.last_price == u256(0):
            return  # First price, no history to compare

        if new_price > self.last_price:
            deviation = ((new_price - self.last_price) * u256(10000)) // self.last_price
        else:
            deviation = ((self.last_price - new_price) * u256(10000)) // self.last_price

        if deviation > self.max_deviation_pct:
            raise gl.vm.UserError(
                f"Price deviation {deviation} bps exceeds max {self.max_deviation_pct} bps. "
                f"Circuit breaker triggered."
            )

    @gl.public.write
    def update_price(self, symbol: str) -> str:
        def price_task() -> str:
            # Fetch from multiple sources
            sources = [
                f"https://api.source1.com/price/{symbol}",
                f"https://api.source2.com/price/{symbol}",
                f"https://api.source3.com/price/{symbol}",
            ]
            prices = []
            for url in sources:
                try:
                    data = gl.nondet.web.render(url, mode="text")
                    price = gl.nondet.exec_prompt(
                        f"Extract USD price number from: {data[:500]}. Return only the number."
                    )
                    prices.append(float(price))
                except Exception:
                    continue

            if len(prices) < 2:
                raise Exception("Insufficient price sources")

            # Use median to resist outlier manipulation
            prices.sort()
            median = prices[len(prices) // 2]
            return str(median)

        # Defense: tight tolerance (0.5%)
        result = gl.eq_principle.prompt_comparative(
            price_task,
            principle="Median price from 3+ sources should be within 0.5% tolerance"
        )

        new_price = u256(int(float(result)))
        self._check_circuit_breaker(new_price)
        self.last_price = new_price
        self.price_history.append(new_price)
        return result


# ============================================================================
# ATTACK B: Ambiguity Exploitation (Non-Comparative Validation)
# ============================================================================
class AmbiguityExploitContract(gl.Contract):
    """
    Exploits vague criteria in prompt_non_comparative to get validators
    to accept manipulated results.

    If the criteria is "content should be appropriate", an attacker can
    craft content that is technically "appropriate" by some interpretation
    but actually contains harmful or manipulated information.
    """
    moderation_results: TreeMap[str, str]

    @gl.public.write
    def moderate_content(self, content: str) -> str:
        def moderation_task() -> str:
            prompt = f"Is this content appropriate? Content: {content}"
            return gl.nondet.exec_prompt(prompt)

        # VULNERABILITY: vague criteria allows interpretation manipulation
        result = gl.eq_principle.prompt_non_comparative(
            moderation_task,
            task="Content moderation",
            criteria="Result should be reasonable"  # TOO VAGUE
        )
        self.moderation_results[content[:64]] = result
        return result


class HardenedContentModerator(gl.Contract):
    """
    Defense: Precise criteria, structured output, deterministic post-processing.
    """
    moderation_results: TreeMap[str, str]

    @gl.public.write
    def moderate_content(self, content: str) -> str:
        if len(content) > 5000:
            raise gl.vm.UserError("Content exceeds maximum length")

        def moderation_task() -> str:
            prompt = (
                "You are a content moderator. Evaluate the text for:\n"
                "1. Hate speech or discrimination\n"
                "2. Violence or threats\n"
                "3. Spam or scam content\n"
                "4. Misinformation\n\n"
                f'Text: """{content}"""\n\n'
                "Return a JSON object with this EXACT structure:\n"
                '{"verdict": "APPROVED" or "REJECTED", '
                '"categories_flagged": ["category1"], '
                '"confidence": 0.0-1.0}'
            )
            return gl.nondet.exec_prompt(prompt)

        # Defense: highly specific criteria
        result = gl.eq_principle.prompt_non_comparative(
            moderation_task,
            task="Content moderation with structured output",
            criteria=(
                "Must return valid JSON with 'verdict' (APPROVED/REJECTED), "
                "'categories_flagged' (list of strings from: hate_speech, violence, "
                "spam, misinformation), and 'confidence' (float 0.0-1.0). "
                "Verdict must be REJECTED if any category is flagged with confidence > 0.7."
            )
        )

        # Defense: deterministic post-processing validates structure
        try:
            parsed = json.loads(result)
            assert parsed["verdict"] in ("APPROVED", "REJECTED")
            assert isinstance(parsed["categories_flagged"], list)
            assert 0.0 <= parsed["confidence"] <= 1.0
        except (json.JSONDecodeError, KeyError, AssertionError):
            raise gl.vm.UserError("Moderation produced invalid output structure")

        self.moderation_results[content[:64]] = parsed["verdict"]
        return result


# ============================================================================
# ATTACK C: Consensus Griefing (DoS via Perpetual Disagreement)
# ============================================================================
class ConsensusGriefTarget(gl.Contract):
    """
    Demonstrates how a contract can be made to perpetually fail consensus.

    If a prompt is designed to produce maximally divergent LLM outputs,
    strict_eq will always fail, effectively DoSing the contract method.

    Attack vector: An attacker deploys or calls a contract with prompts
    designed to never reach consensus.
    """
    counter: u256

    def __init__(self):
        self.counter = u256(0)

    @gl.public.write
    def creative_task(self, seed: str) -> str:
        def task() -> str:
            # This prompt is DESIGNED to produce different results each time
            # strict_eq will almost certainly fail
            prompt = (
                f"Write a unique, creative haiku about '{seed}'. "
                "Be as original and unexpected as possible. "
                "Never repeat a haiku you've generated before."
            )
            return gl.nondet.exec_prompt(prompt)

        # VULNERABILITY: strict_eq on inherently non-deterministic output
        result = gl.eq_principle.strict_eq(task)
        self.counter += u256(1)
        return result


class ResilientContract(gl.Contract):
    """
    Defense against consensus griefing:
    - Use appropriate equivalence principle for the task
    - Implement fallback mechanisms
    - Rate-limit non-deterministic operations
    """
    counter: u256
    call_counts: TreeMap[Address, u256]
    rate_limit: u256

    def __init__(self):
        self.counter = u256(0)
        self.rate_limit = u256(10)  # max 10 calls per address

    @gl.public.write
    def creative_task(self, seed: str) -> str:
        sender = gl.message.sender_address

        # Defense 1: Rate limiting
        current_count = self.call_counts.get(sender, u256(0))
        if current_count >= self.rate_limit:
            raise gl.vm.UserError("Rate limit exceeded")
        self.call_counts[sender] = current_count + u256(1)

        def task() -> str:
            # Defense 2: Constrain output to be more deterministic
            prompt = (
                f"Generate a haiku about '{seed}'.\n"
                "Follow this EXACT format (5-7-5 syllables):\n"
                "Line 1: [5 syllables about the topic]\n"
                "Line 2: [7 syllables expanding the theme]\n"
                "Line 3: [5 syllables concluding]\n"
                "Use simple, common words. Focus on the literal meaning."
            )
            return gl.nondet.exec_prompt(prompt)

        # Defense 3: Use non-comparative for inherently subjective tasks
        result = gl.eq_principle.prompt_non_comparative(
            task,
            task="Generate a structured haiku",
            criteria=(
                "Must be exactly 3 lines in haiku format (5-7-5 syllables). "
                "Must be related to the given topic. "
                "Must use proper English."
            )
        )

        self.counter += u256(1)
        return result


# ============================================================================
# ATTACK D: Time-Dependent Consensus Divergence
# ============================================================================
class TimeExploitContract(gl.Contract):
    """
    Exploits the time gap between leader execution and validator verification.

    If a contract fetches rapidly-changing data (stock prices, live scores),
    the leader and validators will see different values. An attacker can
    time their transaction to maximize this divergence for profit.

    Example: Submit a price oracle update right before a major announcement.
    Leader gets the pre-announcement price, validators get post-announcement,
    or vice versa. Either way, consensus fails or accepts a stale price.
    """
    recorded_prices: DynArray[str]

    @gl.public.write
    def record_live_price(self, symbol: str) -> str:
        def price_task() -> str:
            # VULNERABILITY: Real-time data changes between leader and validator
            url = f"https://api.exchange.com/realtime/{symbol}"
            data = gl.nondet.web.render(url, mode="text")
            return data

        # strict_eq on rapidly changing data = consensus failure
        result = gl.eq_principle.strict_eq(price_task)
        self.recorded_prices.append(result)
        return result


class TimeResilientOracle(gl.Contract):
    """
    Defense: Use comparative validation with appropriate tolerance for
    time-sensitive data, plus staleness checks.
    """
    prices: TreeMap[str, u256]
    timestamps: TreeMap[str, u256]

    @gl.public.write
    def record_price(self, symbol: str) -> str:
        def price_task() -> str:
            url = f"https://api.exchange.com/v2/{symbol}/ohlcv/latest"
            data = gl.nondet.web.render(url, mode="text")
            # Use closing price (more stable than real-time)
            return gl.nondet.exec_prompt(
                f"Extract the latest closing price from: {data[:1000]}. Return only the number."
            )

        # Defense: comparative with reasonable tolerance for market volatility
        result = gl.eq_principle.prompt_comparative(
            price_task,
            principle="Closing price from OHLCV data should be within 1% tolerance"
        )
        return result
