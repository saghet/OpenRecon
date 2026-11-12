"""
Account Search Engine for Email Intelligence.
Executes non-invasive digital presence checks based on Zehef v2.2.1 modules.
Classifies each check strictly into:
- CONFIRMED: Irrefutable proof of account existence (user ID, avatar, profile data, or explicit "email taken" API response).
- PROBABLE: Indirect correlation (search hit or partial match).
- NOT_FOUND: Service explicitly confirmed the email is available or not registered.
- INCONCLUSIVE: Anti-bot challenge, captive portal, or ambiguous response.
- QUERY_ERROR: Network timeout or connection drop.
"""

import httpx
import hashlib
import json
import logging
from typing import List, Dict, Any, Tuple
from datetime import datetime, timezone
from app.services.email_intel.zehef_adapter import ZehefAdapter

logger = logging.getLogger("email_intel.account_searcher")


class AccountSearcher:
    def __init__(self, adapter: ZehefAdapter):
        self.adapter = adapter

    async def search_all_accounts(self, target_email: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Runs asynchronous checks across all supported digital services.
        Returns:
            (findings_list, evidences_list)
        """
        findings = []
        evidences = []

        async with await self.adapter.get_client() as client:
            # 1. GitHub
            f, e = await self._check_github(client, target_email)
            findings.append(f)
            evidences.append(e)

            # 2. Adobe
            f, e = await self._check_adobe(client, target_email)
            findings.append(f)
            evidences.append(e)

            # 3. Duolingo
            f, e = await self._check_duolingo(client, target_email)
            findings.append(f)
            evidences.append(e)

            # 4. Chess.com
            f, e = await self._check_chess(client, target_email)
            findings.append(f)
            evidences.append(e)

            # 5. Gravatar
            f, e = await self._check_gravatar(client, target_email)
            findings.append(f)
            evidences.append(e)

            # 6. Spotify
            f, e = await self._check_spotify(client, target_email)
            findings.append(f)
            evidences.append(e)

            # 7. Twitter / X
            f, e = await self._check_twitter(client, target_email)
            findings.append(f)
            evidences.append(e)

            # 8. BandLab
            f, e = await self._check_bandlab(client, target_email)
            findings.append(f)
            evidences.append(e)

            # 9. Deezer
            f, e = await self._check_deezer(client, target_email)
            findings.append(f)
            evidences.append(e)

            # 10. PicsArt
            f, e = await self._check_picsart(client, target_email)
            findings.append(f)
            evidences.append(e)

            # 11. Flickr
            f, e = await self._check_flickr(client, target_email)
            findings.append(f)
            evidences.append(e)

            # 12. Instagram (Protected / WAF test)
            f, e = await self._check_instagram(client, target_email)
            findings.append(f)
            evidences.append(e)

        return findings, evidences

    async def _check_github(self, client: httpx.AsyncClient, email: str):
        url = f"https://api.github.com/search/users?q={email}+in:email"
        try:
            r = await client.get(url, headers={"User-Agent": "OpenRecon-EmailIntel/1.0"})
            raw = r.text
            sha = self.adapter.calculate_sha256(raw)
            ev = self._create_evidence("GitHub", "ACCOUNT_LOOKUP", raw, sha, r.status_code == 200)

            if r.status_code == 200:
                data = r.json()
                total = data.get("total_count", 0)
                if total > 0 and len(data.get("items", [])) > 0:
                    user = data["items"][0]
                    login = user.get("login")
                    profile = f"https://github.com/{login}"
                    avatar = user.get("avatar_url")
                    return {
                        "platform": "GitHub",
                        "status": "CONFIRMED",
                        "query_date": datetime.now(timezone.utc).isoformat(),
                        "check_method": "API User Search in Email",
                        "evidence_snippet": f"User ID: {user.get('id')}, Login: {login}",
                        "profile_url": profile,
                        "avatar_url": avatar,
                        "username": login,
                        "confidence_level": "CRITICAL",
                        "raw_evidence_sha256": sha
                    }, ev
                else:
                    return {
                        "platform": "GitHub",
                        "status": "NOT_FOUND",
                        "query_date": datetime.now(timezone.utc).isoformat(),
                        "check_method": "API User Search in Email",
                        "evidence_snippet": "Total count is 0",
                        "confidence_level": "HIGH",
                        "raw_evidence_sha256": sha
                    }, ev
            else:
                return self._error_finding("GitHub", f"HTTP status {r.status_code}", sha), ev
        except Exception as e:
            return self._exception_finding("GitHub", e)

    async def _check_adobe(self, client: httpx.AsyncClient, email: str):
        url = "https://auth.services.adobe.com/signin/v2/users/accounts"
        headers = {"x-ims-clientid": "homepage_milo", "content-type": "application/json"}
        payload = {"username": email, "usernameType": "EMAIL"}
        try:
            r = await client.post(url, headers=headers, json=payload)
            raw = r.text
            sha = self.adapter.calculate_sha256(raw)
            ev = self._create_evidence("Adobe", "ACCOUNT_AUTH_PROBE", raw, sha, r.status_code == 200)

            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list) and len(data) > 0 and data[0].get("authenticationMethods"):
                    return {
                        "platform": "Adobe",
                        "status": "CONFIRMED",
                        "query_date": datetime.now(timezone.utc).isoformat(),
                        "check_method": "IMS Account Discovery API",
                        "evidence_snippet": f"Account type: {data[0].get('type', 'individual')}, Methods: OTP/Password",
                        "profile_url": "https://account.adobe.com",
                        "confidence_level": "HIGH",
                        "raw_evidence_sha256": sha
                    }, ev
                else:
                    return {
                        "platform": "Adobe",
                        "status": "NOT_FOUND",
                        "query_date": datetime.now(timezone.utc).isoformat(),
                        "check_method": "IMS Account Discovery API",
                        "evidence_snippet": "No authentication methods available",
                        "confidence_level": "HIGH",
                        "raw_evidence_sha256": sha
                    }, ev
            else:
                return self._error_finding("Adobe", f"HTTP status {r.status_code}", sha), ev
        except Exception as e:
            return self._exception_finding("Adobe", e)

    async def _check_duolingo(self, client: httpx.AsyncClient, email: str):
        url = f"https://www.duolingo.com/2017-06-30/users?email={email}"
        try:
            r = await client.get(url)
            raw = r.text
            sha = self.adapter.calculate_sha256(raw)
            ev = self._create_evidence("Duolingo", "ACCOUNT_LOOKUP", raw, sha, r.status_code == 200)

            if r.status_code == 200:
                data = r.json()
                users = data.get("users", [])
                if users:
                    u = users[0]
                    uname = u.get("username")
                    pic = u.get("picture")
                    if pic and pic.startswith("//"):
                        pic = "https:" + pic
                    return {
                        "platform": "Duolingo",
                        "status": "CONFIRMED",
                        "query_date": datetime.now(timezone.utc).isoformat(),
                        "check_method": "Public Profile API Query",
                        "evidence_snippet": f"User: {uname}, Name: {u.get('name', 'N/A')}",
                        "profile_url": f"https://www.duolingo.com/profile/{uname}" if uname else None,
                        "avatar_url": pic,
                        "username": uname,
                        "confidence_level": "HIGH",
                        "raw_evidence_sha256": sha
                    }, ev
                else:
                    return {
                        "platform": "Duolingo",
                        "status": "NOT_FOUND",
                        "query_date": datetime.now(timezone.utc).isoformat(),
                        "check_method": "Public Profile API Query",
                        "evidence_snippet": "User array is empty",
                        "confidence_level": "HIGH",
                        "raw_evidence_sha256": sha
                    }, ev
            else:
                return self._error_finding("Duolingo", f"HTTP {r.status_code}", sha), ev
        except Exception as e:
            return self._exception_finding("Duolingo", e)

    async def _check_chess(self, client: httpx.AsyncClient, email: str):
        url = f"https://www.chess.com/callback/email/available?email={email}"
        try:
            r = await client.get(url)
            raw = r.text
            sha = self.adapter.calculate_sha256(raw)
            ev = self._create_evidence("Chess.com", "ACCOUNT_AVAILABILITY", raw, sha, r.status_code in [200, 226])

            if r.status_code in [200, 226]:
                data = r.json()
                is_available = data.get("isEmailAvailable", True)
                if not is_available or data.get("reason") == "Email In Use":
                    return {
                        "platform": "Chess.com",
                        "status": "CONFIRMED",
                        "query_date": datetime.now(timezone.utc).isoformat(),
                        "check_method": "Registration Availability Probe",
                        "evidence_snippet": f"Reason: {data.get('reason', 'Email in use')}",
                        "profile_url": "https://www.chess.com",
                        "confidence_level": "HIGH",
                        "raw_evidence_sha256": sha
                    }, ev
                else:
                    return {
                        "platform": "Chess.com",
                        "status": "NOT_FOUND",
                        "query_date": datetime.now(timezone.utc).isoformat(),
                        "check_method": "Registration Availability Probe",
                        "evidence_snippet": "Email is available for registration",
                        "confidence_level": "HIGH",
                        "raw_evidence_sha256": sha
                    }, ev
            else:
                return self._error_finding("Chess.com", f"HTTP {r.status_code}", sha), ev
        except Exception as e:
            return self._exception_finding("Chess.com", e)

    async def _check_gravatar(self, client: httpx.AsyncClient, email: str):
        h = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
        url = f"https://en.gravatar.com/{h}.json"
        try:
            r = await client.get(url)
            raw = r.text
            sha = self.adapter.calculate_sha256(raw)
            ev = self._create_evidence("Gravatar", "HASH_LOOKUP", raw, sha, r.status_code in [200, 404])

            if r.status_code == 200:
                data = r.json()
                entries = data.get("entry", [])
                if entries:
                    ent = entries[0]
                    display = ent.get("displayName")
                    thumb = ent.get("thumbnailUrl", "").replace("\\", "")
                    return {
                        "platform": "Gravatar",
                        "status": "CONFIRMED",
                        "query_date": datetime.now(timezone.utc).isoformat(),
                        "check_method": "SHA-256 Public Avatar Profile API",
                        "evidence_snippet": f"Display Name: {display}, Profile: {ent.get('profileUrl')}",
                        "profile_url": ent.get("profileUrl") or f"https://gravatar.com/{display}",
                        "avatar_url": thumb,
                        "username": display,
                        "confidence_level": "HIGH",
                        "raw_evidence_sha256": sha
                    }, ev
            elif r.status_code == 404:
                return {
                    "platform": "Gravatar",
                    "status": "NOT_FOUND",
                    "query_date": datetime.now(timezone.utc).isoformat(),
                    "check_method": "SHA-256 Public Avatar Profile API",
                    "evidence_snippet": "User profile not found",
                    "confidence_level": "HIGH",
                    "raw_evidence_sha256": sha
                }, ev
            return self._error_finding("Gravatar", f"HTTP {r.status_code}", sha), ev
        except Exception as e:
            return self._exception_finding("Gravatar", e)

    async def _check_spotify(self, client: httpx.AsyncClient, email: str):
        url = f"https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={email}"
        try:
            r = await client.get(url)
            raw = r.text
            sha = self.adapter.calculate_sha256(raw)
            ev = self._create_evidence("Spotify", "REGISTRATION_VALIDATE", raw, sha, r.status_code == 200)

            if r.status_code == 200:
                data = r.json()
                errs = data.get("errors", {})
                if "email" in errs and "already registered" in str(errs["email"]).lower():
                    return {
                        "platform": "Spotify",
                        "status": "CONFIRMED",
                        "query_date": datetime.now(timezone.utc).isoformat(),
                        "check_method": "Public Account Validation Endpoint",
                        "evidence_snippet": str(errs.get("email")),
                        "profile_url": "https://open.spotify.com",
                        "confidence_level": "HIGH",
                        "raw_evidence_sha256": sha
                    }, ev
                else:
                    return {
                        "platform": "Spotify",
                        "status": "NOT_FOUND",
                        "query_date": datetime.now(timezone.utc).isoformat(),
                        "check_method": "Public Account Validation Endpoint",
                        "evidence_snippet": "Email is not registered",
                        "confidence_level": "HIGH",
                        "raw_evidence_sha256": sha
                    }, ev
            return self._error_finding("Spotify", f"HTTP {r.status_code}", sha), ev
        except Exception as e:
            return self._exception_finding("Spotify", e)

    async def _check_twitter(self, client: httpx.AsyncClient, email: str):
        url = f"https://api.twitter.com/i/users/email_available.json?email={email}"
        try:
            r = await client.get(url)
            raw = r.text
            sha = self.adapter.calculate_sha256(raw)
            ev = self._create_evidence("Twitter / X", "ACCOUNT_AVAILABILITY", raw, sha, r.status_code == 200)

            if r.status_code == 200:
                data = r.json()
                taken = data.get("taken", False)
                if taken:
                    return {
                        "platform": "Twitter / X",
                        "status": "CONFIRMED",
                        "query_date": datetime.now(timezone.utc).isoformat(),
                        "check_method": "API Email Availability Checker",
                        "evidence_snippet": "Email is taken / in use",
                        "profile_url": "https://x.com",
                        "confidence_level": "HIGH",
                        "raw_evidence_sha256": sha
                    }, ev
                else:
                    return {
                        "platform": "Twitter / X",
                        "status": "NOT_FOUND",
                        "query_date": datetime.now(timezone.utc).isoformat(),
                        "check_method": "API Email Availability Checker",
                        "evidence_snippet": "Email is available",
                        "confidence_level": "HIGH",
                        "raw_evidence_sha256": sha
                    }, ev
            return self._error_finding("Twitter / X", f"HTTP {r.status_code}", sha), ev
        except Exception as e:
            return self._exception_finding("Twitter / X", e)

    async def _check_bandlab(self, client: httpx.AsyncClient, email: str):
        url = "https://www.bandlab.com/api/v1.3/validation/user"
        try:
            r = await client.get(url, params={"email": email})
            raw = r.text
            sha = self.adapter.calculate_sha256(raw)
            ev = self._create_evidence("BandLab", "ACCOUNT_VALIDATION", raw, sha, r.status_code == 200)

            if r.status_code == 200:
                data = r.json()
                if data.get("isValid") and data.get("isAvailable") is False:
                    return {
                        "platform": "BandLab",
                        "status": "CONFIRMED",
                        "query_date": datetime.now(timezone.utc).isoformat(),
                        "check_method": "BandLab User Validation API",
                        "evidence_snippet": "isAvailable=false (Email in use)",
                        "profile_url": "https://www.bandlab.com",
                        "confidence_level": "HIGH",
                        "raw_evidence_sha256": sha
                    }, ev
                else:
                    return {
                        "platform": "BandLab",
                        "status": "NOT_FOUND",
                        "query_date": datetime.now(timezone.utc).isoformat(),
                        "check_method": "BandLab User Validation API",
                        "evidence_snippet": "Email is available",
                        "confidence_level": "HIGH",
                        "raw_evidence_sha256": sha
                    }, ev
            return self._error_finding("BandLab", f"HTTP {r.status_code}", sha), ev
        except Exception as e:
            return self._exception_finding("BandLab", e)

    async def _check_deezer(self, client: httpx.AsyncClient, email: str):
        token_url = "https://www.deezer.com/ajax/gw-light.php?method=deezer.getUserData&input=3&api_version=1.0&api_token=&cid="
        try:
            r1 = await client.post(token_url)
            token = r1.json().get("results", {}).get("checkForm", "")
            if not token:
                return self._inconclusive_finding("Deezer", "Unable to obtain CSRF checkForm token")

            params = {"method": "deezer.emailCheck", "input": 3, "api_version": "1.0", "api_token": token}
            payload = json.dumps({"EMAIL": email})
            r2 = await client.post("https://www.deezer.com/ajax/gw-light.php", params=params, content=payload)
            raw = r2.text
            sha = self.adapter.calculate_sha256(raw)
            ev = self._create_evidence("Deezer", "AJAX_EMAIL_CHECK", raw, sha, r2.status_code == 200)

            if r2.status_code == 200:
                avail = r2.json().get("results", {}).get("availability")
                if avail is False:
                    return {
                        "platform": "Deezer",
                        "status": "CONFIRMED",
                        "query_date": datetime.now(timezone.utc).isoformat(),
                        "check_method": "Deezer Gateway Email Availability",
                        "evidence_snippet": "availability=false (Account exists)",
                        "profile_url": "https://www.deezer.com",
                        "confidence_level": "HIGH",
                        "raw_evidence_sha256": sha
                    }, ev
                elif avail is True:
                    return {
                        "platform": "Deezer",
                        "status": "NOT_FOUND",
                        "query_date": datetime.now(timezone.utc).isoformat(),
                        "check_method": "Deezer Gateway Email Availability",
                        "evidence_snippet": "availability=true (Email available)",
                        "confidence_level": "HIGH",
                        "raw_evidence_sha256": sha
                    }, ev
            return self._error_finding("Deezer", f"HTTP {r2.status_code}", sha), ev
        except Exception as e:
            return self._exception_finding("Deezer", e)

    async def _check_picsart(self, client: httpx.AsyncClient, email: str):
        url = f"https://api.picsart.com/users/search.json?query={email}"
        try:
            r = await client.get(url)
            raw = r.text
            sha = self.adapter.calculate_sha256(raw)
            ev = self._create_evidence("PicsArt", "USER_SEARCH", raw, sha, r.status_code == 200)

            if r.status_code == 200:
                resp = r.json().get("response", [])
                if resp:
                    return {
                        "platform": "PicsArt",
                        "status": "PROBABLE",
                        "query_date": datetime.now(timezone.utc).isoformat(),
                        "check_method": "User Search Directory",
                        "evidence_snippet": f"Found {len(resp)} possible profiles",
                        "profile_url": "https://picsart.com",
                        "confidence_level": "MEDIUM",
                        "raw_evidence_sha256": sha
                    }, ev
                else:
                    return {
                        "platform": "PicsArt",
                        "status": "NOT_FOUND",
                        "query_date": datetime.now(timezone.utc).isoformat(),
                        "check_method": "User Search Directory",
                        "evidence_snippet": "No profiles found",
                        "confidence_level": "HIGH",
                        "raw_evidence_sha256": sha
                    }, ev
            return self._error_finding("PicsArt", f"HTTP {r.status_code}", sha), ev
        except Exception as e:
            return self._exception_finding("PicsArt", e)

    async def _check_flickr(self, client: httpx.AsyncClient, email: str):
        url = f"https://www.flickr.com/search/people/?q={email}"
        try:
            r = await client.get(url)
            raw = r.text
            sha = self.adapter.calculate_sha256(raw)
            ev = self._create_evidence("Flickr", "PEOPLE_SEARCH", raw, sha, r.status_code == 200)

            if r.status_code == 200:
                # Basic non-false-positive check
                if "No results found" in raw or "0 results" in raw:
                    return {
                        "platform": "Flickr",
                        "status": "NOT_FOUND",
                        "query_date": datetime.now(timezone.utc).isoformat(),
                        "check_method": "People Directory Search",
                        "evidence_snippet": "No people found for query",
                        "confidence_level": "HIGH",
                        "raw_evidence_sha256": sha
                    }, ev
                else:
                    return {
                        "platform": "Flickr",
                        "status": "PROBABLE",
                        "query_date": datetime.now(timezone.utc).isoformat(),
                        "check_method": "People Directory Search",
                        "evidence_snippet": "Potential community references found",
                        "profile_url": url,
                        "confidence_level": "MEDIUM",
                        "raw_evidence_sha256": sha
                    }, ev
            return self._error_finding("Flickr", f"HTTP {r.status_code}", sha), ev
        except Exception as e:
            return self._exception_finding("Flickr", e)

    async def _check_instagram(self, client: httpx.AsyncClient, email: str):
        # We know Instagram blocks unauthenticated requests with 429
        url = "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/"
        try:
            r = await client.post(url, data={"email": email})
            raw = r.text
            sha = self.adapter.calculate_sha256(raw)
            ev = self._create_evidence("Instagram", "WAF_PROTECTED_PROBE", raw, sha, False)
            if r.status_code == 429 or r.status_code == 403:
                return {
                    "platform": "Instagram",
                    "status": "INCONCLUSIVE",
                    "query_date": datetime.now(timezone.utc).isoformat(),
                    "check_method": "AJAX Attempt (Anti-Bot Protected)",
                    "evidence_snippet": f"HTTP {r.status_code} - Protected by platform anti-bot / rate limit",
                    "confidence_level": "LOW",
                    "raw_evidence_sha256": sha
                }, ev
            return self._error_finding("Instagram", f"HTTP {r.status_code}", sha), ev
        except Exception as e:
            return self._exception_finding("Instagram", e)

    def _create_evidence(self, source: str, kind: str, content: str, sha: str, success: bool):
        return {
            "source_type": f"ACCOUNT_{kind}",
            "source_name": source,
            "collected_at_utc": datetime.now(timezone.utc).isoformat(),
            "raw_content_preview": content[:500],
            "content_sha256": sha,
            "validation_status": "CORROBORATED" if success else "INCONCLUSIVE",
            "confidence_score": 0.85 if success else 0.2
        }

    def _error_finding(self, platform: str, snippet: str, sha: str):
        return {
            "platform": platform,
            "status": "QUERY_ERROR",
            "query_date": datetime.now(timezone.utc).isoformat(),
            "check_method": "HTTP Verification",
            "evidence_snippet": snippet,
            "confidence_level": "LOW",
            "raw_evidence_sha256": sha
        }

    def _inconclusive_finding(self, platform: str, reason: str):
        sha = self.adapter.calculate_sha256(reason)
        ev = self._create_evidence(platform, "INCONCLUSIVE", reason, sha, False)
        return {
            "platform": platform,
            "status": "INCONCLUSIVE",
            "query_date": datetime.now(timezone.utc).isoformat(),
            "check_method": "Protocol Negotiation",
            "evidence_snippet": reason,
            "confidence_level": "LOW",
            "raw_evidence_sha256": sha
        }, ev

    def _exception_finding(self, platform: str, e: Exception):
        msg = f"Network or protocol exception: {str(e)}"
        sha = self.adapter.calculate_sha256(msg)
        ev = self._create_evidence(platform, "EXCEPTION", msg, sha, False)
        return {
            "platform": platform,
            "status": "QUERY_ERROR",
            "query_date": datetime.now(timezone.utc).isoformat(),
            "check_method": "Exception Handler",
            "evidence_snippet": msg,
            "confidence_level": "LOW",
            "raw_evidence_sha256": sha
        }, ev
