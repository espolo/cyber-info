"""Scarica feed RSS, rivendicazioni ransomware, catalogo dei gruppi criminali e CISA KEV
e genera data/data.json per la dashboard.

Eseguito da GitHub Actions ogni 30 minuti. Ogni fonte e' indipendente:
se una non risponde, le altre vengono aggiornate e per quella si riusano i dati precedenti.

Riconoscimento dei gruppi (threat actor):
  1. gruppi aggiunti a mano in config.json (extra_actors, soprattutto hacktivisti)
  2. tutti i gruppi ransomware tracciati da ransomware.live
  3. il catalogo MISP threat-actor (APT e gruppi criminali, con i relativi alias)
Ogni notizia viene confrontata con tutti i nomi e alias; i gruppi trovati diventano etichette.
"""
import json
import os
import re
from collections import Counter
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import feedparser
import requests

ROOT = Path(__file__).resolve().parent.parent
CONFIG = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
OUT = ROOT / "data" / "data.json"
ACTORS_CACHE = ROOT / "data" / "actors.json"
UA = {"User-Agent": "CyberInfoDashboard/1.0 (+github pages)"}
# alcuni siti istituzionali rifiutano client non-browser
BROWSER_UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
              "Accept": "application/rss+xml, application/xml, text/xml, */*"}
NOW = datetime.now(timezone.utc)

CONTEXT_RE = re.compile(
    r"ransomware|gang|group|gruppo|gruppi|team|crew|hacker|hacktivist|apt|operator|actor|"
    r"collettivo|banda|ddos|leak|rivendic|claim|affiliat|extortion|estorsion",
    re.I,
)


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clean(html, limit=300):
    text = re.sub(r"<[^>]+>", " ", html or "")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def word_regex(words):
    words = sorted({w.lower() for w in words if w}, key=len, reverse=True)
    if not words:
        return None
    alt = "|".join(re.escape(w).replace(r"\ ", r"\s+") for w in words)
    return re.compile(rf"(?<!\w)(?:{alt})(?!\w)", re.I)


THREAT_RE = word_regex(CONFIG["threat_keywords"])
HIGHLIGHT_RE = word_regex(CONFIG["highlight_keywords"])
# Italia nei post Telegram (anche in russo e con la bandiera)
IT_RE = re.compile(r"(?<!\w)(?:ital\w*|итали\w*)(?!\w)|🇮🇹", re.I)


def get_json(url, timeout=40):
    r = requests.get(url, headers=UA, timeout=timeout)
    r.raise_for_status()
    return r.json()


def load_previous():
    try:
        return json.loads(OUT.read_text(encoding="utf-8"))
    except Exception:
        return {}


# ---------------------------------------------------------------- gruppi / threat actor

def build_actors(errors, victims):
    """Restituisce {nome_canonico: {type, country, aliases}}."""
    actors = {}

    def add(name, typ, country="", aliases=(), override_type=False):
        name = (name or "").strip()
        if not name:
            return
        key = name.lower()
        # cerca se il gruppo esiste gia' con un alias uguale
        existing = next((n for n, a in actors.items()
                         if n.lower() == key or key in (x.lower() for x in a["aliases"])), None)
        if existing:
            a = actors[existing]
            a["aliases"].update(x for x in aliases if x)
            if override_type:
                a["type"] = typ
            if not a["country"] and country:
                a["country"] = country
            return
        actors[name] = {"type": typ, "country": country or "", "aliases": {x for x in aliases if x}}

    # 1. gruppi manuali (precedenza massima)
    for a in CONFIG.get("extra_actors", []):
        add(a["name"], a.get("type", "criminal"), a.get("country", ""), a.get("aliases", []))

    # 2. gruppi ransomware
    rgroups = []
    try:
        data = get_json(CONFIG["ransomware_groups_api"])
        for g in data if isinstance(data, list) else data.get("groups", []):
            n = g.get("name") or g.get("group") if isinstance(g, dict) else g
            if n:
                rgroups.append(n)
    except Exception as ex:
        errors.append(f"ransomware.live gruppi: {ex}")
    rgroups += [v["group"] for v in victims]
    for n in rgroups:
        add(n, "ransomware", override_type=False)

    # 3. catalogo MISP (APT e criminali)
    try:
        misp = get_json(CONFIG["misp_threat_actors"], timeout=60)
        for v in misp.get("values", []):
            meta = v.get("meta", {}) or {}
            state = meta.get("cfr-suspected-state-sponsor") or meta.get("country")
            add(v.get("value"), "apt" if state else "criminal",
                (meta.get("country") or "").upper()[:2], meta.get("synonyms", []))
    except Exception as ex:
        errors.append(f"MISP threat actors: {ex}")
        try:  # riusa la cache dell'ultima volta
            for n, a in json.loads(ACTORS_CACHE.read_text(encoding="utf-8")).items():
                if a["type"] in ("apt", "criminal"):
                    add(n, a["type"], a["country"], a["aliases"])
        except Exception:
            pass

    ACTORS_CACHE.write_text(json.dumps(
        {n: {**a, "aliases": sorted(a["aliases"])} for n, a in actors.items()},
        ensure_ascii=False), encoding="utf-8")
    return actors


class ActorMatcher:
    def __init__(self, actors):
        minlen = CONFIG.get("min_alias_length", 4)
        ambiguous_cfg = {a.lower() for a in CONFIG.get("ambiguous_aliases", [])}
        self.index = {}       # alias minuscolo -> nome canonico
        self.ambiguous = set()
        for name, a in actors.items():
            for alias in [name, *a["aliases"]]:
                al = alias.strip().lower()
                if len(al) < minlen or al in self.index:
                    continue
                self.index[al] = name
                # parole singole brevi o elencate come ambigue richiedono un contesto
                if al in ambiguous_cfg or (re.fullmatch(r"[a-z]+", al) and len(al) <= 6):
                    self.ambiguous.add(al)
        self.regex = word_regex(self.index.keys())

    def canonical(self, name):
        return self.index.get((name or "").strip().lower(), name)

    def find(self, text):
        if not self.regex or not text:
            return []
        found = []
        for m in self.regex.finditer(text):
            al = re.sub(r"\s+", " ", m.group(0).lower())
            name = self.index.get(al)
            if not name:
                continue
            if al in self.ambiguous:
                window = text[max(0, m.start() - 45): m.end() + 45]
                if not CONTEXT_RE.search(window.replace(m.group(0), " ")):
                    continue
            if name not in found:
                found.append(name)
        return found


# ---------------------------------------------------------------- fonti

def fetch_feeds(errors):
    items = []
    for f in CONFIG["feeds"]:
        try:
            parsed, tried = None, []
            for url in [f["url"], *f.get("fallback_urls", [])]:
                host = re.sub(r"^https?://(www\.)?", "", url).split("/")[0]
                try:
                    r = requests.get(url, headers=BROWSER_UA, timeout=25)
                    r.raise_for_status()
                    parsed = feedparser.parse(r.content)
                    if parsed.entries:
                        break
                    start = re.sub(r"\s+", " ", r.text[:80])
                    tried.append(f"{host}: risposta {r.status_code} senza notizie ({r.headers.get('content-type', '?')}; inizia con: {start!r})")
                except Exception as ex:
                    tried.append(f"{host}: {str(ex)[:120]}")
            if not parsed or not parsed.entries:
                raise Exception(" | ".join(tried))
            for e in parsed.entries[:40]:
                st = e.get("published_parsed") or e.get("updated_parsed")
                dt = datetime.fromtimestamp(time.mktime(st), timezone.utc) if st else NOW
                items.append({
                    "id": e.get("link") or e.get("title", ""),
                    "title": clean(e.get("title", ""), 220),
                    "link": e.get("link", ""),
                    "summary": clean(e.get("summary", "")),
                    "source": f["name"],
                    "lang": f["lang"],
                    "type": f["type"],
                    "date": iso(dt),
                })
        except Exception as ex:
            errors.append(f"{f['name']}: {ex}")
    return items


def fetch_ransomware(errors):
    try:
        data = get_json(CONFIG["ransomware_api"])
    except Exception as ex:
        errors.append(f"ransomware.live: {ex}")
        return None
    out = []
    for v in data if isinstance(data, list) else data.get("victims", []):
        victim = v.get("victim") or v.get("post_title") or "?"
        group = v.get("group") or v.get("group_name") or "?"
        date = v.get("discovered") or v.get("attackdate") or v.get("published") or ""
        out.append({
            "id": f"{group}|{victim}",
            "victim": victim,
            "group": group,
            "country": (v.get("country") or "").upper(),
            "sector": v.get("activity") or "",
            "date": str(date).replace(" ", "T")[:19],
            "link": f"https://www.ransomware.live/group/{group}",
            "summary": clean(v.get("description", ""), 250),
        })
    out.sort(key=lambda x: x["date"], reverse=True)
    return out[:400]


def fetch_kev(errors):
    try:
        vulns = get_json(CONFIG["cisa_kev"]).get("vulnerabilities", [])
    except Exception as ex:
        errors.append(f"CISA KEV: {ex}")
        return None
    vulns.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
    return [{
        "cve": v["cveID"],
        "vendor": v.get("vendorProject", ""),
        "product": v.get("product", ""),
        "name": v.get("vulnerabilityName", ""),
        "date": v.get("dateAdded", ""),
        "ransomware": v.get("knownRansomwareCampaignUse", "") == "Known",
        "link": f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
    } for v in vulns[:40]]


# ---------------------------------------------------------------- RansomLook (seconda fonte leak site)

COUNTRY_NAMES = {
    "italy": "IT", "italia": "IT", "germany": "DE", "france": "FR", "spain": "ES", "united kingdom": "GB",
    "uk": "GB", "united states": "US", "usa": "US", "canada": "CA", "netherlands": "NL", "belgium": "BE",
    "switzerland": "CH", "austria": "AT", "portugal": "PT", "poland": "PL", "brazil": "BR", "india": "IN",
    "australia": "AU", "mexico": "MX", "japan": "JP", "sweden": "SE", "denmark": "DK", "norway": "NO",
    "finland": "FI", "ireland": "IE", "greece": "GR", "czech republic": "CZ", "czechia": "CZ", "romania": "RO",
    "turkey": "TR", "israel": "IL", "argentina": "AR", "colombia": "CO", "chile": "CL", "peru": "PE",
}


def norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def guess_country(title, desc):
    m = re.search(r"country\s*:\s*([A-Za-z .]+?)\s*(?:\||$|,)", desc or "", re.I)
    if m:
        c = m.group(1).strip().lower()
        if len(c) == 2:
            return c.upper()
        if c in COUNTRY_NAMES:
            return COUNTRY_NAMES[c]
    if re.search(r"\.it\b|\*+\.it$", (title or "").lower()):
        return "IT"
    return ""


def fetch_ransomlook(errors):
    try:
        data = get_json(CONFIG.get("ransomlook_api", "https://www.ransomlook.io/api/recent/200"))
    except Exception as ex:
        errors.append(f"RansomLook: {ex}")
        return None
    out = []
    for v in data if isinstance(data, list) else []:
        victim = (v.get("post_title") or "?").strip()
        group = v.get("group_name") or "?"
        desc = v.get("description") or ""
        out.append({
            "id": f"{group}|{victim}",
            "victim": victim,
            "group": group,
            "country": guess_country(victim, desc),
            "sector": "",
            "date": str(v.get("discovered") or "").replace(" ", "T")[:19],
            "link": f"https://www.ransomlook.io/group/{group}",
            "summary": clean(desc, 250),
        })
    return out


def merge_victims(a, b):
    """Unisce le rivendicazioni di ransomware.live (a) e RansomLook (b), togliendo i doppioni."""
    seen = {}
    for r in a:
        r.setdefault("sources", ["ransomware.live"])
        seen[(norm(r["group"]), norm(r["victim"]))] = r
    for r in b:
        k = (norm(r["group"]), norm(r["victim"]))
        if k in seen:
            x = seen[k]
            if "RansomLook" not in x["sources"]:
                x["sources"].append("RansomLook")
            if not x["country"] and r["country"]:
                x["country"] = r["country"]
        else:
            r["sources"] = ["RansomLook"]
            seen[k] = r
    out = sorted(seen.values(), key=lambda x: x["date"], reverse=True)
    return out[:500]


# ---------------------------------------------------------------- Telegram (canali pubblici hacktivisti)

TG_MSG_RE = re.compile(r'data-post="([^"]+)"(.*?)(?=data-post="|\Z)', re.S)
TG_TEXT_RE = re.compile(r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', re.S)
TG_TIME_RE = re.compile(r'<time[^>]*datetime="([^"]+)"')


def tg_text(html_):
    import html as _h
    t = re.sub(r"<br\s*/?>", "\n", html_)
    t = re.sub(r"<[^>]+>", " ", t)
    return re.sub(r"[ \t]+", " ", _h.unescape(t)).strip()


def fetch_telegram(errors):
    """Legge l'anteprima web pubblica (t.me/s/<canale>) senza account Telegram."""
    items = []
    for ch in CONFIG.get("telegram_channels", []):
        # piu' username possibili: i canali vengono chiusi e riaperti spesso con nomi nuovi
        names = [u.lstrip("@") for u in ch.get("usernames") or [ch.get("username", "")] if u]
        user, r, tried = names[0] if names else "?", None, []
        for u in names:
            try:
                x = requests.get(f"https://t.me/s/{u}", headers=BROWSER_UA, timeout=25)
                x.raise_for_status()
                if "/s/" in x.url and "tgme_widget_message" in x.text:
                    user, r = u, x
                    break
                tried.append(u)
            except Exception as ex:
                tried.append(f"{u} ({str(ex)[:60]})")
        try:
            if r is None:
                raise Exception("nessun canale pubblico raggiungibile tra: " + ", ".join(tried)
                                + " (aggiorna gli username in config.json)")
            count = 0
            for post, body in TG_MSG_RE.findall(r.text):
                tm = TG_TEXT_RE.search(body)
                dt = TG_TIME_RE.search(body)
                if not tm or not dt:
                    continue
                text = tg_text(tm.group(1))
                if len(text) < 15:
                    continue
                d = datetime.fromisoformat(dt.group(1).replace("Z", "+00:00"))
                first = text.split("\n", 1)[0]
                items.append({
                    "id": f"https://t.me/{post}",
                    "title": clean(first, 200),
                    "link": f"https://t.me/{post}",
                    "summary": clean(text[len(first):] if len(text) > len(first) + 20 else "", 400),
                    "source": f"Telegram · {ch.get('name') or user}",
                    "lang": "tg",
                    "type": "claims",
                    "tg_actor": ch.get("actor", ""),
                    "date": iso(d),
                })
                count += 1
            if not count:
                raise Exception("nessun messaggio di testo trovato")
        except Exception as ex:
            errors.append(f"Telegram {ch.get('name') or user}: {str(ex)[:300]}")
    return items


# ---------------------------------------------------------------- Cloudflare Radar (DDoS e disservizi)

CF_TOKEN = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
CF_API = "https://api.cloudflare.com/client/v4/radar"


def cf_get(path, **params):
    r = requests.get(f"{CF_API}{path}", params={**params, "format": "json"},
                     headers={**UA, "Authorization": f"Bearer {CF_TOKEN}"}, timeout=40)
    r.raise_for_status()
    return r.json().get("result", {})


def fetch_radar(errors):
    if not CF_TOKEN:
        errors.append("Cloudflare Radar: token non configurato (secret CLOUDFLARE_API_TOKEN)")
        return None
    out = {}
    try:
        for rng in ("1d", "7d"):
            res = cf_get("/attacks/layer7/top/locations/target", dateRange=rng, limit=100)
            rows = [{"code": x.get("targetCountryAlpha2", ""), "name": x.get("targetCountryName", ""),
                     "value": round(float(x.get("value", 0)), 2), "rank": x.get("rank")}
                    for x in res.get("top_0", [])]
            out[f"l7_{rng}"] = rows[:12]
            it = next((x for x in rows if x["code"] == "IT"), None)
            out[f"it_{rng}"] = it
    except Exception as ex:
        errors.append(f"Cloudflare Radar attacchi: {str(ex)[:160]}")
    try:
        res = cf_get("/annotations/outages", location="IT", dateRange="30d", limit=20)
        out["outages_it"] = [{
            "start": a.get("startDate", ""), "end": a.get("endDate") or "",
            "cause": (a.get("outage") or {}).get("outageCause", ""),
            "type": (a.get("outage") or {}).get("outageType", ""),
            "desc": clean(a.get("description", ""), 250),
            "asns": [d.get("name", "") for d in (a.get("asnsDetails") or [])][:3],
            "link": a.get("linkedUrl") or "",
        } for a in res.get("annotations", [])]
    except Exception as ex:
        errors.append(f"Cloudflare Radar disservizi: {str(ex)[:160]}")
    return out or None


# ---------------------------------------------------------------- malware e IoC (abuse.ch, CERT-AGID)

ABUSE_KEY = os.environ.get("ABUSECH_AUTH_KEY", "").strip()


def abuse_post(url, data=None, json_body=None):
    r = requests.post(url, headers={**UA, "Auth-Key": ABUSE_KEY}, data=data, json=json_body, timeout=45)
    r.raise_for_status()
    return r.json()


def defang(x):
    """Rende un indicatore non cliccabile: hxxp://dominio[.]it"""
    return (x or "").replace("http", "hxxp").replace(".", "[.]")


def fetch_threatfox(errors):
    try:
        d = abuse_post("https://threatfox-api.abuse.ch/api/v1/", json_body={"query": "get_iocs", "days": 1})
    except Exception as ex:
        errors.append(f"ThreatFox: {ex}")
        return None
    out = []
    for i in d.get("data") or []:
        if not isinstance(i, dict):
            continue
        out.append({
            "ioc": defang(i.get("ioc", "")),
            "type": i.get("ioc_type", ""),
            "threat": i.get("threat_type_desc") or i.get("threat_type", ""),
            "malware": i.get("malware_printable") or i.get("malware", ""),
            "confidence": i.get("confidence_level", 0),
            "date": str(i.get("first_seen", "")).replace(" UTC", "").replace(" ", "T")[:19],
            "tags": i.get("tags") or [],
            "link": f"https://threatfox.abuse.ch/ioc/{i.get('id')}/",
        })
    out.sort(key=lambda x: x["date"], reverse=True)
    return out


def fetch_urlhaus(errors):
    rows, tried = None, []
    # 1) API v1 "recent" (GET)
    try:
        r = requests.get("https://urlhaus-api.abuse.ch/v1/urls/recent/",
                         headers={**UA, "Auth-Key": ABUSE_KEY}, timeout=45)
        r.raise_for_status()
        d = r.json()
        if d.get("query_status") not in (None, "ok"):
            raise Exception(f"query_status={d.get('query_status')}")
        rows = [{"url": u.get("url", ""), "status": u.get("url_status", ""), "threat": u.get("threat", ""),
                 "tags": u.get("tags") or [], "date": u.get("date_added", ""), "link": u.get("urlhaus_reference", "")}
                for u in d.get("urls") or []]
    except Exception as ex:
        tried.append(f"API v1: {str(ex)[:120]}")
    # 2) export v2 CSV delle URL recenti
    if rows is None:
        try:
            r = requests.get(f"https://urlhaus-api.abuse.ch/v2/files/exports/{ABUSE_KEY}/recent.csv",
                             headers=UA, timeout=60)
            r.raise_for_status()
            import csv, io
            lines = [l for l in r.text.splitlines() if l and not l.startswith("#")]
            rows = []
            for c in csv.reader(io.StringIO("\n".join(lines))):
                # id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
                if len(c) < 8:
                    continue
                rows.append({"url": c[2], "status": c[3], "threat": c[5],
                             "tags": [t for t in c[6].split(",") if t], "date": c[1], "link": c[7]})
        except Exception as ex:
            tried.append(f"export v2: {str(ex)[:120].replace(ABUSE_KEY, '***')}")
    if rows is None:
        errors.append("URLhaus: " + " | ".join(tried))
        return None
    out = []
    for u in rows:
        host = re.sub(r"^[a-z]+://", "", u["url"].lower()).split("/")[0].split(":")[0]
        out.append({
            "ioc": defang(u["url"]),
            "host_it": host.endswith(".it"),
            "status": u["status"],
            "threat": u["threat"],
            "tags": u["tags"],
            "date": str(u["date"]).replace(" UTC", "").replace(" ", "T")[:19],
            "link": u["link"],
        })
    out.sort(key=lambda x: x["date"], reverse=True)
    it = [u for u in out if u["host_it"]]
    return (it + [u for u in out if not u["host_it"]][:150])[:400]


def fetch_bazaar(errors):
    try:
        d = abuse_post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_recent", "selector": "time"})
    except Exception as ex:
        errors.append(f"MalwareBazaar: {ex}")
        return None
    return [{"sig": s.get("signature") or "", "type": s.get("file_type", ""),
             "date": str(s.get("first_seen", "")).replace(" ", "T")[:19]}
            for s in (d.get("data") or []) if isinstance(s, dict)]


def agid_campaigns(news):
    """Post CERT-AGID su campagne malevole e sintesi settimanali (n. campagne e IoC)."""
    camp_re = re.compile(r"campagn|malware|phishing|smishing|trojan|stealer|\brat\b|ransomware|truffa|spoofing", re.I)
    posts, weekly = [], []
    for n in news:
        if n["source"] != "CERT-AGID":
            continue
        text = f"{n['title']} {n['summary']}"
        if "sintesi riepilogativa" in n["title"].lower():
            c = re.search(r"(\d[\d.]*)\s+campagne", text, re.I)
            i = re.search(r"(\d[\d.]*)\s+(?:indicatori|ioc)", text, re.I)
            weekly.append({"title": n["title"], "link": n["link"], "date": n["date"],
                           "campaigns": int(c.group(1).replace(".", "")) if c else None,
                           "iocs": int(i.group(1).replace(".", "")) if i else None})
        elif camp_re.search(text):
            posts.append(n)
    return posts[:40], weekly[:8]


# ---------------------------------------------------------------- main

def main():
    prev = load_previous()
    errors = []

    merged = {i["id"]: i for i in prev.get("news", [])}
    for i in fetch_feeds(errors) + fetch_telegram(errors):
        merged[i["id"]] = i
    cutoff = iso(NOW - timedelta(days=CONFIG["max_age_days"]))
    news = sorted((i for i in merged.values() if i["date"] >= cutoff),
                  key=lambda x: x["date"], reverse=True)[: CONFIG["max_items"]]

    ransom = fetch_ransomware(errors)
    rlook = fetch_ransomlook(errors)
    # se una delle due fonti non risponde, per quella si riusano i dati precedenti
    old = prev.get("ransomware", [])
    if ransom is None:
        ransom = [r for r in old if "ransomware.live" in r.get("sources", ["ransomware.live"])]
    if rlook is None:
        rlook = [r for r in old if r.get("sources") == ["RansomLook"]]
    ransom = merge_victims(ransom, rlook)
    kev = fetch_kev(errors)
    if kev is None:
        kev = prev.get("kev", [])

    actors = build_actors(errors, ransom)
    matcher = ActorMatcher(actors)
    watch = {matcher.canonical(w) for w in CONFIG.get("watchlist", [])}

    # etichette sulle notizie (ricalcolate ogni volta, cosi' valgono anche per lo storico)
    for n in news:
        text = f"{n['title']} {n['summary']}"
        n["actors"] = matcher.find(text)
        if n.get("tg_actor"):
            a = matcher.canonical(n["tg_actor"])
            n["actors"] = [a] + [x for x in n["actors"] if x != a]
        n["threat"] = bool(n["actors"]) or n["type"] == "claims" or bool(THREAT_RE and THREAT_RE.search(text))
        n["highlight"] = bool(HIGHLIGHT_RE and HIGHLIGHT_RE.search(text)) or \
            (n["lang"] == "tg" and bool(IT_RE.search(text)))
    for r in ransom:
        r["group"] = matcher.canonical(r["group"])

    # statistiche per gruppo negli ultimi N giorni
    since = iso(NOW - timedelta(days=CONFIG.get("actor_stats_days", 7)))
    stats = defaultdict(lambda: {"mentions": 0, "claims": 0, "claims_it": 0, "last": ""})
    for n in news:
        if n["date"] >= since:
            if n.get("tg_actor"):  # un post sul canale del gruppo conta come rivendicazione
                s = stats[n["actors"][0]]; s["claims"] += 1; s["last"] = max(s["last"], n["date"])
                s["claims_it"] += bool(IT_RE.search(n["title"] + " " + n["summary"]))
                continue
            for a in n["actors"]:
                s = stats[a]; s["mentions"] += 1; s["last"] = max(s["last"], n["date"])
    for r in ransom:
        if r["date"] >= since[:19]:
            s = stats[r["group"]]; s["claims"] += 1; s["claims_it"] += r["country"] == "IT"
            s["last"] = max(s["last"], r["date"])
    for w in watch:  # i gruppi in watchlist compaiono sempre
        stats[w]
    actor_list = []
    for name, s in stats.items():
        a = actors.get(name, {"type": "ransomware", "country": ""})
        actor_list.append({"name": name, "type": a["type"], "country": a["country"],
                           "watch": name in watch, **s})
    actor_list.sort(key=lambda x: (x["watch"], x["claims"] + 3 * x["mentions"]), reverse=True)

    # malware e IoC
    if ABUSE_KEY:
        tf, uh, mb = fetch_threatfox(errors), fetch_urlhaus(errors), fetch_bazaar(errors)
    else:
        tf = uh = mb = None
        errors.append("abuse.ch: chiave non configurata (secret ABUSECH_AUTH_KEY)")
    tf = tf if tf is not None else prev.get("iocs", [])
    uh = uh if uh is not None else prev.get("urlhaus", [])
    fam = Counter(i["malware"] for i in tf if i["malware"] and i["malware"].lower() != "unknown malware")
    for s_ in (mb or []):
        if s_["sig"]:
            fam[s_["sig"]] += 1
    malware_top = [{"name": k, "count": v} for k, v in fam.most_common(25)] if (tf or mb) else prev.get("malware_top", [])
    camp_posts, camp_weekly = agid_campaigns(news)
    radar = fetch_radar(errors) or prev.get("radar", {})

    result = {
        "updated": iso(NOW),
        "news": news,
        "ransomware": ransom,
        "kev": kev,
        "actors": actor_list[:250],
        "actor_types": {n: a["type"] for n, a in actors.items()
                        if n in stats or any(n in x["actors"] for x in news)},
        "known_actors": len(actors),
        "iocs": tf[:200],
        "urlhaus": uh,
        "malware_top": malware_top,
        "agid_campaigns": [{k: p[k] for k in ("title", "link", "summary", "date")} for p in camp_posts],
        "agid_weekly": camp_weekly,
        "radar": radar,
        "telegram_channels": [c.get("name", "") for c in CONFIG.get("telegram_channels", [])],
        "errors": errors,
    }
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"news={len(news)} ransomware={len(ransom)} kev={len(kev)} "
          f"gruppi_noti={len(actors)} gruppi_attivi={len(actor_list)} errori={len(errors)}")
    for e in errors:
        print("  !", e[:200])


if __name__ == "__main__":
    main()
