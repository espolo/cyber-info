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
            parsed, last_err = None, None
            for url in [f["url"], *f.get("fallback_urls", [])]:
                try:
                    r = requests.get(url, headers=BROWSER_UA, timeout=25)
                    r.raise_for_status()
                    parsed = feedparser.parse(r.content)
                    if parsed.entries:
                        break
                    last_err = "feed vuoto o non valido"
                except Exception as ex:
                    last_err = ex
            if not parsed or not parsed.entries:
                raise Exception(last_err)
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
    try:
        d = abuse_post("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/")
    except Exception as ex:
        errors.append(f"URLhaus: {ex}")
        return None
    out = []
    for u in d.get("urls") or []:
        host = (u.get("host") or "").lower()
        out.append({
            "ioc": defang(u.get("url", "")),
            "host_it": host.endswith(".it"),
            "status": u.get("url_status", ""),
            "threat": u.get("threat", ""),
            "tags": u.get("tags") or [],
            "date": str(u.get("date_added", "")).replace(" UTC", "").replace(" ", "T")[:19],
            "link": u.get("urlhaus_reference", ""),
        })
    # tutte le URL su domini .it + le 150 piu' recenti
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
    for i in fetch_feeds(errors):
        merged[i["id"]] = i
    cutoff = iso(NOW - timedelta(days=CONFIG["max_age_days"]))
    news = sorted((i for i in merged.values() if i["date"] >= cutoff),
                  key=lambda x: x["date"], reverse=True)[: CONFIG["max_items"]]

    ransom = fetch_ransomware(errors)
    if ransom is None:
        ransom = prev.get("ransomware", [])
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
        n["threat"] = bool(n["actors"]) or n["type"] == "claims" or bool(THREAT_RE and THREAT_RE.search(text))
        n["highlight"] = bool(HIGHLIGHT_RE and HIGHLIGHT_RE.search(text))
    for r in ransom:
        r["group"] = matcher.canonical(r["group"])

    # statistiche per gruppo negli ultimi N giorni
    since = iso(NOW - timedelta(days=CONFIG.get("actor_stats_days", 7)))
    stats = defaultdict(lambda: {"mentions": 0, "claims": 0, "claims_it": 0, "last": ""})
    for n in news:
        if n["date"] >= since:
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
