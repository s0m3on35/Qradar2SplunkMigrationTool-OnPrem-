#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse, csv, os, re, json, hashlib, shutil, tempfile, datetime, logging, ssl, urllib.parse, urllib.request, urllib.error, html as html_lib, tarfile, zipfile, base64
import xml.etree.ElementTree as ET
from typing import Optional, List, Dict, Any
try:
    import yaml
except ImportError:
    yaml = None

SEVERITIES = {"low","medium","high","critical"}
REQUIRED_CSV_COLUMNS = {"name", "aql"}
SUPPORTED_STATUS = ("auto", "partial", "manual_review", "unsupported")

class WarningCollector(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.WARNING)
        self.records = []

    def emit(self, record):
        self.records.append({"level": record.levelname, "message": record.getMessage()})

def sha256(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for chunk in iter(lambda:f.read(65536), b""): h.update(chunk)
    return h.hexdigest()

def atomic_write(path, data:str):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp_", text=True)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f: f.write(data)
        os.replace(tmp, path)
    except Exception:
        try: os.remove(tmp)
        except: pass
        raise

def ensure_dir(p): os.makedirs(p, exist_ok=True)

def load_yaml(p):
    if not p:
        return {}
    try:
        with open(p,"r",encoding="utf-8") as f:
            if yaml:
                return yaml.safe_load(f) or {}
            data={}
            stack=[(-1, data)]
            for lineno,line in enumerate(f,1):
                if "\t" in line:
                    logging.warning(f"YAML simple: tabulador ignorado en linea {lineno} de {p}")
                s=line.split("#",1)[0].rstrip()
                if not s or s.startswith("#"):
                    continue
                if ":" not in s:
                    logging.warning(f"YAML simple: linea {lineno} ignorada en {p}")
                    continue
                indent=len(line)-len(line.lstrip(" "))
                k,v=s.strip().split(":",1)
                key=k.strip()
                val=v.strip().strip("'\"")
                while stack and indent <= stack[-1][0]:
                    stack.pop()
                parent=stack[-1][1] if stack else data
                if val == "":
                    parent[key]={}
                    stack.append((indent, parent[key]))
                else:
                    if val.lower() in ("true","false"):
                        parent[key]=val.lower()=="true"
                    else:
                        parent[key]=val
            return data
    except Exception as e:
        logging.warning(f"No se pudo cargar YAML {p}: {e}")
        return {}

def deep_merge(base, override):
    out=dict(base or {})
    for k,v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k]=deep_merge(out[k], v)
        else:
            out[k]=v
    return out

def get_nested(d, path, default=None):
    cur=d or {}
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur=cur[part]
    return cur

def conf_value(v):
    return str(v or "").replace("\r", " ").replace("\n", " ").strip()

def spl_quote(v):
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'

def normalize_spl_value(v):
    raw = str(v or "").strip()
    if len(raw) >= 2 and raw[0] in ("'", '"') and raw[-1] == raw[0]:
        return spl_quote(raw[1:-1])
    return raw

def http_json(url, method="GET", data=None, headers=None, timeout=20, verify_ssl=True):
    body=None
    if data is not None:
        body=urllib.parse.urlencode(data).encode("utf-8")
    req=urllib.request.Request(url, data=body, method=method, headers=headers or {})
    ctx=None if verify_ssl else ssl._create_unverified_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        raw=resp.read().decode("utf-8", errors="replace")
        if not raw.strip():
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw":raw}

def splunk_headers(cfg):
    token=(cfg or {}).get("token")
    username=(cfg or {}).get("username")
    password=(cfg or {}).get("password")
    if token:
        return {"Authorization":f"Bearer {token}"}
    if username and password:
        raw=f"{username}:{password}".encode("utf-8")
        return {"Authorization":"Basic " + base64.b64encode(raw).decode("ascii")}
    return {}

def extract_search_terms(spl):
    indexes=sorted(set(re.findall(r"(?i)\bindex\s*=\s*([A-Za-z0-9_*.-]+)", spl or "")))
    sourcetypes=sorted(set(re.findall(r"(?i)\bsourcetype\s*=\s*([A-Za-z0-9_*:.-]+)", spl or "")))
    fields=sorted(set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|!=|>=|<=|>|<)", spl or "")))
    return {"indexes":indexes,"sourcetypes":sourcetypes,"fields":fields}

SECRET_KEYS={"password","token","authorization","secret","api_key","apikey"}
SECRET_EXACT_KEYS={"sec"}

def sanitize_secrets(value):
    if isinstance(value, dict):
        out={}
        for k,v in value.items():
            key=str(k).lower()
            if key in SECRET_EXACT_KEYS or any(secret in key for secret in SECRET_KEYS):
                out[k]="***REDACTED***" if v not in (None,"") else v
            else:
                out[k]=sanitize_secrets(v)
        return out
    if isinstance(value, list):
        return [sanitize_secrets(v) for v in value]
    return value

def truthy_profile(v, default=False):
    return norm_bool(v, default)

def norm_bool(v, default=True):
    if isinstance(v, bool): return v
    s = str(v).strip().lower()
    if s in ("true","1","yes","y"): return True
    if s in ("false","0","no","n"): return False
    return default

def norm_severity(s):
    s = str(s or "medium").strip().lower()
    if s not in SEVERITIES:
        logging.warning(f"Severidad desconocida '{s}', usando 'medium'")
        return "medium"
    return s

def norm_cron(c):
    c = (c or "* * * * *").strip()
    if len(c.split()) != 5:
        logging.warning(f"Cron inválido '{c}', usando '* * * * *'")
        return "* * * * *"
    return c

def norm_throttle(w):
    w = (w or "0").strip()
    if w == "0": return "0"
    if re.fullmatch(r"\d+[smhd]", w): return w
    logging.warning(f"Throttle inválido '{w}', usando '15m'")
    return "15m"

def sanitize_name(name):
    x = re.sub(r"[^A-Za-z0-9_\-]+","_", (name or "Rule").strip())
    return x[:120] if x else "Rule"

def extract_aql_fields(aql):
    fields=set()
    patterns=[
        r"(?i)\bWHERE\b(.+?)(?:(?:\bGROUP\b)|(?:\bLAST\b)|$)",
        r"(?i)\bGROUP BY\b\s+(.+?)(?:\bHAVING\b|$)",
        r"(?i)\bHAVING\b\s+(.+)$",
    ]
    for pat in patterns:
        m=re.search(pat, aql or "")
        if not m:
            continue
        segment=re.sub(r"'[^']*'|\"[^\"]*\"", " ", m.group(1))
        segment=re.sub(r"BB:[A-Za-z0-9_ .:-]+", " ", segment)
        for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", segment):
            low=token.lower()
            if low not in {"and","or","not","in","like","matches","is","null","true","false","count","as","reference","set"}:
                fields.add(low)
    return sorted(fields)

def assess_rule(rule, fmap, bb, refsets, profile):
    aql=rule.get("aql","")
    fields=extract_aql_fields(aql)
    aliases={m.group(1).lower() for m in re.finditer(r"(?i)\bAS\s+([A-Za-z_]\w*)", aql)}
    fields=[f for f in fields if f not in aliases]
    unmapped=[f for f in fields if f not in fmap and not f.startswith("bb")]
    dependencies=[]
    issues=[]
    unsupported=[]
    upper=aql.upper()

    for bb_name in bb:
        if bb_name in aql:
            dependencies.append({"type":"building_block","name":bb_name,"status":"mapped"})
    for setname in re.findall(r"(?i)\bIN\s+REFERENCE\s+SET\s+['\"]([^'\"]+)['\"]", aql):
        if setname in refsets:
            dependencies.append({"type":"reference_set","name":setname,"status":"mapped"})
        else:
            dependencies.append({"type":"reference_set","name":setname,"status":"missing"})
            issues.append(f"Reference set no definido: {setname}")

    unsupported_patterns={
        "REFERENCE MAP": "Reference maps requieren modelado manual como lookup multicolumna.",
        "REFERENCE TABLE": "Reference tables requieren exportacion y transforms especificos.",
        "ACCUMULATE": "Acumuladores QRadar no tienen traduccion directa.",
        "FOLLOWED BY": "Secuencias temporales requieren SPL especifico.",
        "NOT FOLLOWED BY": "Ausencia/secuencia negativa requiere SPL especifico.",
        "GEO::": "Funciones GEO QRadar requieren equivalencia en Splunk.",
        "MAGNITUDE": "Magnitude QRadar necesita mapping de severidad/riesgo.",
    }
    for token, msg in unsupported_patterns.items():
        if token in upper:
            unsupported.append(token)
            issues.append(msg)

    if unmapped:
        issues.append("Campos sin mapping: " + ", ".join(unmapped))
    if "SELECT " in upper and " FROM " not in upper:
        issues.append("AQL incompleto o no estandar.")
    if re.search(r"(?i)\bJOIN\b|\bUNION\b", aql):
        unsupported.append("JOIN/UNION")
        issues.append("JOIN/UNION requiere revision manual.")

    if unsupported:
        status="unsupported"
        confidence=0.2
    elif issues:
        status="partial"
        confidence=0.65 if len(unmapped) <= 2 else 0.45
    else:
        status="auto"
        confidence=0.9

    if rule.get("notable") and not get_nested(profile, "splunk.enterprise_security", False):
        issues.append("Regla notable generada en savedsearches; valida si Splunk ES esta instalado.")
        if status == "auto":
            status="partial"
            confidence=0.75

    return {
        "status": status,
        "confidence": confidence,
        "fields": fields,
        "unmapped_fields": unmapped,
        "dependencies": dependencies,
        "issues": issues,
    }

def detect_duplicates(stanzas, autofix=True):
    seen = {}
    out = []
    for s in stanzas:
        if s in seen:
            if autofix:
                i = seen[s] + 1
                ns = f"{s}_{i}"
                while ns in seen: 
                    i += 1
                    ns = f"{s}_{i}"
                seen[s] = i
                out.append(ns)
                logging.warning(f"Duplicado '{s}' → renombrado a '{ns}'")
            else:
                out.append(s)
        else:
            seen[s]=0; out.append(s)
    return out

def expand_building_blocks(aql, bb):
    for _ in range(10):
        found=False
        for k,v in sorted(bb.items(), key=lambda x: len(x[0]), reverse=True):
            if k in aql:
                aql=aql.replace(k, f"({v})"); found=True
        if not found: break
    else:
        logging.error("Posible bucle en Building Blocks")
    return aql

def parse_xml_rules(xml_path):
    out=[]
    try:
        tree=ET.parse(xml_path); root=tree.getroot()
    except Exception as e:
        logging.error(f"No se pudo parsear XML {xml_path}: {e}")
        return out
    for r in root.findall(".//rule"):
        name=(r.findtext("name") or "").strip() or "QRadar_Rule"
        aql=(r.findtext("aql") or "").strip()
        enabled=norm_bool(r.findtext("enabled"), True)
        cron=norm_cron(r.findtext("cron"))
        notable=norm_bool(r.findtext("notable"), False)
        severity=norm_severity(r.findtext("severity"))
        desc=(r.findtext("description") or "").strip()
        out.append({"name":name,"aql":aql,"enabled":enabled,"cron":cron,"notable":notable,
                    "severity":severity,"description":desc,"throttle_window":"0","risk_score":"0","throttle_keys":"user,src"})
    return out

def normalize_qradar_rule(item):
    name=item.get("name") or item.get("rule_name") or item.get("identifier") or "QRadar_Rule"
    aql=item.get("aql") or item.get("query") or item.get("test") or item.get("expression") or ""
    enabled=norm_bool(item.get("enabled", item.get("is_enabled", True)), True)
    desc=conf_value(item.get("description",""))
    severity=norm_severity(item.get("severity", item.get("magnitude", "medium")))
    return {
        "name":name,
        "aql":aql,
        "enabled":enabled,
        "cron":"*/5 * * * *",
        "notable":True,
        "severity":severity,
        "description":desc,
        "throttle_window":"0",
        "risk_score":"0",
        "throttle_keys":"user,src",
    }

def qradar_headers(cfg):
    token=(cfg or {}).get("token") or (cfg or {}).get("sec_token")
    headers={"Accept":"application/json"}
    if token:
        headers["SEC"]=token
    return headers

def export_qradar_inventory(qradar_cfg, outdir):
    url=(qradar_cfg or {}).get("url")
    if not url:
        logging.warning("Export QRadar omitido: falta qradar.url")
        return {"enabled":False,"error":"missing_url","rules":[]}
    verify_ssl=norm_bool((qradar_cfg or {}).get("verify_ssl", True), True)
    timeout=int((qradar_cfg or {}).get("timeout", 30))
    base=url.rstrip("/")
    endpoints={
        "rules":"/api/analytics/rules",
        "building_blocks":"/api/analytics/building_blocks",
        "reference_sets":"/api/reference_data/sets",
        "log_sources":"/api/config/event_sources/log_source_management/log_sources",
        "log_source_types":"/api/config/event_sources/log_source_management/log_source_types",
        "custom_properties":"/api/config/event_sources/custom_properties/property_expressions",
    }
    inventory={"enabled":True,"url":base,"objects":{},"errors":[]}
    headers=qradar_headers(qradar_cfg)
    for name,path in endpoints.items():
        try:
            data=http_json(base+path, headers=headers, timeout=timeout, verify_ssl=verify_ssl)
            inventory["objects"][name]=data
        except urllib.error.HTTPError as e:
            inventory["errors"].append({"object":name,"status":e.code,"error":e.read().decode("utf-8", errors="replace")[:1000]})
            inventory["objects"][name]=[]
        except Exception as e:
            inventory["errors"].append({"object":name,"error":str(e)})
            inventory["objects"][name]=[]
    ensure_dir(outdir)
    inv_path=os.path.join(outdir,"qradar_inventory.json")
    with open(inv_path,"w",encoding="utf-8") as f:
        json.dump(inventory, f, indent=2, ensure_ascii=False)
    rules=[]
    raw_rules=inventory["objects"].get("rules") or []
    if isinstance(raw_rules, dict):
        raw_rules=raw_rules.get("items") or raw_rules.get("rules") or []
    for item in raw_rules:
        if isinstance(item, dict):
            rule=normalize_qradar_rule(item)
            if rule["aql"]:
                rules.append(rule)
    return {"enabled":True,"path":inv_path,"rules":rules,"errors":inventory["errors"],"object_counts":{k:len(v) if isinstance(v,list) else 1 for k,v in inventory["objects"].items()}}

def load_review_state(path):
    data=load_yaml(path) if path else {}
    reviews=data.get("reviews", data) if isinstance(data, dict) else {}
    if not isinstance(reviews, dict):
        return {}
    return reviews

def apply_review_state(report, reviews):
    if not reviews:
        report["review_state"]={"enabled":False,"reviewed":0}
        return report
    reviewed=0
    for rule in report.get("rules", []):
        keys=[rule.get("name"), rule.get("stanza")]
        review={}
        for k in keys:
            if k in reviews and isinstance(reviews[k], dict):
                review=reviews[k]
                break
        if review:
            reviewed+=1
            rule["review"]=review
            status=review.get("status")
            if status in ("approved","accepted","validated"):
                rule["compatibility"]["review_status"]="approved"
            elif status in ("rejected","discarded"):
                rule["compatibility"]["review_status"]="rejected"
            else:
                rule["compatibility"]["review_status"]=status or "in_review"
        else:
            rule["review"]={"status":"pending"}
            rule["compatibility"]["review_status"]="pending"
    report["review_state"]={"enabled":True,"reviewed":reviewed,"pending":len(report.get("rules",[]))-reviewed}
    return report

def load_csv_rules(csv_path):
    out=[]
    with open(csv_path, newline="", encoding="utf-8") as f:
        rd=csv.reader(f)
        header=next(rd, [])
        header=[h.strip() for h in header]
        missing = REQUIRED_CSV_COLUMNS - set(header or [])
        if missing:
            raise ValueError(f"CSV {csv_path} sin columnas obligatorias: {', '.join(sorted(missing))}")
        for i,raw in enumerate(rd,2):
            if not raw or not any(x.strip() for x in raw):
                continue
            if len(raw) == len(header):
                row=dict(zip(header, raw))
            else:
                bool_idx=None
                for pos in range(2, len(raw)):
                    if raw[pos].strip().lower() in ("true","false","yes","no","1","0"):
                        bool_idx=pos
                        break
                if bool_idx is None:
                    logging.warning(f"[CSV L{i}] columnas no cuadran y no se pudo reconstruir; se omite")
                    continue
                tail=raw[bool_idx:]
                fixed_tail=tail[:7] + [",".join(tail[7:]) if len(tail) > 7 else ""]
                values=[raw[0], ",".join(raw[1:bool_idx])] + fixed_tail
                if len(values) < len(header):
                    values += [""] * (len(header)-len(values))
                row=dict(zip(header, values[:len(header)]))
                logging.warning(f"[CSV L{i}] columnas reconstruidas; entrecomilla el AQL si contiene comas")
            name=sanitize_name(row.get("name","Rule"))
            aql=(row.get("aql","") or "").strip()
            if not aql: logging.warning(f"[CSV L{i}] sin AQL, se omite"); continue
            enabled=norm_bool(row.get("enabled","true"))
            cron=norm_cron(row.get("cron"))
            notable=norm_bool(row.get("notable","false"))
            severity=norm_severity(row.get("severity","medium"))
            desc=conf_value(row.get("description",""))
            throttle=norm_throttle(row.get("throttle_window","0"))
            risk=str(row.get("risk_score","0")).strip()
            tkeys=(row.get("throttle_keys","user,src") or "user,src")
            out.append({"name":name,"aql":aql,"enabled":enabled,"cron":cron,"notable":notable,
                        "severity":severity,"description":desc,"throttle_window":throttle,"risk_score":risk,"throttle_keys":tkeys})
    return out

def translate_aql(aql, fmap, bb, refsets, default_index):
    src=aql.strip().rstrip(";")
    if bb: src=expand_building_blocks(src, bb)
    m=re.search(r"(?i)LAST\s+(\d+)\s+([A-Z]+)", src)
    mcount=re.search(r"(?i)\bCOUNT\s*\(\s*\*\s*\)\s+AS\s+([A-Za-z_]\w*)", src)
    count_alias=mcount.group(1) if mcount else "count"
    earliest=""; unitmap={"MINUTES":"m","HOURS":"h","DAYS":"d","MINUTE":"m","HOUR":"h","DAY":"d"}
    if m:
        earliest=f' earliest=-{m.group(1)}{unitmap.get(m.group(2).upper(),"m")} latest=now'
    mwhere=re.search(r"(?i)\bWHERE\b(.+?)(?:(?:\bGROUP\b)|(?:\bLAST\b)|$)", src)
    cond=mwhere.group(1).strip() if mwhere else ""
    def fmap_field(tok):
        k=tok.strip().lower()
        return fmap.get(k, tok)
    extra_pipes=[]
    if cond:
        def ref_repl(m):
            field=fmap_field(m.group(1)); setname=m.group(2).strip("'\"")
            info=refsets.get(setname)
            if not info:
                logging.warning(f"Reference set '{setname}' no definido")
                return "true()"
            lookup=info["lookup_csv_path"]; key=info["key_field"]
            marker=f'_hit_{sanitize_name(setname)}'
            extra_pipes.append(f'lookup {lookup} {key} as {field} OUTPUTNEW {key} as {marker}')
            extra_pipes.append(f'where isnotnull({marker})')
            return "true()"
        cond=re.sub(r'(?i)\b(\w+)\s+IN\s+REFERENCE\s+SET\s+(\'[^\']+\'|\"[^\"]+\")', ref_repl, cond)
        def not_in_repl(m):
            field=fmap_field(m.group(1)); items=[x.strip().strip("'\"") for x in m.group(2).split(",")]
            return "NOT ("+" OR ".join([f'{field}={spl_quote(v)}' for v in items])+")"
        cond=re.sub(r"(?i)\b(\w+)\s+NOT\s+IN\s*\(([^)]+)\)", not_in_repl, cond)
        def in_repl(m):
            field=fmap_field(m.group(1)); items=[x.strip().strip("'\"") for x in m.group(2).split(",")]
            return "("+" OR ".join([f'{field}={spl_quote(v)}' for v in items])+")"
        cond=re.sub(r"(?i)\b(\w+)\s+IN\s*\(([^)]+)\)", in_repl, cond)
        def not_like_repl(m):
            field=fmap_field(m.group(1)); pat=m.group(2).strip().strip("'\"")
            return f'NOT like({field}, {spl_quote(pat)})'
        cond=re.sub(r"(?i)\b(\w+)\s+NOT\s+LIKE\s+('.*?'|\".*?\")", not_like_repl, cond)
        def like_repl(m):
            field=fmap_field(m.group(1)); pat=m.group(2).strip().strip("'\"")
            return f'like({field}, {spl_quote(pat)})'
        cond=re.sub(r"(?i)\b(\w+)\s+LIKE\s+('.*?'|\".*?\")", like_repl, cond)
        def matches_repl(m):
            field=fmap_field(m.group(1)); rx=m.group(2).strip().strip("'\"")
            return f'match({field}, {spl_quote(rx)})'
        cond=re.sub(r"(?i)\b(\w+)\s+matches\s+('.*?'|\".*?\")", matches_repl, cond)
        def null_repl(m):
            field=fmap_field(m.group(1)); neg=m.group(2) or ""
            return f'isnotnull({field})' if neg.strip().upper() == "NOT" else f'isnull({field})'
        cond=re.sub(r"(?i)\b(\w+)\s+IS\s+(NOT\s+)?NULL\b", null_repl, cond)
        def op_repl(m):
            left,op,right=m.group(1),m.group(2),m.group(3)
            return f'{fmap_field(left)}{op}{normalize_spl_value(right)}'
        cond=re.sub(r"\b([A-Za-z_]\w*)\s*(=|!=|>=|<=|>|<)\s*('[^']*'|\"[^\"]*\"|[^ \)]+)", op_repl, cond)
    base=f'search index={default_index}{earliest}'
    if cond: base+=f' | where {cond}'
    if extra_pipes:
        base+=" | "+" | ".join(extra_pipes)
    mg=re.search(r"(?i)\bGROUP BY\b\s+(.+?)(?:\bHAVING\b|$)", src)
    having=""
    mh=re.search(r"(?i)\bHAVING\b\s+(.+)$", src)
    if mh: having=mh.group(1).strip()
    if mg:
        fields=[fmap_field(x.strip()) for x in mg.group(1).split(",")]
        base+=f' | stats count as {count_alias} by {", ".join(fields)}'
        if having:
            base+=f' | where {having}'
    return base

def validate_splunk_searches(report, splunk_cfg):
    url=(splunk_cfg or {}).get("url")
    if not url:
        return report
    token=(splunk_cfg or {}).get("token")
    username=(splunk_cfg or {}).get("username")
    password=(splunk_cfg or {}).get("password")
    verify_ssl=norm_bool((splunk_cfg or {}).get("verify_ssl", True), True)
    timeout=int((splunk_cfg or {}).get("timeout", 20))
    if not token and not (username and password):
        logging.warning("Validacion Splunk omitida: faltan token o usuario/password")
        report["splunk_validation"]={"enabled":False,"error":"missing_credentials"}
        return report

    base=url.rstrip("/")
    parser_endpoint=f"{base}/services/search/parser"
    ctx=None if verify_ssl else ssl._create_unverified_context()
    headers=splunk_headers(splunk_cfg)
    report["splunk_validation"]={"enabled":True,"url":base,"results":[],"environment":{"indexes":[],"sourcetypes":[]}}

    try:
        indexes=http_json(f"{base}/services/data/indexes", data={"output_mode":"json","count":"0"}, headers=headers, timeout=timeout, verify_ssl=verify_ssl)
        report["splunk_validation"]["environment"]["indexes"]=[e.get("name") for e in indexes.get("entry",[]) if isinstance(e,dict)]
    except Exception as e:
        report["splunk_validation"]["environment"]["index_error"]=str(e)
    try:
        sourcetypes=http_json(f"{base}/services/saved/sourcetypes", data={"output_mode":"json","count":"0"}, headers=headers, timeout=timeout, verify_ssl=verify_ssl)
        report["splunk_validation"]["environment"]["sourcetypes"]=[e.get("name") for e in sourcetypes.get("entry",[]) if isinstance(e,dict)]
    except Exception as e:
        report["splunk_validation"]["environment"]["sourcetype_error"]=str(e)

    known_indexes=set(report["splunk_validation"]["environment"].get("indexes") or [])
    known_sourcetypes=set(report["splunk_validation"]["environment"].get("sourcetypes") or [])
    execute_sample=norm_bool(splunk_cfg.get("execute_sample", False), False)
    sample_earliest=splunk_cfg.get("sample_earliest","-24h")
    sample_latest=splunk_cfg.get("sample_latest","now")

    for rule in report.get("rules", []):
        data=urllib.parse.urlencode({"q": rule.get("spl",""), "output_mode":"json"}).encode("utf-8")
        req=urllib.request.Request(parser_endpoint, data=data, method="POST")
        for k,v in headers.items():
            req.add_header(k,v)
        terms=extract_search_terms(rule.get("spl",""))
        metadata={
            "indexes":terms["indexes"],
            "missing_indexes":[i for i in terms["indexes"] if "*" not in i and known_indexes and i not in known_indexes],
            "sourcetypes":terms["sourcetypes"],
            "missing_sourcetypes":[s for s in terms["sourcetypes"] if "*" not in s and known_sourcetypes and s not in known_sourcetypes],
            "fields":terms["fields"],
        }
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body=resp.read().decode("utf-8", errors="replace")
                parsed=json.loads(body) if body.strip() else {}
                result={"rule":rule.get("name"),"stanza":rule.get("stanza"),"valid":True,"metadata":metadata,"response":parsed}
        except urllib.error.HTTPError as e:
            body=e.read().decode("utf-8", errors="replace")
            result={"rule":rule.get("name"),"stanza":rule.get("stanza"),"valid":False,"metadata":metadata,"status":e.code,"error":body[:1000]}
        except Exception as e:
            result={"rule":rule.get("name"),"stanza":rule.get("stanza"),"valid":False,"metadata":metadata,"error":str(e)}
        if execute_sample and result.get("valid"):
            sample_search=rule.get("spl","")
            if not sample_search.lower().startswith("search "):
                sample_search="search " + sample_search
            try:
                sample=http_json(f"{base}/services/search/jobs/export",
                                 data={"search":sample_search + " | head 1", "earliest_time":sample_earliest, "latest_time":sample_latest, "output_mode":"json"},
                                 headers=headers, timeout=timeout, verify_ssl=verify_ssl)
                result["sample_execution"]={"enabled":True,"ok":True,"response":sample}
            except urllib.error.HTTPError as e:
                result["sample_execution"]={"enabled":True,"ok":False,"status":e.code,"error":e.read().decode("utf-8", errors="replace")[:1000]}
            except Exception as e:
                result["sample_execution"]={"enabled":True,"ok":False,"error":str(e)}
        report["splunk_validation"]["results"].append(result)
    return report

def write_compatibility_html(path, report):
    rows=[]
    for r in report.get("rules", []):
        c=r.get("compatibility", {})
        issues="<br>".join(html_lib.escape(conf_value(x)) for x in c.get("issues", [])) or "-"
        unmapped=html_lib.escape(", ".join(c.get("unmapped_fields", [])) or "-")
        rows.append(
            "<tr>"
            f"<td>{html_lib.escape(conf_value(r.get('name')))}</td>"
            f"<td>{html_lib.escape(conf_value(r.get('stanza')))}</td>"
            f"<td>{html_lib.escape(conf_value(c.get('status')))}</td>"
            f"<td>{c.get('confidence','')}</td>"
            f"<td>{unmapped}</td>"
            f"<td>{issues}</td>"
            "</tr>"
        )
    html="""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>QRadar to Splunk Compatibility Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #1f2933; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 8px; vertical-align: top; }}
    th {{ background: #edf2f7; text-align: left; }}
    tr:nth-child(even) {{ background: #f8fafc; }}
  </style>
</head>
<body>
  <h1>QRadar to Splunk Compatibility Report</h1>
  <p>Generated: {generated}</p>
  <table>
    <thead><tr><th>Rule</th><th>Stanza</th><th>Status</th><th>Confidence</th><th>Unmapped fields</th><th>Issues</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>
""".format(generated=conf_value(report.get("generated")), rows="\n".join(rows))
    atomic_write(path, html)

def parse_conf_stanzas(content):
    stanzas={}
    current=None
    for lineno,line in enumerate(content.splitlines(),1):
        s=line.strip()
        if not s or s.startswith("#"):
            continue
        m=re.match(r"^\[([^\]]+)\]$", s)
        if m:
            current=m.group(1)
            stanzas.setdefault(current, {"line":lineno, "keys":{}})
            continue
        if current and "=" in line:
            k,v=line.split("=",1)
            stanzas[current]["keys"][k.strip()]=v.strip()
    return stanzas

def lint_splunk_app(app_dir, report):
    findings=[]
    def add(severity, check, message, path=None, stanza=None):
        findings.append({"severity":severity,"check":check,"message":message,"path":path,"stanza":stanza})

    required=[
        os.path.join("local","savedsearches.conf"),
        os.path.join("local","macros.conf"),
        os.path.join("default","app.conf"),
        os.path.join("metadata","local.meta"),
        os.path.join("metadata","default.meta"),
    ]
    for rel in required:
        p=os.path.join(app_dir, rel)
        if not os.path.exists(p):
            add("error","required_file",f"Falta fichero requerido: {rel}",rel)

    saved_path=os.path.join(app_dir,"local","savedsearches.conf")
    if os.path.exists(saved_path):
        with open(saved_path,"r",encoding="utf-8") as f:
            stanzas=parse_conf_stanzas(f.read())
        for stanza,info in stanzas.items():
            keys=info["keys"]
            if not keys.get("search"):
                add("error","empty_search","Saved search sin search","local/savedsearches.conf",stanza)
            elif keys["search"].strip() in ("search index=*", "search index=main"):
                add("warning","broad_search","Busqueda demasiado amplia; revisa index/time range","local/savedsearches.conf",stanza)
            if not keys.get("cron_schedule"):
                add("warning","missing_cron","Saved search sin cron_schedule","local/savedsearches.conf",stanza)
            if keys.get("action.notable") == "1" and not keys.get("action.notable.severity"):
                add("warning","notable_severity","Notable sin severidad","local/savedsearches.conf",stanza)

    transforms_path=os.path.join(app_dir,"local","transforms.conf")
    if os.path.exists(transforms_path):
        with open(transforms_path,"r",encoding="utf-8") as f:
            transforms=parse_conf_stanzas(f.read())
        for stanza,info in transforms.items():
            lookup=info["keys"].get("filename")
            if lookup and not os.path.exists(os.path.join(app_dir,"lookups",lookup)):
                add("warning","missing_lookup_file",f"Lookup declarado pero no copiado a app/lookups: {lookup}","local/transforms.conf",stanza)

    statuses={}
    for rule in report.get("rules", []):
        status=rule.get("compatibility",{}).get("status","unknown")
        statuses[status]=statuses.get(status,0)+1
    if statuses.get("unsupported",0):
        add("error","unsupported_rules",f"Hay {statuses['unsupported']} reglas no soportadas")
    if statuses.get("partial",0):
        add("warning","partial_rules",f"Hay {statuses['partial']} reglas que requieren validacion")

    return {
        "summary":{
            "errors":sum(1 for f in findings if f["severity"]=="error"),
            "warnings":sum(1 for f in findings if f["severity"]=="warning"),
            "info":sum(1 for f in findings if f["severity"]=="info"),
        },
        "findings":findings,
    }

def write_executive_summary(path, report):
    counts={}
    for r in report.get("rules", []):
        s=r.get("compatibility",{}).get("status","unknown")
        counts[s]=counts.get(s,0)+1
    lint=report.get("app_lint",{}).get("summary",{})
    lines=[
        "# QRadar to Splunk Migration Summary",
        "",
        f"- Generated: {report.get('generated')}",
        f"- Environment: {report.get('environment')}",
        f"- App: {report.get('app')}",
        f"- Rules processed: {len(report.get('rules', []))}",
        f"- Auto: {counts.get('auto',0)}",
        f"- Partial: {counts.get('partial',0)}",
        f"- Manual review: {counts.get('manual_review',0)}",
        f"- Unsupported: {counts.get('unsupported',0)}",
        f"- Lint errors: {lint.get('errors',0)}",
        f"- Lint warnings: {lint.get('warnings',0)}",
        "",
        "## Priority Actions",
        "",
    ]
    actions=[]
    for r in report.get("rules", []):
        c=r.get("compatibility",{})
        if c.get("status") != "auto":
            issues="; ".join(c.get("issues", [])) or "Validate generated SPL."
            actions.append(f"- {r.get('name')}: {c.get('status')} ({c.get('confidence')}) - {issues}")
    if not actions:
        actions.append("- No priority manual actions detected.")
    lines.extend(actions)
    lines.extend(["", "## Generated Outputs", ""])
    for name,meta in sorted((report.get("outputs") or {}).items()):
        lines.append(f"- {name}: {meta.get('path')}")
    atomic_write(path, "\n".join(lines)+"\n")

def package_splunk_app(outdir, app_name):
    app_dir=os.path.join(outdir,"app")
    package_dir=os.path.join(outdir,"packages")
    ensure_dir(package_dir)
    package_name=f"{sanitize_name(app_name)}.tgz"
    package_path=os.path.join(package_dir, package_name)
    root_name=sanitize_name(app_name)
    with tarfile.open(package_path, "w:gz") as tar:
        for dirpath, _, filenames in os.walk(app_dir):
            for filename in filenames:
                full=os.path.join(dirpath, filename)
                rel=os.path.relpath(full, app_dir)
                tar.add(full, arcname=os.path.join(root_name, rel))
    return package_path

def preflight_check(args, profile, splunk_profile, qradar_profile, review_path):
    checks=[]
    def add(status, check, message):
        checks.append({"status":status,"check":check,"message":message})

    if args.profile:
        add("ok" if os.path.exists(args.profile) else "error", "profile", f"Profile: {args.profile}")
    if not args.app or sanitize_name(args.app) != args.app:
        add("warning", "app_name", f"App name sera normalizado a {sanitize_name(args.app)}")
    else:
        add("ok", "app_name", f"App name valido: {args.app}")
    if args.default_index in (None,"","*"):
        add("warning", "default_index", "Default index vacio o wildcard; revisa antes de produccion")
    else:
        add("ok", "default_index", f"Default index: {args.default_index}")

    for label,path,required in (
        ("input_csv", args.input_csv, False),
        ("input_xml", args.xml, False),
        ("field_map", args.field_map, True),
        ("building_blocks", args.building_blocks, False),
        ("reference_sets", args.reference_sets, False),
        ("review_state", review_path, False),
    ):
        if path:
            add("ok" if os.path.exists(path) else ("error" if required else "warning"), label, f"{path}")
        elif required:
            add("error", label, "Ruta obligatoria no informada")

    try:
        ensure_dir(args.outdir)
        probe=os.path.join(args.outdir,".preflight_write_test")
        atomic_write(probe, "ok\n")
        os.remove(probe)
        add("ok","outdir",f"Escribible: {args.outdir}")
    except Exception as e:
        add("error","outdir",f"No escribible: {args.outdir} ({e})")

    if splunk_profile.get("validate"):
        if not splunk_profile.get("url"):
            add("error","splunk_url","Validacion Splunk activa pero falta URL")
        if not splunk_profile.get("token") and not (splunk_profile.get("username") and splunk_profile.get("password")):
            add("error","splunk_credentials","Validacion Splunk activa pero faltan credenciales")
    if qradar_profile.get("export"):
        if not qradar_profile.get("url"):
            add("error","qradar_url","Export QRadar activo pero falta URL")
        if not qradar_profile.get("token") and not qradar_profile.get("sec_token"):
            add("warning","qradar_token","Export QRadar activo sin token configurado")

    prod=str(profile.get("environment","")).lower() == "prod"
    if prod and not truthy_profile(get_nested(profile,"splunk.disable_searches", False), False) and not getattr(args,"disable_searches",False):
        add("warning","prod_enabled_searches","Entorno prod sin disable_searches; instala primero deshabilitado salvo decision explicita")

    errors=sum(1 for c in checks if c["status"]=="error")
    warnings=sum(1 for c in checks if c["status"]=="warning")
    return {"ok":errors==0,"errors":errors,"warnings":warnings,"checks":checks}

def build_readiness(report):
    blockers=[]
    warnings=[]
    lint=report.get("app_lint",{}).get("summary",{})
    audit=report.get("mapping_audit",{})
    review=report.get("review_state",{})
    statuses={}
    for r in report.get("rules",[]):
        s=r.get("compatibility",{}).get("status","unknown")
        statuses[s]=statuses.get(s,0)+1
    if lint.get("errors",0):
        blockers.append(f"Lint errors: {lint.get('errors')}")
    if statuses.get("unsupported",0):
        blockers.append(f"Unsupported rules: {statuses.get('unsupported')}")
    if audit.get("fields_unmapped",0):
        blockers.append(f"Unmapped fields: {audit.get('fields_unmapped')}")
    if review.get("enabled") and review.get("pending",0):
        warnings.append(f"Rules pending review: {review.get('pending')}")
    if lint.get("warnings",0):
        warnings.append(f"Lint warnings: {lint.get('warnings')}")
    if not report.get("splunk_validation",{}).get("enabled"):
        warnings.append("Splunk validation not executed")
    ready=not blockers
    return {"ready":ready,"blockers":blockers,"warnings":warnings,"status_counts":statuses}

def write_readiness_report(path, report):
    readiness=report.get("readiness",{})
    lines=[
        "# Migration Readiness Report",
        "",
        f"- Ready: {'yes' if readiness.get('ready') else 'no'}",
        f"- Generated: {report.get('generated')}",
        f"- Environment: {report.get('environment')}",
        f"- App: {report.get('app')}",
        "",
        "## Blockers",
        "",
    ]
    blockers=readiness.get("blockers") or ["No blockers detected."]
    lines.extend([f"- {b}" for b in blockers])
    lines.extend(["", "## Warnings", ""])
    warnings=readiness.get("warnings") or ["No warnings detected."]
    lines.extend([f"- {w}" for w in warnings])
    lines.extend(["", "## Status Counts", ""])
    for k,v in sorted((readiness.get("status_counts") or {}).items()):
        lines.append(f"- {k}: {v}")
    atomic_write(path, "\n".join(lines)+"\n")

def write_manifest(path, report, args, profile, input_paths):
    manifest={
        "tool":"qradar2splunk_portable",
        "version":"1.0.0",
        "generated":datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00","Z"),
        "app":report.get("app"),
        "environment":report.get("environment"),
        "parameters":sanitize_secrets(vars(args)),
        "profile":sanitize_secrets(profile),
        "inputs":{},
        "outputs":report.get("outputs",{}),
        "readiness":report.get("readiness",{}),
    }
    for label,p in input_paths.items():
        if p and os.path.exists(p) and os.path.isfile(p):
            manifest["inputs"][label]={"path":p,"sha256":sha256(p)}
    atomic_write(path, json.dumps(manifest, indent=2, ensure_ascii=False))

def build_mapping_audit(rows, report, fmap):
    field_usage={}
    actions=[]
    for idx, rule in enumerate(report.get("rules", [])):
        comp=rule.get("compatibility",{})
        source_row=rows[idx] if idx < len(rows) else {}
        for field in comp.get("fields", []):
            entry=field_usage.setdefault(field, {
                "qradar_field":field,
                "splunk_field":fmap.get(field,""),
                "mapped":field in fmap,
                "usage_count":0,
                "rules":[],
            })
            entry["usage_count"]+=1
            entry["rules"].append(rule.get("name"))
        for field in comp.get("unmapped_fields", []):
            actions.append({
                "priority":"high",
                "type":"mapping",
                "rule":rule.get("name"),
                "item":field,
                "action":f"Definir mapping para campo QRadar '{field}'",
            })
        if comp.get("status") != "auto":
            actions.append({
                "priority":"medium",
                "type":"rule_review",
                "rule":rule.get("name"),
                "item":comp.get("status"),
                "action":"Revisar SPL generado y validar contra datos reales",
            })
        if source_row.get("notable"):
            actions.append({
                "priority":"medium",
                "type":"notable_es",
                "rule":rule.get("name"),
                "item":"notable",
                "action":"Confirmar si se instalara en Splunk ES/RBA o como savedsearch core",
            })

    dependencies=[]
    for rule in report.get("rules", []):
        for dep in rule.get("compatibility",{}).get("dependencies", []):
            dependencies.append({
                "rule":rule.get("name"),
                "type":dep.get("type"),
                "name":dep.get("name"),
                "status":dep.get("status"),
            })

    rules=[]
    for rule in report.get("rules", []):
        comp=rule.get("compatibility",{})
        rules.append({
            "rule":rule.get("name"),
            "stanza":rule.get("stanza"),
            "status":comp.get("status"),
            "review_status":comp.get("review_status","pending"),
            "owner":rule.get("review",{}).get("owner",""),
            "confidence":comp.get("confidence"),
            "mapped_fields":len(comp.get("fields",[]))-len(comp.get("unmapped_fields",[])),
            "unmapped_fields":", ".join(comp.get("unmapped_fields",[])),
            "issues":"; ".join(comp.get("issues",[])),
            "spl":rule.get("spl"),
        })

    summary={
        "rules_total":len(report.get("rules",[])),
        "fields_total":len(field_usage),
        "fields_mapped":sum(1 for v in field_usage.values() if v["mapped"]),
        "fields_unmapped":sum(1 for v in field_usage.values() if not v["mapped"]),
        "actions_total":len(actions),
    }
    return {
        "summary":summary,
        "fields":sorted(field_usage.values(), key=lambda x:(not x["mapped"], -x["usage_count"], x["qradar_field"])),
        "rules":rules,
        "dependencies":dependencies,
        "actions":actions,
    }

def write_csv_rows(path, rows, fieldnames):
    with open(path,"w",encoding="utf-8",newline="") as f:
        writer=csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k:(", ".join(row.get(k,[])) if isinstance(row.get(k), list) else row.get(k,"")) for k in fieldnames})

def xlsx_col(n):
    s=""
    while n:
        n,rem=divmod(n-1,26)
        s=chr(65+rem)+s
    return s

def xlsx_sheet_xml(rows):
    out=['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
         '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>']
    for r_idx,row in enumerate(rows,1):
        out.append(f'<row r="{r_idx}">')
        for c_idx,value in enumerate(row,1):
            cell=f"{xlsx_col(c_idx)}{r_idx}"
            text=html_lib.escape(conf_value(value))
            out.append(f'<c r="{cell}" t="inlineStr"><is><t>{text}</t></is></c>')
        out.append('</row>')
    out.append('</sheetData></worksheet>')
    return "".join(out)

def write_migration_tracker_xlsx(path, audit):
    sheets=[
        ("Summary", [["Metric","Value"]] + [[k,v] for k,v in audit.get("summary",{}).items()]),
        ("Rules", [["Rule","Stanza","Status","Review","Owner","Confidence","Mapped fields","Unmapped fields","Issues","SPL"]] + [[r.get("rule"),r.get("stanza"),r.get("status"),r.get("review_status"),r.get("owner"),r.get("confidence"),r.get("mapped_fields"),r.get("unmapped_fields"),r.get("issues"),r.get("spl")] for r in audit.get("rules",[])]),
        ("Fields", [["QRadar field","Splunk field","Mapped","Usage count","Rules"]] + [[f.get("qradar_field"),f.get("splunk_field"),f.get("mapped"),f.get("usage_count"),", ".join(f.get("rules",[]))] for f in audit.get("fields",[])]),
        ("Dependencies", [["Rule","Type","Name","Status"]] + [[d.get("rule"),d.get("type"),d.get("name"),d.get("status")] for d in audit.get("dependencies",[])]),
        ("Actions", [["Priority","Type","Rule","Item","Action"]] + [[a.get("priority"),a.get("type"),a.get("rule"),a.get("item"),a.get("action")] for a in audit.get("actions",[])]),
    ]
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>%s</Types>' % "".join([f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' for i in range(1,len(sheets)+1)]))
        z.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        workbook_sheets="".join([f'<sheet name="{html_lib.escape(name)}" sheetId="{i}" r:id="rId{i}"/>' for i,(name,_) in enumerate(sheets,1)])
        z.writestr("xl/workbook.xml", f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>{workbook_sheets}</sheets></workbook>')
        rels="".join([f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>' for i in range(1,len(sheets)+1)])
        z.writestr("xl/_rels/workbook.xml.rels", f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{rels}</Relationships>')
        for i,(_,rows) in enumerate(sheets,1):
            z.writestr(f"xl/worksheets/sheet{i}.xml", xlsx_sheet_xml(rows))

def build_app(rows, outdir, app_name, default_index, fmap, bb, refsets, profile=None, dry_run=False, strict=False, no_autofix=False, backup=False, package=False, audit_only=False, reviews=None, disable_searches=False):
    ensure_dir(outdir)
    local_dir=os.path.join(outdir,"app","local")
    default_dir=os.path.join(outdir,"app","default")
    lookups_dir=os.path.join(outdir,"app","lookups")
    meta_dir=os.path.join(outdir,"app","metadata")
    for d in (local_dir, default_dir, lookups_dir, meta_dir): ensure_dir(d)

    saved_lines=["# savedsearches.conf"]
    corr_lines=["# correlationsearches.conf"]
    macros_lines=["[qradar2spl_index]\ndefinition = index={}\niseval = 0\n".format(default_index),
                  "[qradar2spl_timerange]\ndefinition = earliest=-15m latest=now\niseval = 0\n"]
    props_lines=["# props.conf"]
    transforms_lines=["# transforms.conf"]

    profile=profile or {}
    report={"generated":datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00","Z"),"app":sanitize_name(app_name),"environment":profile.get("environment","default"),"rules":[], "warnings":[], "errors":[], "outputs":{}, "dry_run":dry_run}
    stanzas=[sanitize_name(r["name"]) for r in rows]
    stanzas=detect_duplicates(stanzas, autofix=(not no_autofix))

    for i,r in enumerate(rows):
        stanza=stanzas[i]
        aql=r["aql"]
        try:
            spl=translate_aql(aql, fmap, bb, refsets, default_index)
        except Exception as e:
            logging.error(f"Error traduciendo AQL '{r['name']}': {e}")
            report["errors"].append({"rule":r["name"], "error":str(e)})
            if strict: raise
            else: continue
        enabled="0" if disable_searches else ("1" if r["enabled"] else "0")
        cron=r["cron"]
        notable=r["notable"]
        severity=r["severity"]
        desc=conf_value(r.get("description",""))
        throttle=r.get("throttle_window","0")
        tkeys=r.get("throttle_keys","user,src")

        saved_lines.append(f'[{stanza}]')
        saved_lines.append(f'search = {conf_value(spl)}')
        saved_lines.append(f'cron_schedule = {cron}')
        saved_lines.append(f'enabled = {enabled}')
        saved_lines.append(f'dispatch.earliest_time = 0')
        saved_lines.append(f'dispatch.latest_time = now')
        if desc: saved_lines.append(f'description = {desc}')
        if notable:
            saved_lines.append('action.notable = 1')
            saved_lines.append(f'action.notable.severity = {severity}')
            saved_lines.append('action.notable.rule_name = $name$')
            saved_lines.append('action.notable.category = Correlation')
            saved_lines.append('action.notable.drilldown_name = View Search Results')
            saved_lines.append('action.notable.drilldown_search = $search$')
            if throttle and throttle!="0":
                saved_lines.append('alert.suppress = 1')
                saved_lines.append(f'alert.suppress.fields = {",".join([k.strip() for k in tkeys.split(",") if k.strip()])}')
                saved_lines.append(f'alert.suppress.period = {throttle}')
        else:
            saved_lines.append('action.notable = 0')
        saved_lines.append("")

        if notable:
            corr_lines.append(f'[{stanza}]')
            corr_lines.append(f'annotations = risk_score={r.get("risk_score","0")}')
            corr_lines.append(f'description = {desc}')
            corr_lines.append('enabled = 1')
            corr_lines.append(f'severity = {severity}')
            corr_lines.append("")

        report["rules"].append({
            "name":r["name"],
            "stanza":stanza,
            "enabled":bool(int(enabled)),
            "notable":notable,
            "spl":spl,
            "compatibility":assess_rule(r, fmap, bb, refsets, profile),
        })

    apply_review_state(report, reviews or {})

    if len(saved_lines)<3:
        report["errors"].append({"error":"No se generaron savedsearches"})
        if strict: raise SystemExit("Fallo: savedsearches vacío")

    for setname, info in refsets.items():
        lookup = os.path.basename(info["lookup_csv_path"])
        transform = os.path.splitext(lookup)[0]
        transforms_lines.append(f'[{transform}]')
        transforms_lines.append(f'filename = {lookup}')
        transforms_lines.append("")

    files={
        "savedsearches.conf":"\n".join(saved_lines)+"\n",
        "correlationsearches.conf":"\n".join(corr_lines)+"\n",
        "macros.conf":"\n".join(macros_lines)+"\n",
        "props.conf":"\n".join(props_lines)+"\n",
        "transforms.conf":"\n".join(transforms_lines)+"\n",
        "app.conf":"[install]\nis_configured = 1\n\n[ui]\nis_visible = 1\nlabel = {}\n\n[launcher]\nauthor = QRadar2Splunk Toolkit\ndescription = App generada para migracion automatizada de reglas QRadar a Splunk.\nversion = 1.0.0\n".format(conf_value(app_name)),
        "metadata/local.meta":"[savedsearches]\nexport = system\n[transforms]\nexport = system\n[props]\nexport = system\n[lookups]\nexport = system\n",
        "metadata/default.meta":"[application]\nowner = admin\naccess = read : [ * ], write : [ admin ]\n"
    }

    if dry_run:
        print(f"[DRY-RUN] Validacion completada para app: {os.path.join(outdir,'app')}")
        print(f"[DRY-RUN] Reglas procesadas: {len(report['rules'])}; errores: {len(report['errors'])}")
        counts={}
        for r in report["rules"]:
            s=r.get("compatibility",{}).get("status","unknown")
            counts[s]=counts.get(s,0)+1
        print(f"[DRY-RUN] Compatibilidad: {counts}")
        return report

    if backup and not audit_only:
        ts=datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")
        bdir=os.path.join(outdir,f"backup_{ts}")
        os.makedirs(bdir, exist_ok=True)
        for rel in ("app/local/savedsearches.conf","app/local/correlationsearches.conf","app/local/macros.conf"):
            p=os.path.join(outdir, rel)
            if os.path.exists(p):
                os.makedirs(os.path.join(bdir, os.path.dirname(rel)), exist_ok=True)
                shutil.copy2(p, os.path.join(bdir, rel))

    # Escribir (atómico) + hashes
    if not audit_only:
        for rel,content in files.items():
            p=os.path.join(outdir,"app", "local" if rel.endswith(".conf") else "", rel if not rel.endswith(".conf") else os.path.basename(rel))
            if rel == "app.conf":
                p=os.path.join(outdir,"app","default","app.conf")
            if rel.startswith("metadata/"):
                p=os.path.join(outdir,"app","metadata", rel.split("/",1)[1])
            os.makedirs(os.path.dirname(p), exist_ok=True)
            atomic_write(p, content)
            report["outputs"][rel]= {"path":p, "sha256":sha256(p)}

    rep_path=os.path.join(outdir,"report.json")
    with open(rep_path,"w",encoding="utf-8") as f: json.dump(report, f, indent=2, ensure_ascii=False)
    compat_json=os.path.join(outdir,"compatibility_report.json")
    compat_html=os.path.join(outdir,"compatibility_report.html")
    summary_md=os.path.join(outdir,"executive_summary.md")
    readiness_md=os.path.join(outdir,"readiness_report.md")
    manifest_json=os.path.join(outdir,"manifest.json")
    audit_json=os.path.join(outdir,"mapping_audit.json")
    audit_csv=os.path.join(outdir,"mapping_audit.csv")
    tracker_xlsx=os.path.join(outdir,"migration_tracker.xlsx")
    compatibility={"generated":report["generated"],"app":report["app"],"environment":report.get("environment"),"rules":[{"name":r["name"],"stanza":r["stanza"],"compatibility":r["compatibility"]} for r in report["rules"]]}
    with open(compat_json,"w",encoding="utf-8") as f: json.dump(compatibility, f, indent=2, ensure_ascii=False)
    write_compatibility_html(compat_html, report)
    audit=build_mapping_audit(rows, report, fmap)
    with open(audit_json,"w",encoding="utf-8") as f: json.dump(audit, f, indent=2, ensure_ascii=False)
    write_csv_rows(audit_csv, audit["fields"], ["qradar_field","splunk_field","mapped","usage_count","rules"])
    write_migration_tracker_xlsx(tracker_xlsx, audit)
    report["mapping_audit"]=audit["summary"]
    report["app_lint"]=lint_splunk_app(os.path.join(outdir,"app"), report) if not audit_only else {"summary":{"errors":0,"warnings":0,"info":0},"findings":[]}
    report["readiness"]=build_readiness(report)
    report["outputs"]["compatibility_report.json"]={"path":compat_json,"sha256":sha256(compat_json)}
    report["outputs"]["compatibility_report.html"]={"path":compat_html,"sha256":sha256(compat_html)}
    report["outputs"]["mapping_audit.json"]={"path":audit_json,"sha256":sha256(audit_json)}
    report["outputs"]["mapping_audit.csv"]={"path":audit_csv,"sha256":sha256(audit_csv)}
    report["outputs"]["migration_tracker.xlsx"]={"path":tracker_xlsx,"sha256":sha256(tracker_xlsx)}
    if package and not audit_only:
        package_path=package_splunk_app(outdir, app_name)
        report["outputs"]["package"]={"path":package_path,"sha256":sha256(package_path)}
    write_executive_summary(summary_md, report)
    write_readiness_report(readiness_md, report)
    report["outputs"]["executive_summary.md"]={"path":summary_md,"sha256":sha256(summary_md)}
    report["outputs"]["readiness_report.md"]={"path":readiness_md,"sha256":sha256(readiness_md)}
    with open(rep_path,"w",encoding="utf-8") as f: json.dump(report, f, indent=2, ensure_ascii=False)

    if audit_only:
        print(f"[OK] Auditoria generada en: {outdir}")
    else:
        print(f"[OK] App generada en: {os.path.join(outdir,'app')}")
    print(f"[OK] Informe: {rep_path}")
    print(f"[OK] Compatibilidad: {compat_html}")
    print(f"[OK] Tracker Excel: {tracker_xlsx}")
    if package and not audit_only:
        print(f"[OK] Paquete Splunk: {package_path}")
    return report

def interactive_wizard()->int:
    print("=== QRadar → Splunk Migration Toolkit (Wizard) ===")
    def ask(prompt, default=""):
        p = f"{prompt} [{default}]: " if default else f"{prompt}: "
        v = input(p).strip()
        return v if v else default

    csv_path = ask("Ruta CSV de reglas", "samples/qradar_rules.csv")
    xml_path = ask("Ruta XML exportado (opcional)", "samples/qradar_rules_export.xml")
    outdir   = ask("Carpeta de salida", "output")
    app_name = ask("Nombre de la app", "My_SIEM_Migration")
    dindex   = ask("Índice por defecto", "main")
    fmap     = ask("Mappings de campos (YAML)", "mappings/field_map.yaml")
    bb_csv   = ask("Building Blocks (CSV)", "mappings/building_blocks.csv")
    rs_csv   = ask("Reference Sets (CSV)", "mappings/reference_sets.csv")

    def ask_bool(prompt, default=False):
        d = "y" if default else "n"
        v = input(f"{prompt} [y/n] ({d}): ").strip().lower()
        if v == "": return default
        return v in ("y","yes","1")

    use_backup = ask_bool("Hacer backup si existe salida previa?", True)
    use_strict = ask_bool("Strict mode (fallar ante errores)?", False)
    use_dryrun = ask_bool("Dry-run (no escribir ficheros)?", False)
    fail_warn  = ask_bool("Fail on warnings?", False)
    log_level  = ask("Nivel de log (INFO/DEBUG/WARN)", "INFO")

    print("\nResumen:")
    print(f"  CSV: {csv_path}")
    print(f"  XML: {xml_path}")
    print(f"  Outdir: {outdir}")
    print(f"  App: {app_name}")
    print(f"  Index: {dindex}")
    print(f"  Map: {fmap}")
    print(f"  BB: {bb_csv}")
    print(f"  RefSets: {rs_csv}")
    print(f"  Backup: {use_backup}  Strict: {use_strict}  Dry-run: {use_dryrun}  Fail-on-warn: {fail_warn}")
    ok = input("\n¿Proceder? (y/n): ").strip().lower()
    if ok not in ("y","yes"):
        print("Cancelado.")
        return 0

    argv = [
        "--outdir", outdir,
        "--app", app_name,
        "--default-index", dindex,
        "--field-map", fmap,
        "--log-level", log_level,
    ]
    if csv_path: argv.extend(["--input-csv", csv_path])
    if xml_path: argv.extend(["--xml", xml_path])
    if bb_csv: argv.extend(["--building-blocks", bb_csv])
    if rs_csv: argv.extend(["--reference-sets", rs_csv])
    if use_backup: argv.append("--backup")
    if use_strict: argv.append("--strict")
    if use_dryrun: argv.append("--dry-run")
    if fail_warn: argv.append("--fail-on-warn")

    return main(argv)

def main(argv: Optional[List[str]]=None)->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--profile", help="YAML/JSON con parametros del entorno de migracion")
    ap.add_argument("--input-csv")
    ap.add_argument("--xml")
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--app")
    ap.add_argument("--default-index")
    ap.add_argument("--field-map")
    ap.add_argument("--building-blocks")
    ap.add_argument("--reference-sets")
    ap.add_argument("--qradar-export", action="store_true", help="Exporta inventario basico desde QRadar API")
    ap.add_argument("--qradar-url")
    ap.add_argument("--qradar-token")
    ap.add_argument("--qradar-no-verify-ssl", action="store_true")
    ap.add_argument("--validate-splunk", action="store_true")
    ap.add_argument("--splunk-url")
    ap.add_argument("--splunk-username")
    ap.add_argument("--splunk-password")
    ap.add_argument("--splunk-token")
    ap.add_argument("--splunk-verify-ssl", action="store_true")
    ap.add_argument("--splunk-no-verify-ssl", action="store_true")
    ap.add_argument("--splunk-execute-sample", action="store_true", help="Ejecuta una muestra de cada SPL en Splunk")
    ap.add_argument("--sample-earliest", default="-24h")
    ap.add_argument("--sample-latest", default="now")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--preflight", action="store_true", help="Valida profile/rutas/permisos/credenciales y termina")
    ap.add_argument("--disable-searches", action="store_true", help="Genera saved searches deshabilitadas por defecto")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--fail-on-warn", action="store_true")
    ap.add_argument("--no-autofix", action="store_true")
    ap.add_argument("--backup", action="store_true")
    ap.add_argument("--package", action="store_true", help="Genera un .tgz instalable en Splunk")
    ap.add_argument("--audit-only", action="store_true", help="Genera reportes de auditoria/mapping sin escribir la app Splunk")
    ap.add_argument("--review-state", help="YAML con estado de revision/aprobacion por regla")
    ap.add_argument("--log-level", default="INFO")
    args=ap.parse_args(argv)

    profile=load_yaml(args.profile) if args.profile else {}
    args.app=args.app or get_nested(profile, "splunk.app", None) or "QRadar2Splunk"
    args.default_index=args.default_index or get_nested(profile, "splunk.default_index", None) or "*"
    args.field_map=args.field_map or get_nested(profile, "mappings.field_map", None) or "mappings/field_map.yaml"
    args.building_blocks=args.building_blocks or get_nested(profile, "mappings.building_blocks", None)
    args.reference_sets=args.reference_sets or get_nested(profile, "mappings.reference_sets", None)
    args.input_csv=args.input_csv or get_nested(profile, "inputs.csv", None)
    args.xml=args.xml or get_nested(profile, "inputs.xml", None)

    splunk_profile=dict(get_nested(profile, "splunk", {}) or {})
    if args.splunk_url: splunk_profile["url"]=args.splunk_url
    if args.splunk_username: splunk_profile["username"]=args.splunk_username
    if args.splunk_password: splunk_profile["password"]=args.splunk_password
    if args.splunk_token: splunk_profile["token"]=args.splunk_token
    if args.splunk_verify_ssl: splunk_profile["verify_ssl"]=True
    if args.splunk_no_verify_ssl: splunk_profile["verify_ssl"]=False
    if args.validate_splunk:
        splunk_profile["validate"]=True
    if args.splunk_execute_sample:
        splunk_profile["execute_sample"]=True
    splunk_profile["sample_earliest"]=args.sample_earliest
    splunk_profile["sample_latest"]=args.sample_latest

    qradar_profile=dict(get_nested(profile, "qradar", {}) or {})
    if args.qradar_url: qradar_profile["url"]=args.qradar_url
    if args.qradar_token: qradar_profile["token"]=args.qradar_token
    if args.qradar_no_verify_ssl: qradar_profile["verify_ssl"]=False
    if args.qradar_export:
        qradar_profile["export"]=True
    review_path=args.review_state or get_nested(profile, "reviews.path", None)
    disable_searches=args.disable_searches or truthy_profile(get_nested(profile, "splunk.disable_searches", False), False)

    if args.preflight:
        preflight=preflight_check(args, profile, splunk_profile, qradar_profile, review_path)
        ensure_dir(args.outdir)
        preflight_path=os.path.join(args.outdir,"preflight_report.json")
        atomic_write(preflight_path, json.dumps(sanitize_secrets(preflight), indent=2, ensure_ascii=False))
        print(f"[OK] Preflight report: {preflight_path}")
        print(f"[OK] Checks: {len(preflight['checks'])}; errors: {preflight['errors']}; warnings: {preflight['warnings']}")
        return 0 if preflight["ok"] else 4

    os.makedirs(args.outdir, exist_ok=True)
    logging.basicConfig(filename=os.path.join(args.outdir,"migration.log"),
                        level=getattr(logging, args.log_level.upper(), logging.INFO),
                        format="%(asctime)s %(levelname)s %(message)s")
    warning_collector=WarningCollector()
    logging.getLogger().addHandler(warning_collector)

    fmap=load_yaml(args.field_map)
    bb={}
    if args.building_blocks and os.path.exists(args.building_blocks):
        with open(args.building_blocks, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f): bb[row["name"].strip()]=row["expression_aql"].strip()
    refsets={}
    if args.reference_sets and os.path.exists(args.reference_sets):
        with open(args.reference_sets, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                nm=row["set_name"].strip()
                refsets[nm]={"lookup_csv_path":os.path.basename(row["lookup_csv_path"].strip()), "key_field":row["key_field"].strip()}

    rows=[]
    qradar_export_result=None
    if qradar_profile.get("export"):
        qradar_export_result=export_qradar_inventory(qradar_profile, args.outdir)
        rows+=qradar_export_result.get("rules", [])
    if args.input_csv:
        if os.path.exists(args.input_csv):
            try:
                rows+=load_csv_rules(args.input_csv)
            except Exception as e:
                logging.error(f"No se pudo cargar CSV {args.input_csv}: {e}")
                if args.strict: raise
        else:
            logging.error(f"No existe CSV de entrada: {args.input_csv}")
    if args.xml:
        if os.path.exists(args.xml):
            rows+=parse_xml_rules(args.xml)
        else:
            logging.warning(f"No existe XML de entrada: {args.xml}")

    if not rows:
        if qradar_export_result:
            if qradar_export_result.get("path"):
                print(f"[OK] Inventario QRadar exportado: {qradar_export_result.get('path')}")
            else:
                print(f"[WARN] Inventario QRadar no exportado: {qradar_export_result.get('error','unknown_error')}")
            if qradar_export_result.get("errors"):
                print(f"[WARN] Export QRadar con errores: {len(qradar_export_result.get('errors'))}")
            return 0
        print("ERROR: No hay reglas de entrada")
        return 2

    if args.dry_run:
        logging.info("Dry-run activo: no se escribiran ficheros de app ni report.json")

    try:
        report=build_app(rows, args.outdir, args.app, args.default_index, fmap, bb, refsets, profile,
                  dry_run=args.dry_run, strict=args.strict, no_autofix=args.no_autofix, backup=args.backup, package=args.package, audit_only=args.audit_only, reviews=load_review_state(review_path), disable_searches=disable_searches)
    except SystemExit as e:
        return int(str(e)) if str(e).isdigit() else 1
    report["warnings"]=warning_collector.records
    if qradar_export_result:
        report["qradar_export"]=qradar_export_result
    if splunk_profile.get("validate"):
        report=validate_splunk_searches(report, splunk_profile)
    if not args.dry_run:
        report["readiness"]=build_readiness(report)
        readiness_path=os.path.join(args.outdir,"readiness_report.md")
        summary_path=os.path.join(args.outdir,"executive_summary.md")
        manifest_path=os.path.join(args.outdir,"manifest.json")
        write_readiness_report(readiness_path, report)
        write_executive_summary(summary_path, report)
        report["outputs"]["readiness_report.md"]={"path":readiness_path,"sha256":sha256(readiness_path)}
        report["outputs"]["executive_summary.md"]={"path":summary_path,"sha256":sha256(summary_path)}
        input_paths={"profile":args.profile,"input_csv":args.input_csv,"input_xml":args.xml,"field_map":args.field_map,"building_blocks":args.building_blocks,"reference_sets":args.reference_sets,"review_state":review_path}
        write_manifest(manifest_path, report, args, profile, input_paths)
        report["outputs"]["manifest.json"]={"path":manifest_path,"sha256":sha256(manifest_path)}
        rep_path=os.path.join(args.outdir,"report.json")
        if os.path.exists(rep_path):
            with open(rep_path,"w",encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
    if args.fail_on_warn and warning_collector.records:
        print(f"ERROR: fail-on-warn activo y se detectaron {len(warning_collector.records)} warnings")
        return 3
    return 0

if __name__=="__main__":
    import sys
    if len(sys.argv)==1:
        raise SystemExit(interactive_wizard())
    else:
        raise SystemExit(main())
