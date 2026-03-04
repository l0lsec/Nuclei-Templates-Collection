#!/usr/bin/env python3

import os
import sys
import shutil
import hashlib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

WORKERS = 8

category_map = {
    "wordpress": ["wp", "wordpress"],
    "xss": ["xss"],
    "sql_injection": ["sqli", "sql_injection"],
    "local_file_inclusion": ["lfi"],
    "remote_code_execution": ["rce"],
    "cross_site_request_forgery": ["csrf"],
    "xml_external_entity": ["xxe"],
    "cve": ["cve", "cnvd", "cnnvd"],
    "open_redirect": ["redirect", "open_redirect"],
    "ssrf": ["ssrf", "server_side_request_forgery"],
    "subdomain_takeover": ["subdomain_takeover", "takeover"],
    "template_injection": ["template_injection", "ssti"],
    "crlf_injection": ["crlf_injection", "crlf"],
    "directory_listing": ["directory_listing", "traversal"],
    "exposed": ["exposed", "disclosure", "sensitive", "exposure"],
    "adobe": ["adobe", "aem"],
    "coldfusion": ["coldfusion", "cfm"],
    "drupal": ["drupal"],
    "joomla": ["joomla"],
    "magento": ["magento"],
    "php": ["php"],
    "airflow": ["airflow"],
    "aws": ["aws", "amazon", "ec2", "s3", "lambda", "cloudfront"],
    "apache": ["apache"],
    "cpanel": ["cpanel"],
    "docker": ["docker", "container", "kubernetes"],
    "git": ["git"],
    "jenkins": ["jenkins"],
    "cisco": ["cisco"],
    "api": ["api"],
    "upload": ["upload"],
    "sensitive": ["sensitive"],
    "debug": ["debug"],
    "backup": ["backup"],
    "auth": [
        "auth", "login", "signin", "sign_in", "sign-in", "oauth", "sso",
        "register", "signup", "sign_up", "sign-up", "password", "pwd",
        "passwd", "secret", "token", "credential", "cred", "jwt", "cookie",
        "session", "remember", "keycloak", "key",
    ],
    "atlassian": ["atlassian", "jira", "confluence", "bitbucket", "bamboo"],
    "config": ["config", "conf", "configuration"],
    "mysql": ["mysql", "mariadb"],
    "sql": ["sql", "database", "db"],
    "default": ["default"],
    "detect": ["detect"],
    "extract": ["extract"],
    "fuzz": ["fuzz"],
    "graphql": ["graphql"],
    "http": ["http"],
    "social": ["social", "social_media", "facebook", "twitter", "instagram", "linkedin"],
    "favicon": ["favicon"],
    "python": ["python", "flask", "django"],
    "ftp": ["ftp"],
    "gcloud": ["gcloud", "google_cloud", "gcp"],
    "google": ["google"],
    "graphite": ["graphite"],
    "header": ["header"],
    "injection": ["injection"],
    "ibm": ["ibm"],
    "search": ["search"],
    "ldap": ["ldap"],
    "microsoft": ["microsoft", "ms"],
    "mongodb": ["mongodb", "mongo"],
    "netlify": ["netlify"],
    "oracle": ["oracle"],
    "java": [
        "java", "jsp", "jsf", "j2ee", "j2se", "j2me", "jvm", "jre", "jdk",
        "jboss", "tomcat", "glassfish", "wildfly", "jetty", "websphere",
        "weblogic", "spring", "struts", "hibernate", "mybatis", "shiro",
    ],
    "javascript": ["javascript", "js"],
    "elk": ["elk", "elasticsearch", "kibana", "logstash"],
    "kafka": ["kafka"],
    "kong": ["kong"],
    "laravel": ["laravel"],
    "nginx": ["nginx"],
    "nodejs": ["nodejs", "node", "express", "npm"],
    "perl": ["perl"],
    "postgres": ["postgres", "postgresql"],
    "rabbitmq": ["rabbitmq"],
    "redis": ["redis"],
    "ruby": ["ruby", "rails"],
    "samba": ["samba"],
    "sharepoint": ["sharepoint"],
    "smtp": ["smtp"],
    "sap": ["sap"],
    "shopify": ["shopify"],
    "ssh": ["ssh"],
    "vmware": ["vmware"],
    "web": ["web"],
}


def get_all_yaml_files(dir_path, ignore_dirs=None):
    """Returns list of (filename, full_path, file_size) tuples for all YAML files."""
    if ignore_dirs is None:
        ignore_dirs = {".git"}
    results = []
    for dirpath, dirs, files in os.walk(dir_path):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for filename in files:
            if filename.endswith((".yml", ".yaml")):
                full = os.path.join(dirpath, filename)
                try:
                    sz = os.path.getsize(full)
                except OSError:
                    continue
                results.append((filename, full, sz))
    return results


def file_hash(file_path):
    """MD5 hash with chunked reads — fast enough for dedup, no crypto needed."""
    hasher = hashlib.md5()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(131072)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def hash_path(path):
    """Wrapper for thread pool — returns (path, hash) or (path, None) on error."""
    try:
        return (path, file_hash(path))
    except OSError:
        return (path, None)


def parallel_hash(paths, label=""):
    """Hash a list of file paths using a thread pool. Returns {path: hash}."""
    result = {}
    total = len(paths)
    done = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(hash_path, p): p for p in paths}
        for fut in as_completed(futures):
            path, h = fut.result()
            if h is not None:
                result[path] = h
            done += 1
            if done % 1000 == 0 or done == total:
                sys.stdout.write(f"\r    {label} {done}/{total}")
                sys.stdout.flush()
    sys.stdout.write("\n")
    return result


def categorize_file(file_name, cat_map):
    lower_name = file_name.lower()
    categories = [cat for cat, keywords in cat_map.items()
                  if any(kw in lower_name for kw in keywords)]
    return categories or ["other"]


def fast_link(src, dest):
    """Hard-link (instant, zero copy) with fallback to regular copy."""
    try:
        os.link(src, dest)
    except OSError:
        shutil.copy2(src, dest)


def main():
    community_path = "community-templates"
    source_of_truth = "community-templates/projectdiscovery__nuclei-templates"
    output_path = "categorized_templates"
    t0 = time.time()

    # --- Phase 1: scan filesystem ---
    print("[*] Scanning filesystem...")
    sys.stdout.flush()
    sot_files = get_all_yaml_files(source_of_truth)
    community_files = get_all_yaml_files(
        community_path, ignore_dirs={".git", "projectdiscovery__nuclei-templates"}
    )
    print(f"    Official templates: {len(sot_files)}")
    print(f"    Community templates: {len(community_files)}")
    sys.stdout.flush()

    # --- Phase 2: hash official templates in parallel ---
    print(f"[*] Hashing official templates ({WORKERS} threads)...")
    sys.stdout.flush()
    sot_hash_map = parallel_hash([p for _, p, _ in sot_files], label="Hashing SOT")
    sot_hashes = set(sot_hash_map.values())
    sot_sizes = {sz for _, _, sz in sot_files}
    print(f"    {len(sot_hashes)} unique hashes, {len(sot_sizes)} unique sizes")

    # --- Phase 3: size pre-filter community files ---
    # Files whose size doesn't match ANY official template can't be duplicates,
    # so we skip the expensive hash-compare for those.
    maybe_dupes = []
    definitely_unique = []
    for filename, path, sz in community_files:
        if sz in sot_sizes:
            maybe_dupes.append((filename, path, sz))
        else:
            definitely_unique.append((filename, path, sz))
    print(f"[*] Size pre-filter: {len(maybe_dupes)} possible dupes, "
          f"{len(definitely_unique)} unique by size (skipping hash)")
    sys.stdout.flush()

    # --- Phase 4: hash only the possible duplicates in parallel ---
    need_hash_paths = [p for _, p, _ in maybe_dupes]
    if need_hash_paths:
        print(f"[*] Hashing {len(need_hash_paths)} candidate dupes ({WORKERS} threads)...")
        sys.stdout.flush()
        community_hash_map = parallel_hash(need_hash_paths, label="Hashing community")
    else:
        community_hash_map = {}

    # --- Phase 5: process files ---
    print("[*] Processing and categorizing...")
    sys.stdout.flush()

    category_counts = {}
    global_hashes = set()
    duplicates_removed = 0
    files_linked = 0
    errors = 0
    total = len(community_files)
    start_time = time.time()
    created_dirs = set()

    def place_file(filename, src_path, content_hash):
        nonlocal files_linked, errors
        categories = categorize_file(filename, category_map)
        for category in categories:
            cat_key = (category, content_hash)
            if cat_key in global_hashes:
                continue
            global_hashes.add(cat_key)

            target_dir = os.path.join(output_path, category)
            if target_dir not in created_dirs:
                os.makedirs(target_dir, exist_ok=True)
                created_dirs.add(target_dir)

            dest = os.path.join(target_dir, filename)
            if os.path.exists(dest):
                base, ext = os.path.splitext(filename)
                dest = os.path.join(target_dir, f"{base}_{content_hash[:8]}{ext}")

            try:
                fast_link(src_path, dest)
                files_linked += 1
            except OSError as e:
                errors += 1
                if errors <= 10:
                    sys.stderr.write(f"\n[!] Link/copy error {dest}: {e}\n")

            category_counts[category] = category_counts.get(category, 0) + 1

    processed = 0

    # 5a: handle possible duplicates (we already have their hashes)
    for filename, path, sz in maybe_dupes:
        h = community_hash_map.get(path)
        if h and h in sot_hashes:
            try:
                os.remove(path)
                duplicates_removed += 1
            except OSError:
                pass
        elif h:
            place_file(filename, path, h)
        processed += 1
        if processed % 500 == 0:
            elapsed = time.time() - start_time
            rate = processed / elapsed if elapsed > 0 else 0
            eta = (total - processed) / rate if rate > 0 else 0
            sys.stdout.write(
                f"\r    [{processed}/{total}] dupes: {duplicates_removed} | "
                f"linked: {files_linked} | ETA: {eta:.0f}s  "
            )
            sys.stdout.flush()

    # 5b: handle definitely-unique files (no hashing needed for dedup check,
    #     but we still need a hash for intra-category dedup)
    unique_paths = [p for _, p, _ in definitely_unique]
    if unique_paths:
        print(f"\n[*] Hashing {len(unique_paths)} unique files for category dedup...")
        sys.stdout.flush()
        unique_hash_map = parallel_hash(unique_paths, label="Hashing unique")
    else:
        unique_hash_map = {}

    for filename, path, sz in definitely_unique:
        h = unique_hash_map.get(path)
        if h:
            place_file(filename, path, h)
        processed += 1
        if processed % 500 == 0 or processed == total:
            elapsed = time.time() - start_time
            rate = processed / elapsed if elapsed > 0 else 0
            eta = (total - processed) / rate if rate > 0 else 0
            sys.stdout.write(
                f"\r    [{processed}/{total}] dupes: {duplicates_removed} | "
                f"linked: {files_linked} | ETA: {eta:.0f}s  "
            )
            sys.stdout.flush()

    elapsed = time.time() - t0
    print(f"\n\n{'=' * 60}")
    print(f"COMPLETED in {elapsed:.1f}s")
    print(f"{'=' * 60}")
    print(f"  Total community files scanned: {total}")
    print(f"  Duplicates removed (matched official): {duplicates_removed}")
    print(f"  Files hard-linked to categories: {files_linked}")
    print(f"  Skipped hashing (size mismatch): {len(definitely_unique)}")
    print(f"  Errors: {errors}")
    print(f"\nFiles per category:")
    for category in sorted(category_counts, key=category_counts.get, reverse=True):
        print(f"  {category:30s} {category_counts[category]:>6d}")


if __name__ == "__main__":
    main()
