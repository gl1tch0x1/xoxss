"""
Application fuzzing: content discovery and parameter mining.

This is an internal, dependency-free complement to the optional external tools
(ffuf/feroxbuster are used when installed).  It is conservative by default:
a baseline request fingerprints the soft-404 response so endless catch-all
pages do not explode the crawl queue.
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import re
import string
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from xoxss.core.protocols import ConsoleLike, HttpLike


DIR_WORDS: Tuple[str, ...] = (
    "admin", "administrator", "adminpanel", "admin-console", "api", "api/v1",
    "api/v2", "api/v3", "apis", "app", "apps", "assets", "auth", "authorize",
    "backend", "backup", "backups", "beta", "bin", "build", "cache", "cgi-bin",
    "cgi", "config", "configs", "console", "content", "cpanel", "crm", "css",
    "dashboard", "data", "database", "db", "debug", "dev", "developer", "docs",
    "download", "downloads", "dump", "email", "env", "files", "file", "fonts",
    "forms", "graphql", "health", "healthcheck", "help", "home", "html", "img",
    "images", "includes", "index", "internal", "js", "json", "lang", "log",
    "login", "logout", "logs", "mail", "manage", "management", "media", "metrics",
    "mobile", "monitor", "monitoring", "news", "oauth", "old", "panel", "pay",
    "payment", "payments", "portal", "private", "prod", "public", "register",
    "reset", "rest", "rpc", "scripts", "search", "secure", "server", "service",
    "services", "settings", "setup", "signin", "signup", "sitemap", "sql", "src",
    "staging", "static", "status", "storage", "support", "system", "temp",
    "test", "tests", "tmp", "token", "upload", "uploads", "user", "users",
    "v1", "v2", "v3", "vendor", "web", "webhook", "webhooks", "welcome", "ws",
    "xmlrpc", "actuator", "actuator/env", "actuator/health", "swagger",
    "swagger-ui", "swagger-ui.html", "openapi.json", "api-docs", "graphiql",
    "phpinfo.php", "info.php", "test.php", "shell.php", "admin.php", "login.php",
    "wp-admin", "wp-login.php", "wp-json", "wp-content", "server-status",
    "robots.txt", "sitemap.xml", "security.txt", ".well-known", ".git/config",
    ".env", ".ds_store", "README.md", "package.json", "composer.json",
    # --- added: API surface -------------------------------------------------
    "api", "api/v1", "api/v2", "api/users", "api/user", "api/search",
    "api/items", "api/products", "api/orders", "api/admin", "api/config",
    "api/settings", "api/status", "api/health", "api/version", "api/info",
    "api/debug", "api/test", "api/internal", "api/private", "api/export",
    "api/import", "api/upload", "api/download", "api/files", "api/media",
    "api/images", "api/avatar", "api/profile", "api/account", "api/auth",
    "api/login", "api/logout", "api/register", "api/token", "api/session",
    "api/oauth", "api/callback", "api/webhook", "api/notify", "api/logs",
    "api/log", "api/metrics", "api/stats", "api/analytics", "api/report",
    "api/reports", "api/search", "api/query", "api/graphql", "api/rest",
    "api/rpc", "api/json", "api/xml", "api/feed", "api/rss", "api/sitemap",
    "v1", "v2", "v3", "v4", "beta", "alpha", "dev", "development",
    "sandbox", "staging", "stage", "uat", "qa", "test", "testing",
    "demo", "trial", "preview", "canary", "experimental", "lab",
    # --- added: admin / debug / ops ----------------------------------------
    "admin", "administrator", "adminpanel", "admin-panel", "admin_area",
    "admin_area/index.php", "administrator/index.php", "backend", "backoffice",
    "console", "dashboard", "controlpanel", "cpanel", "webadmin", "siteadmin",
    "sysadmin", "root", "superuser", "moderator", "staff", "support-admin",
    "debug", "debugger", "devtools", "dev-console", "console", "shell",
    "terminal", "cmd", "command", "exec", "execute", "run", "eval",
    "phpmyadmin", "pma", "adminer", "adminer.php", "dbadmin", "sqladmin",
    "mysql", "phpinfo", "server-info", "server-status", "status.php",
    "health", "healthz", "ready", "readyz", "live", "livez", "ping",
    "info", "version", "versions", "build", "buildinfo", "release",
    "changelog", "changes", "history", "audit", "auditlog", "accesslog",
    "errorlog", "error_log", "logs", "log", "syslog", "trace", "traces",
    "monitor", "monitoring", "grafana", "kibana", "prometheus", "metrics",
    "alerts", "alertmanager", "nagios", "zabbix", "jenkins", "ci",
    "gitlab", "github", "bitbucket", "jira", "confluence", "wiki",
    "internal", "intranet", "private", "secret", "hidden", "backup",
    "backups", "old", "oldsite", "archive", "archives", "legacy",
    "deprecated", "unused", "testbed", "sandbox", "staging",
    # --- added: config / secrets / keys ------------------------------------
    "config", "config.php", "config.json", "config.yml", "config.yaml",
    "configuration", "settings", "settings.php", "settings.json",
    "wp-config.php", "configuration.php", "local.settings.json",
    "appsettings.json", "web.config", "global.asax", "crossdomain.xml",
    "clientaccesspolicy.xml", "elmah.axd", "trace.axd", "phpinfo.php",
    ".env", ".env.local", ".env.production", ".env.development",
    ".git/config", ".git/HEAD", ".svn/entries", ".hg/store",
    ".idea", ".vscode", ".DS_Store", "Thumbs.db", "desktop.ini",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".ssh",
    "credentials", "credentials.json", "secrets", "secrets.json",
    "secrets.yml", "vault", "vault.json", "keys", "keys.json",
    "certificates", "certs", "cert.pem", "key.pem", "server.key",
    "database.yml", "db.yml", "database.php", "db.php", "dbconfig.php",
    "dump.sql", "backup.sql", "db.sql", "database.sql", "mysql.sql",
    "data.sql", "export.sql", "import.sql", "site.sql", "backup.zip",
    "backup.tar.gz", "site.zip", "www.zip", "public_html.zip",
    "db.zip", "database.zip", "dump.zip", "backup.bak", "db.bak",
    # --- added: user content / upload surfaces ------------------------------
    "uploads", "upload", "files", "file", "download", "downloads",
    "media", "images", "img", "assets", "static", "public", "cdn",
    "content", "data", "docs", "documents", "doc", "pdf", "attachments",
    "attachment", "tmp", "temp", "cache", "cached", "sessions", "session",
    "cookies", "storage", "localstorage", "userdata", "userfiles",
    "avatars", "profile", "profiles", "members", "member", "customers",
    "clients", "contacts", "messages", "inbox", "notifications",
    "comments", "reviews", "feedback", "support", "tickets", "help",
    "faq", "forum", "forums", "community", "blog", "news", "articles",
    "posts", "pages", "page", "landing", "home", "index", "default",
    "search", "find", "query", "results", "listing", "listings",
    "catalog", "shop", "store", "cart", "checkout", "order", "orders",
    "payment", "payments", "billing", "invoice", "invoices", "account",
    "accounts", "profile", "settings", "preferences", "security",
    "privacy", "terms", "about", "contact", "company", "team", "careers",
    "jobs", "press", "media", "events", "calendar", "schedule",
    # --- added: framework / CMS fingerprints --------------------------------
    "wp-admin", "wp-login.php", "wp-content", "wp-includes", "wp-json",
    "wp-config.php", "xmlrpc.php", "wp-cron.php", "wp-trackback.php",
    "administrator", "index.php?option=com_users", "configuration.php",
    "configuration.php-dist", "web.config.txt", "elmah.axd", "trace.axd",
    "telerik.web.ui", "sitefinity", "umbraco", "drupal", "joomla",
    "magento", "prestashop", "opencart", "shopware", "typo3",
    "concrete5", "modx", "processwire", "craftcms", "statamic",
    "ghost", "discourse", "forum", "boards", "nodebb",
    "laravel", "artisan", "symfony", "zend", "codeigniter", "cakephp",
    "yii", "phalcon", "slim", "lumen", "fuelphp", "kohana",
    "spring", "actuator", "actuator/health", "actuator/info",
    "actuator/env", "actuator/beans", "actuator/mappings",
    "actuator/configprops", "actuator/heapdump", "actuator/threaddump",
    "server-status", "server-info", "nginx_status", "stub_status",
    "fpm-status", "fpm-ping", "status", "ping", "health", "healthz",
    "ready", "readyz", "live", "livez", "metrics", "prometheus",
    "_cat/indices", "_cluster/health", "_nodes", "_all",
    "kibana", "grafana", "prometheus", "alertmanager", "node-exporter",
    "jenkins", "gitlab-ci", "github-actions", "circleci", "travis",
    "bitbucket-pipelines", "drone", "concourse", "tekton",
    "sonar", "sonarqube", "nexus", "artifactory", "harbor",
    "vault", "consul", "nomad", "etcd", "zookeeper",
    "rabbitmq", "kafka", "redis", "memcached", "mongo", "elasticsearch",
    "solr", "cassandra", "couchdb", "influxdb", "timescaledb",
    "phpmyadmin", "pma", "adminer", "adminer.php", "sqlbuddy",
    "mysql", "postgresql", "mongodb", "redis-commander", "mongo-express",
    "redisinsight", "phpredisadmin", "adminmongo", "mongoadmin",
    "elasticvue", "dejavu", "cerebro", "hq", "elastic-hq",
    # --- added: JavaScript / source maps / build artifacts -------------------
    "js", "scripts", "script", "assets/js", "static/js", "dist",
    "build", "out", "output", "public", "www", "web", "app",
    "main.js", "bundle.js", "app.js", "vendor.js", "runtime.js",
    "chunk.js", "chunks", "vendor", "node_modules", "bower_components",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.json", "composer.lock", "Gemfile", "Gemfile.lock",
    "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock",
    "Cargo.toml", "Cargo.lock", "go.mod", "go.sum", "pom.xml",
    "build.gradle", "settings.gradle", "gradle.properties",
    "Makefile", "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "dockerfile", "containerfile", "kubernetes.yml", "k8s.yml",
    "deployment.yaml", "service.yaml", "ingress.yaml", "configmap.yaml",
    "secret.yaml", "persistentvolumeclaim.yaml", "statefulset.yaml",
    "daemonset.yaml", "job.yaml", "cronjob.yaml",
    # --- added: documentation / help / support -------------------------------
    "docs", "doc", "documentation", "help", "support", "faq",
    "knowledge", "knowledgebase", "kb", "wiki", "manual", "guide",
    "tutorial", "tutorials", "learn", "academy", "training",
    "about", "aboutus", "company", "team", "careers", "jobs",
    "press", "media", "news", "blog", "articles", "posts",
    "events", "calendar", "schedule", "webinars", "podcasts",
    "contact", "contactus", "feedback", "survey", "poll",
    "newsletter", "subscribe", "unsubscribe", "preferences",
    "account", "profile", "settings", "preferences", "security",
    "privacy", "terms", "terms-of-service", "tos", "eula",
    "disclaimer", "copyright", "licenses", "licensing", "attribution",
    "credits", "acknowledgements", "authors", "contributors",
    "changelog", "changes", "release-notes", "whats-new",
    "roadmap", "plans", "pricing", "enterprise", "partners",
    "affiliates", "resellers", "integrations", "marketplace",
    "developers", "api-docs", "api-documentation", "api-reference",
    "sdk", "sdks", "libraries", "tools", "utilities", "resources",
    "downloads", "downloads", "releases", "binaries", "installers",
    "drivers", "firmware", "updates", "patches", "hotfixes",
)

FUZZ_EXTENSIONS: Tuple[str, ...] = (
    "", ".php", ".asp", ".aspx", ".jsp", ".jspx", ".do", ".action", ".json",
    ".xml", ".html", ".htm", ".txt", ".bak", ".old", ".zip", ".tar.gz", ".sql",
    ".log", ".js", ".map", ".yaml", ".yml",
    # --- added: backup / dev / vcs / config extensions ----------------------
    ".php~", ".php.bak", ".php.old", ".php.save", ".php.swp", ".php.orig",
    ".php.txt", ".php.inc", ".php.dist", ".php.sample", ".php.example",
    ".inc", ".module", ".install", ".engine", ".theme", ".profile",
    ".info", ".test", ".spec", ".bak", ".backup", ".old", ".orig",
    ".save", ".swp", ".swo", ".tmp", ".temp", ".cache", ".copy",
    ".dist", ".sample", ".example", ".template", ".tmpl", ".tpl",
    ".conf", ".config", ".cfg", ".ini", ".properties", ".props",
    ".env", ".env.local", ".env.production", ".env.development",
    ".gitignore", ".gitattributes", ".gitmodules", ".gitkeep",
    ".svn", ".hg", ".bzr", ".DS_Store", "Thumbs.db", "desktop.ini",
    ".sqlite", ".sqlite3", ".db", ".mdb", ".accdb",
    ".pem", ".key", ".crt", ".cer", ".p12", ".pfx", ".jks",
    ".csv", ".tsv", ".xls", ".xlsx", ".ods", ".numbers",
    ".doc", ".docx", ".ppt", ".pptx", ".rtf", ".odt",
    ".md", ".markdown", ".rst", ".adoc", ".tex", ".wiki",
    ".rss", ".atom", ".rdf", ".opml", ".ics",
    ".wasm", ".wat", ".wast", ".wast2json",
    ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".vue", ".svelte",
    ".scss", ".sass", ".less", ".styl", ".pcss",
    ".gradle", ".groovy", ".kt", ".kts", ".scala", ".clj",
    ".go", ".rs", ".rb", ".pl", ".pm", ".lua", ".r", ".jl",
    ".cs", ".vb", ".fs", ".fsx", ".swift", ".m", ".mm",
    ".dart", ".ex", ".exs", ".erl", ".hrl", ".cljc",
    ".ipynb", ".rmd", ".qmd",
    ".tf", ".tfvars", ".hcl", ".nomad", ".packer",
    ".proto", ".thrift", ".avsc", ".avdl", ".avpr",
    ".graphql", ".gql", ".graphqls",
    ".har", ".chls", ".wadl", ".raml", ".api", ".postman",
    ".http", ".rest", ".curl",
)

PARAM_WORDS: Tuple[str, ...] = (
    "q", "query", "search", "keyword", "keywords", "s", "term", "text",
    "id", "ids", "uid", "user", "userid", "user_id", "account", "accountid",
    "email", "username", "name", "firstname", "lastname", "fullname", "title", "url",
    "uri", "link", "redirect", "redirect_uri", "return", "returnurl", "next", "continue",
    "target", "dest", "destination", "callback", "ref", "referer", "referrer", "from",
    "to", "page", "p", "pageid", "page_id", "path", "file", "filename",
    "filepath", "dir", "folder", "template", "view", "display", "mode", "action",
    "cmd", "command", "op", "operation", "type", "kind", "category", "cat",
    "tag", "tags", "lang", "language", "locale", "country", "region", "city",
    "address", "zip", "postal", "phone", "mobile", "message", "msg", "comment",
    "content", "body", "desc", "description", "note", "notes", "subject", "status",
    "state", "code", "token", "auth", "key", "apikey", "api_key", "secret",
    "password", "pass", "session", "sessionid", "sid", "csrf", "nonce", "signature",
    "sig", "hash", "format", "output", "jsonp", "cb", "method", "api",
    "version", "v", "debug", "test", "preview", "draft", "print", "embed",
    "iframe", "widget", "share", "source", "src", "href", "img", "image",
    "icon", "logo", "color", "theme", "style", "css", "js", "script",
    "html", "raw", "download", "export", "import", "upload", "attachment", "invoice",
    "order", "orderid", "product", "productid", "item", "itemid", "cart", "coupon",
    "price", "amount", "currency", "date", "start", "end", "startdate", "enddate",
    "from_date", "to_date", "limit", "offset", "per_page", "pagesize", "sort", "order_by",
    "filter", "where", "select", "table", "db", "host", "domain", "subdomain",
    "port", "ip", "remote", "proxy", "feed", "rss", "sitemap", "report",
    "chart", "graph", "metric", "event", "log", "level", "ipn", "webhook",
    "notification", "notify", "alert", "email_to", "recipient", "returnTo", "return_to", "returnto",
    "ret", "rurl", "ru", "goto", "redir", "redirect_to", "redirectTo", "redirect_url",
    "redirectUrl", "callback_url", "callbackUrl", "continue_url", "continueUrl", "forward", "forwarded", "bounce",
    "landing", "landing_page", "landingPage", "come_from", "comeFrom", "origin_url", "originUrl", "source_url",
    "sourceUrl", "ref_url", "doc", "document", "document_url", "documentUrl", "page_url", "content_url",
    "contentUrl", "media_url", "mediaUrl", "asset_url", "avatar_url", "avatarUrl", "image_url", "imageUrl",
    "img_url", "icon_url", "iconUrl", "logo_url", "logoUrl", "thumbnail", "thumb", "picture",
    "pic", "photo", "photos", "gallery", "attachment_url", "attachmentUrl", "file_url", "fileUrl",
    "download_url", "downloadUrl", "export_url", "exportUrl", "import_url", "importUrl", "feed_url", "feedUrl",
    "rss_url", "sitemap_url", "sitemapUrl", "xml_url", "xmlUrl", "json_url", "jsonUrl", "api_url",
    "apiUrl", "endpoint", "service_url", "serviceUrl", "webhook_url", "webhookUrl", "notify_url", "notifyUrl",
    "callback_endpoint", "callbackEndpoint", "hook", "hook_url", "hookUrl", "listener", "receiver", "target_url",
    "targetUrl", "destination_url", "destinationUrl", "goto_url", "gotoUrl", "forward_url", "forwardUrl", "bounce_url",
    "bounceUrl", "jump", "jump_url", "jumpUrl", "leap", "leap_url", "leapUrl", "skip",
    "skip_url", "skipUrl", "exit", "exit_url", "exitUrl", "out", "out_url", "outUrl",
    "away", "away_url", "awayUrl", "external", "external_url", "externalUrl", "ext", "ext_url",
    "extUrl", "outbound", "outbound_url", "outboundUrl", "offsite", "offsite_url", "offsiteUrl", "off_domain",
    "offDomain", "third_party", "thirdParty", "third_party_url", "thirdPartyUrl", "partner", "partner_url", "partnerUrl",
    "affiliate", "affiliate_url", "affiliateUrl", "sponsor", "sponsor_url", "sponsorUrl", "vendor", "vendor_url",
    "vendorUrl", "supplier", "supplier_url", "supplierUrl", "merchant", "merchant_url", "merchantUrl", "provider",
    "provider_url", "providerUrl", "client", "client_url", "clientUrl", "customer", "customer_url", "customerUrl",
    "user_url", "userUrl", "account_url", "accountUrl", "profile_url", "profileUrl", "member_url", "memberUrl",
    "contact_url", "contactUrl", "support_url", "supportUrl", "help_url", "helpUrl", "faq_url", "faqUrl",
    "docs_url", "docsUrl", "documentation_url", "documentationUrl", "guide_url", "guideUrl", "tutorial_url", "tutorialUrl",
    "learn_url", "learnUrl", "academy_url", "academyUrl", "training_url", "trainingUrl", "course_url", "courseUrl",
    "class_url", "classUrl", "lesson_url", "lessonUrl", "module_url", "moduleUrl", "chapter_url", "chapterUrl",
    "section_url", "sectionUrl", "pageUrl", "view_url", "viewUrl", "display_url", "displayUrl", "show_url",
    "showUrl", "detail_url", "detailUrl", "info_url", "infoUrl", "about_url", "aboutUrl", "company_url",
    "companyUrl", "team_url", "teamUrl", "careers_url", "careersUrl", "jobs_url", "jobsUrl", "press_url",
    "pressUrl", "news_url", "newsUrl", "blog_url", "blogUrl", "article_url", "articleUrl", "post_url",
    "postUrl", "story_url", "storyUrl", "event_url", "eventUrl", "calendar_url", "calendarUrl", "schedule_url",
    "scheduleUrl", "webinar_url", "webinarUrl", "podcast_url", "podcastUrl", "feedback_url", "feedbackUrl", "survey_url",
    "surveyUrl", "poll_url", "pollUrl", "review_url", "reviewUrl", "rating_url", "ratingUrl", "comment_url",
    "commentUrl", "reply_url", "replyUrl", "thread_url", "threadUrl", "topic_url", "topicUrl", "forum_url",
    "forumUrl", "community_url", "communityUrl", "group_url", "groupUrl", "org_url", "orgUrl", "organization_url",
    "organizationUrl", "business_url", "businessUrl", "enterprise_url", "enterpriseUrl", "jsonp_callback", "jsonpcallback", "json_callback",
    "jsonCallback", "cb_func", "cbFunc", "cb_name", "cbName", "func", "function", "fn",
    "handler", "exec", "execute", "run", "eval", "evaluate", "script_name", "scriptName",
    "script_src", "scriptSrc", "script_url", "scriptUrl", "javascript", "javascript_url", "javascriptUrl", "http_method",
    "httpMethod", "request_method", "requestMethod", "verb", "http_verb", "httpVerb", "action_method", "actionMethod",
    "call_method", "callMethod", "invoke_method", "invokeMethod", "exec_method", "execMethod", "run_method", "runMethod",
    "do_method", "doMethod", "perform_method", "performMethod", "execute_method", "executeMethod", "authorization", "proxy_authorization",
    "proxyAuthorization", "www_authenticate", "wwwAuthenticate", "proxy_authenticate", "proxyAuthenticate", "authentication_info", "authenticationInfo", "auth_info",
    "authInfo", "auth_scheme", "authScheme", "auth_type", "authType", "auth_method", "authMethod", "auth_protocol",
    "authProtocol", "auth_version", "authVersion", "auth_realm", "authRealm", "auth_domain", "authDomain", "auth_path",
    "authPath", "auth_scope", "authScope", "auth_audience", "authAudience", "auth_issuer", "authIssuer", "auth_subject",
    "authSubject", "auth_client", "authClient", "auth_client_id", "authClientId", "auth_client_secret", "authClientSecret", "auth_redirect_uri",
    "authRedirectUri", "auth_redirect_url", "authRedirectUrl", "auth_response_type", "authResponseType", "auth_response_mode", "authResponseMode", "auth_state",
    "authState", "auth_nonce", "authNonce", "auth_code", "authCode", "auth_code_challenge", "authCodeChallenge", "auth_code_challenge_method",
    "authCodeChallengeMethod", "auth_grant_type", "authGrantType", "auth_access_token", "authAccessToken", "auth_refresh_token", "authRefreshToken", "auth_id_token",
    "authIdToken", "auth_session_token", "authSessionToken", "auth_api_key", "authApiKey", "auth_secret", "authSecret", "auth_password",
    "authPassword", "auth_username", "authUsername", "auth_email", "authEmail", "auth_phone", "authPhone", "auth_otp",
    "authOtp", "auth_totp", "authTotp", "auth_mfa", "authMfa", "auth_2fa", "auth2fa", "auth_webauthn",
    "authWebauthn", "auth_passkey", "authPasskey", "auth_fido", "authFido", "auth_u2f", "authU2f", "auth_hotp",
    "authHotp", "auth_saml", "authSaml", "auth_oidc", "authOidc", "auth_oauth", "authOauth", "auth_oauth2",
    "authOauth2", "auth_oauth1", "authOauth1", "auth_oauth1a", "authOauth1a", "auth_jwt", "authJwt", "auth_jws",
    "authJws", "auth_jwe", "authJwe", "auth_jwk", "authJwk", "auth_jwks", "authJwks", "auth_jku",
    "authJku", "auth_jti", "authJti", "auth_iat", "authIat", "auth_exp", "authExp", "auth_nbf",
    "authNbf", "auth_iss", "authIss", "auth_sub", "authSub", "auth_aud", "authAud", "auth_typ",
    "authTyp", "auth_alg", "authAlg", "auth_kid", "authKid", "auth_x5u", "authX5u", "auth_x5c",
    "authX5c", "auth_x5t", "authX5t", "auth_x5t_s256", "authX5tS256", "auth_crit", "authCrit", "auth_b64",
    "authB64", "auth_enc", "authEnc", "auth_zip", "authZip", "auth_deflate", "authDeflate", "auth_gzip",
    "authGzip", "auth_brotli", "authBrotli", "auth_zstd", "authZstd", "auth_lz4", "authLz4", "auth_snappy",
    "authSnappy", "auth_lzo", "authLzo", "auth_lzma", "authLzma", "auth_xz", "authXz", "auth_bzip2",
    "authBzip2", "auth_7z", "auth7z", "auth_rar", "authRar", "auth_tar", "authTar", "auth_gz",
    "authGz", "auth_tgz", "authTgz", "auth_bz2", "authBz2", "auth_lz", "authLz", "cookie",
    "cookies", "set_cookie", "setCookie", "get_cookie", "getCookie", "delete_cookie", "deleteCookie", "clear_cookie",
    "clearCookie", "cookie_name", "cookieName", "cookie_value", "cookieValue", "cookie_domain", "cookieDomain", "cookie_path",
    "cookiePath", "cookie_expires", "cookieExpires", "cookie_secure", "cookieSecure", "cookie_httponly", "cookieHttpOnly", "cookie_samesite",
    "cookieSameSite", "cookie_partitioned", "cookiePartitioned", "cookie_first_party", "cookieFirstParty", "cookie_third_party", "cookieThirdParty", "cookie_cross_site",
    "cookieCrossSite", "cookie_same_site", "cookie_lax", "cookieLax", "cookie_strict", "cookieStrict", "cookie_none", "cookieNone",
    "localStorage", "localstorage", "sessionStorage", "sessionstorage", "indexedDB", "indexeddb", "caches", "cacheStorage",
    "serviceWorker", "serviceworker", "cookieStore", "cookiestore", "cookie_store", "cookie_jar", "cookieJar", "cookie_manager",
    "cookieManager", "cookie_handler", "cookieHandler", "cookie_parser", "cookieParser", "cookie_serializer", "cookieSerializer", "cookie_stringifier",
    "cookieStringifier", "cookie_encoder", "cookieEncoder", "cookie_decoder", "cookieDecoder", "cookie_hasher", "cookieHasher", "cookie_signer",
    "cookieSigner", "cookie_verifier", "cookieVerifier", "cookie_validator", "cookieValidator", "cookie_checker", "cookieChecker", "cookie_scanner",
    "cookieScanner", "cookie_analyzer", "cookieAnalyzer", "cookie_detector", "cookieDetector", "cookie_finder", "cookieFinder", "cookie_extractor",
    "cookieExtractor", "cookie_collector", "cookieCollector", "cookie_gatherer", "cookieGatherer", "cookie_tracker", "cookieTracker", "cookie_monitor",
    "cookieMonitor", "cookie_logger", "cookieLogger", "cookie_auditor", "cookieAuditor", "cookie_inspector", "cookieInspector", "cookie_viewer",
    "cookieViewer", "cookie_editor", "cookieEditor", "cookie_modifier", "cookieModifier", "cookie_changer", "cookieChanger", "cookie_updater",
    "cookieUpdater", "cookie_deleter", "cookieDeleter", "cookie_remover", "cookieRemover", "cookie_clearer", "cookieClearer", "cookie_eraser",
    "cookieEraser", "cookie_cleaner", "cookieCleaner", "cookie_purger", "cookiePurger", "cookie_wiper", "cookieWiper", "cookie_scrubber",
    "cookieScrubber", "cookie_sanitizer", "cookieSanitizer", "cookie_filter", "cookieFilter",
)

@dataclass
class FuzzResult:
    url: str
    status: int = 0
    size: int = 0
    content_type: str = ""
    redirect: str = ""
    words: int = 0
    source: str = "dir"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "size": self.size,
            "content_type": self.content_type,
            "redirect": self.redirect,
            "words": self.words,
            "source": self.source,
        }


@dataclass
class DiscoveredParameter:
    url: str
    name: str
    method: str = "GET"
    evidence: str = ""
    reflected: bool = False
    status: int = 0
    baseline_status: int = 0
    size_delta: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "name": self.name,
            "method": self.method,
            "evidence": self.evidence,
            "reflected": self.reflected,
            "status": self.status,
            "baseline_status": self.baseline_status,
            "size_delta": self.size_delta,
        }

    def key(self) -> str:
        return f"{self.method}|{self.url}|{self.name}"


def load_wordlist(path: Optional[str], fallback: Sequence[str], limit: int = 5000) -> List[str]:
    words: List[str] = []
    seen: Set[str] = set()
    if path:
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
                for line in handle:
                    word = line.strip()
                    if not word or word.startswith("#"):
                        continue
                    if word not in seen:
                        seen.add(word)
                        words.append(word)
                    if len(words) >= limit:
                        break
        except OSError:
            pass
    for word in fallback:
        if word and word not in seen:
            seen.add(word)
            words.append(word)
        if len(words) >= limit:
            break
    return words


def expand_paths(words: Iterable[str], extensions: Sequence[str] = FUZZ_EXTENSIONS) -> List[str]:
    # Extension-major ordering: every word's bare path is emitted first, then
    # one pass per extension.  With a truncated candidate budget this guarantees
    # broad word coverage plus the high-value extensions instead of exhausting
    # the budget on extension variants of only the first few words.
    cleaned: List[str] = []
    seen_words: Set[str] = set()
    for word in words:
        word = word.strip().lstrip("/")
        if word and word not in seen_words:
            seen_words.add(word)
            cleaned.append(word)

    paths: List[str] = []
    seen: Set[str] = set()

    def _emit(candidate: str) -> None:
        if candidate and candidate not in seen:
            seen.add(candidate)
            paths.append(candidate)

    for word in cleaned:
        _emit(word)
    for ext in extensions:
        if not ext:
            continue
        for word in cleaned:
            if not word.endswith(ext):
                _emit(word + ext)
    return paths


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _soft_404_signature(status: int, body: str) -> Tuple[int, int, str]:
    # Collapse nonces, timestamps, request ids and other per-response noise so
    # a catch-all page that echoes a random token still matches its baseline.
    normalized = re.sub(r"\s+", " ", (body or "")[:4000]).strip().lower()
    normalized = re.sub(r"[0-9a-f]{8,}", " ", normalized)
    normalized = re.sub(r"\d{4,}", " ", normalized)
    return status, len(body or ""), hashlib.sha1(normalized.encode("utf-8", "replace")).hexdigest()


class DirFuzzer:
    """Small, safe content-discovery engine."""

    def __init__(
        self,
        http: HttpLike,
        console: ConsoleLike,
        *,
        wordlist: Optional[str] = None,
        extensions: Sequence[str] = FUZZ_EXTENSIONS,
        concurrency: int = 10,
        limit: int = 2000,
        timeout: float = 10.0,
    ):
        self.http = http
        self.console = console
        self.words = expand_paths(load_wordlist(wordlist, DIR_WORDS, limit), extensions)[:limit]
        self.concurrency = max(1, concurrency)
        self.timeout = max(3.0, timeout)
        self._baselines: Dict[str, Tuple[int, int, str]] = {}

    async def _baseline(self, origin: str) -> Tuple[int, int, str]:
        if origin not in self._baselines:
            token = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
            try:
                response = await asyncio.wait_for(
                    self.http.get(f"{origin}/{token}", allow_redirects=False, cache=False),
                    timeout=self.timeout,
                )
                self._baselines[origin] = _soft_404_signature(
                    getattr(response, "status", 0), getattr(response, "text", "")
                )
            except Exception:
                self._baselines[origin] = (404, 0, "")
        return self._baselines[origin]

    async def _probe(self, url: str, origin: str, baseline: Tuple[int, int, str]) -> Optional[FuzzResult]:
        try:
            response = await asyncio.wait_for(
                self.http.get(url, allow_redirects=False, cache=False), timeout=self.timeout
            )
        except Exception:
            return None
        if getattr(response, "error", None):
            return None
        status = int(getattr(response, "status", 0) or 0)
        if status not in (200, 201, 204, 206, 301, 302, 303, 307, 308, 401, 403, 405):
            return None
        body = getattr(response, "text", "") or ""
        signature = _soft_404_signature(status, body)
        # Same normalised body as the random-path baseline: this is a catch-all
        # (soft-404) page, regardless of its status code.
        length_tolerance = max(32, baseline[1] // 20)
        if (
            signature[2] == baseline[2]
            and abs(signature[1] - baseline[1]) <= length_tolerance
        ):
            return None
        headers = getattr(response, "headers", {}) or {}
        return FuzzResult(
            url=str(getattr(response, "url", "") or url),
            status=status,
            size=len(body),
            content_type=str(headers.get("content-type", "")),
            redirect=str(headers.get("location", "")),
            words=len(body.split()),
            source="dir",
        )

    async def discover(
        self,
        target: str,
        *,
        recursive: bool = False,
        max_depth: int = 1,
        base_path: str = "",
    ) -> List[FuzzResult]:
        origin = _origin(target)
        baseline = await self._baseline(origin)
        start = origin + "/"
        if base_path.strip("/"):
            start = origin + "/" + base_path.strip("/") + "/"
        queue: List[Tuple[str, int]] = [(start, 0)]
        seen: Set[str] = set()
        probed: Set[str] = set()
        results: List[FuzzResult] = []
        semaphore = asyncio.Semaphore(self.concurrency)

        while queue:
            base, depth = queue.pop(0)
            if base in seen:
                continue
            seen.add(base)

            async def probe(
                path: str, base_url: str = base
            ) -> Optional[FuzzResult]:
                url = urljoin(base_url, path)
                if url in probed:
                    return None
                probed.add(url)
                async with semaphore:
                    return await self._probe(url, origin, baseline)

            group = await asyncio.gather(*(probe(path) for path in self.words), return_exceptions=True)
            for item in group:
                if not isinstance(item, FuzzResult):
                    continue
                results.append(item)
                if not recursive or depth >= max_depth:
                    continue
                path = urlsplit(item.url).path
                leaf = path.rstrip("/").rsplit("/", 1)[-1]
                looks_like_directory = item.url.endswith("/") or (
                    item.status in (200, 201, 204, 301, 302, 303, 307, 308)
                    and "." not in leaf
                )
                if looks_like_directory and _origin(item.url) == origin:
                    queue.append((item.url.rstrip("/") + "/", depth + 1))
            self.console.debug(
                f"Directory fuzzing {base}: {len(results)} hit(s) so far"
            )
        return results


class ParameterMiner:
    """Find hidden query parameters by observing response deltas."""

    def __init__(
        self,
        http: HttpLike,
        console: ConsoleLike,
        *,
        marker: str = "xoxss",
        concurrency: int = 8,
        timeout: float = 10.0,
    ):
        self.http = http
        self.console = console
        self.marker = marker
        self.concurrency = max(1, concurrency)
        self.timeout = max(3.0, timeout)

    @staticmethod
    def _with_param(url: str, name: str, value: str) -> str:
        parts = urlsplit(url)
        query = parse_qsl(parts.query, keep_blank_values=True)
        query = [(key, val) for key, val in query if key != name]
        query.append((name, value))
        return urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), parts.fragment)
        )

    async def _baseline(self, url: str) -> Any:
        try:
            return await asyncio.wait_for(
                self.http.get(url, allow_redirects=True, cache=True), timeout=self.timeout
            )
        except Exception:
            return None

    async def mine(
        self,
        urls: Sequence[str],
        param_names: Sequence[str],
        *,
        limit_per_url: int = 40,
    ) -> List[DiscoveredParameter]:
        discovered: List[DiscoveredParameter] = []
        seen: Set[str] = set()
        semaphore = asyncio.Semaphore(self.concurrency)
        names = list(dict.fromkeys(param_names))[:limit_per_url]

        async def check(url: str, name: str, baseline: Any) -> Optional[DiscoveredParameter]:
            async with semaphore:
                candidate = self._with_param(url, name, self.marker)
                try:
                    response = await asyncio.wait_for(
                        self.http.get(candidate, allow_redirects=True, cache=False),
                        timeout=self.timeout,
                    )
                except Exception:
                    return None
                if getattr(response, "error", None):
                    return None
                body = getattr(response, "text", "") or ""
                base_body = getattr(baseline, "text", "") if baseline is not None else ""
                status = int(getattr(response, "status", 0) or 0)
                base_status = int(getattr(baseline, "status", 0) or 0) if baseline is not None else 0
                reflected = self.marker in body
                delta = len(body) - len(base_body)
                changed = status != base_status or abs(delta) > 24
                if not reflected and not changed:
                    return None
                evidence = (
                    "marker reflected"
                    if reflected
                    else f"status {base_status}->{status}, size {delta:+d}"
                )
                return DiscoveredParameter(
                    url=url,
                    name=name,
                    evidence=evidence,
                    reflected=reflected,
                    status=status,
                    baseline_status=base_status,
                    size_delta=delta,
                )

        for url in urls:
            baseline = await self._baseline(url)
            if baseline is None or getattr(baseline, "error", None):
                # Without a usable baseline every response looks like a huge
                # delta, which would report the entire wordlist as "found".
                self.console.debug(f"Parameter mining: no baseline for {url}, skipping")
                continue
            group = await asyncio.gather(
                *(check(url, name, baseline) for name in names), return_exceptions=True
            )
            for item in group:
                if isinstance(item, DiscoveredParameter) and item.key() not in seen:
                    seen.add(item.key())
                    discovered.append(item)
            if len(discovered) >= 500:
                break
        if discovered:
            self.console.info(
                f"Parameter mining: {len(discovered)} hidden parameter(s) discovered",
                important=False,
            )
        return discovered


__all__ = [
    "DIR_WORDS",
    "FUZZ_EXTENSIONS",
    "PARAM_WORDS",
    "DirFuzzer",
    "DiscoveredParameter",
    "FuzzResult",
    "ParameterMiner",
    "expand_paths",
    "load_wordlist",
]
