  ## Supported Versions

  SecOpsTM is currently in **alpha**. Only the latest published version receives security fixes.

  | Version       | Supported          |
  | ------------- | ------------------ |
  | 1.1.x (latest) | :white_check_mark: |
  | < 1.1         | :x:                |

  ## Reporting a Vulnerability

  **Do not open a public GitHub issue for security vulnerabilities.**

  Please report vulnerabilities by emailing the maintainer directly or by using [GitHub Private Security
  Advisories](https://github.com/ellipse2v/SecOpsTM/security/advisories/new).

  Include in your report:
  - A description of the vulnerability and its potential impact
  - Steps to reproduce (proof of concept if possible)
  - Affected version(s)
  - Any suggested mitigation if you have one

  ### What to expect

  | Timeline | Action |
  | -------- | ------ |
  | **48 hours** | Acknowledgement of your report |
  | **7 days** | Initial assessment and severity triage |
  | **30 days** | Patch or documented mitigation for confirmed vulnerabilities |

  If a vulnerability is confirmed, a fix will be released as soon as possible and a [GitHub Security
  Advisory](https://github.com/ellipse2v/SecOpsTM/security/advisories) will be published. You will be credited unless you request otherwise.

  If a report is declined (not reproducible, out of scope, or not a security issue), you will receive an explanation within 7 days.

  ## Scope

  The following are considered in scope:

  - Remote code execution via the web server (`--server` mode)
  - Unauthorized access to the filesystem through the API
  - Injection vulnerabilities (YAML, template, command) in system model parsing
  - Authentication bypass (if authentication is added in future versions)

  The following are **out of scope**:

  - Vulnerabilities in dependencies (report those upstream)
  - Issues only exploitable by users with local filesystem access who are already trusted
  - Denial of service against a locally-run server instance

  ## Security considerations for deployment

  SecOpsTM's web server (`secopstm --server`) is designed for **local and trusted-network use only**. It has no built-in authentication. Do not expose it to the
  public internet.

