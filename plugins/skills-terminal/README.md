# Terminal skills 0.1.8

Compact task procedures for CortexTerm's Gemma E2B/E4B and borrowed Qwen. The library covers files, shells, Git, system services, networking, web deployments, databases, queues, search, cloud tools, business applications, AI services and configuration formats. [Workflow coverage](../../docs/terminal-skills/COVERAGE.md) maps the 100 research tasks to actual cards. Cards are source guidance; successful operation still requires real-app verification.

## Loading and tools

The terminal flow 0.1.15 keeps the catalog in the host, advertises at most five relevant cards and attaches a clear match before generation. Its `skill` tool can search for another task and read its full card. Lookups have their own budget. The model sees at most two active card bodies, not the whole library. See [loading and configuration behavior](../../docs/terminal-skills/README.md).

`run` is a bounded read-only check: no keyboard, 20 seconds, about 60 lines/4,000 bytes for the model. A refused command did not run. Changes remain user-run proposals under the terminal risk engine. The `config` tool can inspect a file or prepare a hash-bound exact-replacement preview; it cannot apply it. Native product validation and an observed health check establish the outcome.

## Package format

This is one existing `skills@1` plugin, category `skills-terminal`. `data/skills/<name>.md` uses a short plain situation summary on line 1, a blank line 2 and a self-contained Markdown procedure. Product/action names keep discovery specific. A concrete inspection, interpretation and verification matter more than a word-count target. The cards use the app's actual tool names and do not assume another coding agent's unrestricted tools.

`skills-terminal.describe` lists names and summaries; `skills-terminal.skill {name}` returns one whole card. The backend uses `cc_lang_kit::run_skills_plugin`. `data/` remains a packaged backend asset. The existing conformance probe checks catalog/read identity, a summary/body and unknown-skill behavior. It does not prove small-model task performance. There is no enforced 16-skill ceiling or 250-word minimum.

## Release verification

The 0.1.8 work was requested without a build. Source/card inspection and temporary format checks were performed; no build, package installation, service changes or Gemma/Qwen app session was run. No repository test suite, check scripts or benchmark directory were added. Validate the release in the real app, including an 8 GB Mac, before claiming operational success. [Research sources](../../docs/terminal-skills/SOURCES.md) support maintenance of version-sensitive procedures.
