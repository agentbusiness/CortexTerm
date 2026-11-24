A package, app or Docker image has a known vulnerability, or a package is listed as malicious.

Questions:
- malicious: is it listed as malicious? Yes when rule or what has a MAL- id or says malicious.
- exploited: is the hole known to be used? Yes when rule or what says exploited.
- dev_only: is it only for development? Yes when path_class is project or toolchain and what says a development or test dependency.
- has_fix: is a fixed version named? Yes when what names a fixed version.

normal: dev_only yes with severity low or info and has_fix no.
fix: malicious no and exploited no; write the upgrade, e.g. "brew upgrade poppler", "npm install <pkg>@<fixed> in <project>", "pip install -U <pkg>", "docker pull <image>", or "update <app>".
threat: malicious yes or exploited yes; write "uninstall <package> and rotate tokens if its install script ran".
unsure: never.
Most findings of this kind on a developer's Mac are fix; pick threat only when the finding says MAL-, malicious or exploited. A familiar package name never decides.
