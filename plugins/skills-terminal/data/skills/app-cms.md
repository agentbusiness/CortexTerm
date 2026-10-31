Deploy or maintain WordPress, Ghost, Strapi or Directus and diagnose their service dependencies.

## Inspect

Identify the CMS, release and installation method. Read the existing package or image version, deployment file and supported requirements. These products use different runtimes and database arrangements; choose the matching release guide rather than guessing.

Inspect the relevant service state and bounded logs. Establish public URL, proxy routing, database, writable uploads and extension storage. Check required scheduled jobs and mail behavior. A web-server welcome page does not establish the CMS is served from the correct directory.

## Propose

Use scoped config previews and user-run install or update stages. Keep secrets and private content out of output. Preserve content, uploads, config and the database before changes. Do not remove plugins, reset the database or make the application tree world-writable as a generic repair.

## Verify

Check the public page, administration access, a representative asset and the affected route. Inspect logs after an update. A successful package install does not prove content rendering or scheduled work. Restore a compatible application/data set if an update requires recovery, and hand custom source repairs to CortexCode.
