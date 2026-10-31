Inspect CSV/TSV delimiters, quoting, headers and record boundaries before editing or importing.

Determine the producer and consumer, encoding, delimiter, header row, null convention and expected column types. A filename alone cannot establish these.

Inspect with format `csv` or `tsv`. Quoted fields can contain delimiters and newlines, so a physical line is not always a record. Do not use `cut` or a global substitution to repair arbitrary CSV.

For one small known literal correction, preview unique context with the inspect hash. Preserve quoting and line endings. For transformations across records, hand coding work to CortexCode or use the product's import tool with an explicit mapping.

The helper checks CSV quoting with the selected delimiter. It does not validate column meaning, consistent field counts or database types. Read a bounded sample and check record counts with a proper CSV reader.

Before import, preview the mapping and use a staging table or supported transaction where appropriate. After the person's import, compare row counts, rejected rows and representative values. Keep the source file and recovery route.
