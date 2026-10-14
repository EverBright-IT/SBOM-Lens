# SBOM Lens and the EU Cyber Resilience Act

The Cyber Resilience Act ([Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj))
makes an SBOM part of the technical documentation of every product with
digital elements placed on the EU market, and it already obliges
manufacturers to report actively exploited vulnerabilities. This page maps
those obligations onto what SBOM Lens does, and states plainly what it does
not do.

This is orientation, not legal advice. SBOM Lens is a viewer and checker: it
does not assess conformity, and no report it produces is a compliance
verdict.

## Timeline (as of October 2026)

- **11 September 2026: reporting applies (Article 14).** Manufacturers report
  actively exploited vulnerabilities and severe incidents through ENISA's
  Single Reporting Platform: an early warning within 24 hours, a notification
  within 72 hours, and a final report (14 days after a corrective measure is
  available for a vulnerability, one month for an incident).
- **11 December 2027: the main obligations apply.** Among them the SBOM
  (Annex I, Part II, point 1): drawn up in a commonly used, machine-readable
  format, covering at least the top-level dependencies, and provided to
  market surveillance authorities on request (Article 13(25)).
- **Not yet published:** the implementing act that may specify the SBOM's
  format and elements (Article 13(24)), and harmonised standards of the
  EN 40000 series cited in the Official Journal. Until they exist, BSI
  [TR-03183-2](https://www.bsi.bund.de/dok/TR-03183) is the most concrete
  technical reading, and it is the one SBOM Lens checks against.

Check the current state on [EUR-Lex](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
and the [Commission's CRA reporting page](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting)
before relying on these dates.

## What SBOM Lens covers

| CRA topic | What SBOM Lens does | Details |
| --- | --- | --- |
| SBOM in a commonly used, machine-readable format (Annex I, Part II, point 1) | Reads SPDX 2.x (tag-value, JSON, YAML), SPDX 3.0.x (JSON-LD), and CycloneDX 1.x (JSON or XML) | [Supported formats](../README.md#supported-formats) |
| Checking an SBOM against the technical reading | Built-in preset *BSI TR-03183-2 field coverage (approximation)*, including the format baseline the TR sets (SPDX 3.0.1+ or CycloneDX 1.6+) as a gated check | [Compliance profiles](compliance-profiles.md) |
| Dependencies beyond the top level | Resolves multi-document cascades (SPDX `ExternalDocumentRef` and 3.x imports, CycloneDX BOM-Links) into one tree, with placeholders for what is missing | [How references resolve](../README.md#how-references-resolve) |
| Article 14: which products contain the affected component? | Search by name, purl, or CPE across every loaded SBOM; the Inventory, filtered by the same query, exports the hits as CSV or JSON | [Worked example](#the-first-hours-after-an-advisory) below |
| Information on fixed vulnerabilities (Annex I, Part II, point 4) | Loads CSAF 2.0 and OpenVEX documents, your own before you publish them or your suppliers', as an overlay: the stated status per component, matched by purl or CPE (and, for CSAF, by file hash); each CSAF document is measured against BSI [TR-03191](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03191/BSI-TR-03191.html) | [VEX overlay](vex.md) |
| Due diligence on components from suppliers (Article 13(5)) | Measures a supplier's SBOM with the same presets, and checks a delivery: hashes the delivered files and compares them with the file checksums an SPDX SBOM declares | [Delivery acceptance](acceptance.md) |

Everything runs in the browser or in VS Code. SBOMs are never uploaded,
which matters when the SBOM is part of confidential technical documentation.

## What SBOM Lens does not do

- **No conformity assessment.** The BSI preset measures field coverage and is
  labelled an approximation; what it cannot check is listed in the preset's
  own description.
- **No vulnerability scanning.** There is no CVE database lookup. SBOM Lens
  shows what suppliers communicate (CSAF, OpenVEX) and finds components; it
  does not decide whether a product is affected.
- **No reporting.** It does not file Article 14 notifications; ENISA's Single
  Reporting Platform is the channel for those.
- **No SBOM generation.** Generators such as syft, trivy, or cdxgen produce
  the SBOMs; SBOM Lens reads and checks them.

## The first hours after an advisory

An advisory names an actively exploited component. The question for the
early warning is which of your products contain it.

1. Load the SBOMs of the products you ship: drop a folder, and cascades link
   up on their own.
2. Paste the component's identifier from the advisory into the search box. A
   CPE is matched by identity, not as text: a versionless
   `cpe:2.3:a:acme:thing:*:*:*:*:*:*:*:*` finds every version your SBOMs
   carry, in either the CPE 2.3 or the 2.2 form, while a CPE with a concrete
   version finds exactly that version. A purl works as well.
3. Open **Inventory**. The same query lists every occurrence across all
   loaded documents; export it as CSV or JSON for the record. In **Explore**,
   the funnel next to the search box filters the tree down to the matches and
   their ancestors, so you see where in each product the component sits.
4. If the supplier publishes a CSAF advisory or an OpenVEX document, load it
   as well: each matched component then shows the supplier's status
   (affected, not affected, fixed, under investigation).

To try it, load *ACME web (CycloneDX 1.6)* from the demo catalog and search
for `cpe:2.3:a:acme:thing:*:*:*:*:*:*:*:*`. The component it finds carries no
purl, only a CPE.

## Related regulations

NIS-2 and DORA do not mandate SBOMs as such. Their supply chain and ICT
third-party risk requirements lead regulated organisations to ask their
suppliers for SBOMs, and a supplier that places products with digital
elements on the EU market is a CRA manufacturer, so the same capabilities
serve both sides. For the certificate register that DORA's technical
standard on ICT risk management asks for (Article 7(4) of Commission
Delegated Regulation (EU) 2024/1774), a CycloneDX CBOM can be measured with
the matching preset; see [Compliance profiles](compliance-profiles.md).
