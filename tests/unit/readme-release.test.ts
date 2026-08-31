import { readFile, stat } from "node:fs/promises";
import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

describe("release README", () => {
  it("keeps the approved release structure, features, and exactly three quick-start steps", async () => {
    const readme = await readFile("README.md", "utf8");
    const headings = [...readme.matchAll(/^## (.+)$/gm)].map(
      (match) => match[1] ?? "",
    );
    expect(headings).toEqual([
      "Why we built this",
      "Features",
      "Quick start",
      "Mock workflow and limits",
      "Making it yours",
      "About Mastra templates",
    ]);
    const featureBlock = readme.match(
      /## Features\n\n([\s\S]*?)\n## Quick start/,
    );
    expect(featureBlock?.[1]?.match(/^- /gm) ?? []).toHaveLength(4);
    expect(readme.match(/^### [123]\. /gm)).toHaveLength(3);
  });

  it("uses the approved URL onboarding and first Studio interaction", async () => {
    const readme = await readFile("README.md", "utf8");
    expect(readme).toContain(
      "npx create-mastra@latest template-security-incident-triage --template https://github.com/drantunes/template-security-incident-triage",
    );
    expect(readme).toContain("cd template-security-incident-triage");
    expect(readme).toContain("cp .env.example .env");
    expect(readme).toContain("without external API keys\nor webhook secrets");
    expect(readme).toContain("npm run dev");
    expect(readme).toContain("baselineWorkflow");
    expect(readme).toContain(
      '{ "message": "Studio is ready", "status": "ready" }',
    );
    expect(readme).not.toMatch(
      /production-ready|template-security-incident-triage\s*slug|official Mastra template/i,
    );
  });

  it("states the community ownership and Apache-2.0 metadata factually", async () => {
    const [readme, contributing, manifest, license] = await Promise.all([
      readFile("README.md", "utf8"),
      readFile("CONTRIBUTING.md", "utf8"),
      readFile("package.json", "utf8"),
      readFile("LICENSE", "utf8"),
    ]);
    expect(readme).toContain("authored and maintained by Diego");
    expect(readme).toContain(
      "Mastra templates are ready-to-use projects that show what you can build with\nMastra. Clone one, try it in Studio, and adapt it to your use case.",
    );
    expect(readme).toContain(
      "npm run retention:sweep -- --tenant <tenant> --limit <1-1024>",
    );
    expect(contributing).toContain("authored and maintained by Diego");
    expect(JSON.parse(manifest)).toMatchObject({ license: "Apache-2.0" });
    expect(license).toMatch(/^Apache License\nVersion 2\.0, January 2004/);
  });

  it("keeps local release metadata factual and private", async () => {
    const [manifest, changelog, mediaNotes] = await Promise.all([
      readFile("package.json", "utf8"),
      readFile("CHANGELOG.md", "utf8"),
      readFile("docs/media/README.md", "utf8"),
    ]);
    expect(JSON.parse(manifest)).toMatchObject({
      name: "template-security-incident-triage",
      private: true,
      repository: {
        url: "https://github.com/drantunes/template-security-incident-triage.git",
      },
      bugs: {
        url: "https://github.com/drantunes/template-security-incident-triage/issues",
      },
    });
    expect(changelog).toContain("0.1.0 — local candidate notes");
    expect(changelog).toContain("untagged, unpublished");
    expect(mediaNotes).toContain("studio-baseline-workflow.jpg");
    expect(mediaNotes).toContain(
      "393e9024610f1ce28e047e4ac5a109918f13bcdbccb7f64154d195424d745df0",
    );
  });

  it("references the verified synthetic Studio JPEG without release claims", async () => {
    const [readme, mediaNotes, image, imageStat] = await Promise.all([
      readFile("README.md", "utf8"),
      readFile("docs/media/README.md", "utf8"),
      readFile("docs/assets/studio-baseline-workflow.jpg"),
      stat("docs/assets/studio-baseline-workflow.jpg"),
    ]);
    expect(readme).toContain("docs/assets/studio-baseline-workflow.jpg");
    expect(readme).toContain("synthetic baselineWorkflow output");
    expect(image.subarray(0, 3)).toEqual(Buffer.from([0xff, 0xd8, 0xff]));
    expect(imageStat.size).toBe(22_240);
    expect(createHash("sha256").update(image).digest("hex")).toBe(
      "393e9024610f1ce28e047e4ac5a109918f13bcdbccb7f64154d195424d745df0",
    );
    expect(mediaNotes).toContain("JPEG/JFIF, 1280×720");
    expect(mediaNotes).toContain("no sensitive EXIF or XMP");
    expect(mediaNotes).toContain("does not imply a\n  tag, GitHub Release");
  });
});
