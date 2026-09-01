/** Prevent public demos from making claims the repository cannot evidence. */
import { readFile } from 'node:fs/promises';

const publicSurfaces = ['demo/index.html', 'demo-bpc/index.html'];
const prohibited = [
  /patent pending/i,
  /patent filing in progress/i,
  /fully compromised client cannot forge/i,
  /final barrier/i,
  /deceptive\s*<code>ok:true/i,
  /designed for regulated industries/i,
];

for (const file of publicSurfaces) {
  const source = await readFile(file, 'utf8');
  for (const claim of prohibited) {
    if (claim.test(source)) throw new Error(`${file} contains unsupported public claim: ${claim}`);
  }
}

console.log(`Claim surface: PASS (${publicSurfaces.length} public demo surfaces contain no unsupported patent, compromise, or compliance claims)`);
