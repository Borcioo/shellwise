import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

// npm scripts run with the Astro project (`site/`) as the working directory.
export const RULES_DIR = path.resolve(process.cwd(), '../docs/rules');

/** Rule ids: the file names of `docs/rules/*.md` without the extension, case kept. */
export function listRuleIds(dir = RULES_DIR) {
	const ids = readdirSync(dir)
		.filter((name) => name.endsWith('.md'))
		.map((name) => name.slice(0, -3))
		.sort((a, b) => a.localeCompare(b, 'en'));
	if (ids.length === 0) throw new Error(`no rule files found in ${dir}`);
	return ids;
}

/** The first paragraph of a rule file, or '' when the file opens with a table, list or code. */
export function ruleSummary(id, dir = RULES_DIR) {
	const blocks = readFileSync(path.join(dir, `${id}.md`), 'utf8')
		.replace(/\r\n/g, '\n')
		.split(/\n{2,}/)
		.map((block) => block.trim())
		.filter((block) => block && !block.startsWith('# '));
	const first = blocks[0] ?? '';
	if (/^([|>#-]|```|\d+\.)/.test(first)) return '';
	return first.replace(/\n/g, ' ');
}
