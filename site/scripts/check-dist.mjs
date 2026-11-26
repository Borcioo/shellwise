// Checks the built site in `dist/`. Exits 1 with one line per failure.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { listRuleIds } from '../src/lib/rules.mjs';

const BASE = '/shellwise/';
const dist = path.resolve(process.cwd(), 'dist');
const failures = [];
const fail = (message) => failures.push(message);

function htmlFiles(dir) {
	return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
		const full = path.join(dir, entry.name);
		if (entry.isDirectory()) return htmlFiles(full);
		return entry.name.endsWith('.html') ? [full] : [];
	});
}

function isFile(file) {
	return existsSync(file) && statSync(file).isFile();
}

const landing = path.join(dist, 'index.html');
if (!isFile(landing)) {
	fail('dist/index.html is missing (run `npm run build` first)');
} else if (!readFileSync(landing, 'utf8').includes('A seatbelt for AI agents')) {
	fail('dist/index.html lacks the landing headline "A seatbelt for AI agents"');
}

let pages = 0;
let rules = 0;
let links = 0;

if (failures.length === 0) {
	const ruleIds = listRuleIds();
	const rulesOut = path.join(dist, 'docs', 'rules');
	const built = existsSync(rulesOut)
		? readdirSync(rulesOut).filter((name) => isFile(path.join(rulesOut, name, 'index.html')))
		: [];
	rules = built.length;
	if (rules === 0) fail('no rule pages in dist/docs/rules/');
	for (const id of ruleIds) {
		// Exact, case-sensitive match: the Pages host is case-sensitive.
		if (!built.includes(id)) fail(`rule page missing for docs/rules/${id}.md`);
	}
	for (const name of built) {
		if (!ruleIds.includes(name)) fail(`rule page dist/docs/rules/${name}/ has no source file`);
	}

	for (const page of ['docs/index.html', 'docs/changelog/index.html', 'docs/agents/setup-text/index.html']) {
		if (!isFile(path.join(dist, page))) fail(`dist/${page} is missing`);
	}

	const files = htmlFiles(dist);
	pages = files.length;
	for (const file of files) {
		const name = path.relative(dist, file).replaceAll('\\', '/');
		const html = readFileSync(file, 'utf8');
		for (const match of html.matchAll(/\s(?:href|src)="([^"]*)"/g)) {
			const url = match[1].replaceAll('&amp;', '&');
			if (/docs\/(design|spikes)\.md|docs\/superpowers/.test(url)) {
				fail(`${name}: link to a maintainer document: ${url}`);
			}
			if (!url.startsWith('/') || url.startsWith('//')) continue;
			links += 1;
			if (!url.startsWith(BASE)) {
				fail(`${name}: internal link without the ${BASE} base: ${url}`);
				continue;
			}
			const target = decodeURIComponent(url.slice(BASE.length).split(/[?#]/)[0]);
			const onDisk = path.join(dist, target);
			if (!isFile(onDisk) && !isFile(path.join(onDisk, 'index.html'))) {
				fail(`${name}: link points at nothing: ${url}`);
			}
		}
	}
	if (links === 0) fail('no internal links were read');
}

if (failures.length > 0) {
	for (const message of failures) console.error(`check failed: ${message}`);
	process.exit(1);
}
console.log(`check ok: ${pages} pages, ${rules} rules, ${links} links`);
