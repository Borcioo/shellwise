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

/** Every file in `dir` as a forward-slash path relative to it, spelled as on disk. */
function allFiles(dir, prefix = '') {
	return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
		const rel = prefix + entry.name;
		return entry.isDirectory() ? allFiles(path.join(dir, entry.name), rel + '/') : [rel];
	});
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

	// Targets are matched against the exact spelling on disk: the Pages host is case-sensitive.
	const onDisk = new Set(allFiles(dist));
	if (!onDisk.has('pagefind/pagefind.js')) fail('dist/pagefind/pagefind.js is missing: search would not work');

	const files = htmlFiles(dist);
	pages = files.length;
	const htmlOf = new Map(files.map((file) => [path.relative(dist, file).replaceAll('\\', '/'), readFileSync(file, 'utf8')]));
	const idsOf = new Map();
	const idsIn = (name) => {
		if (!idsOf.has(name)) {
			idsOf.set(name, new Set([...htmlOf.get(name).matchAll(/\sid=(?:"([^"]*)"|'([^']*)')/g)].map((m) => m[1] ?? m[2])));
		}
		return idsOf.get(name);
	};

	// A rendered repository document must carry content, not only the page chrome.
	const rendered = [...built.map((id) => `docs/rules/${id}/index.html`), 'docs/changelog/index.html', 'docs/agents/setup-text/index.html'];
	for (const name of rendered) {
		const body = htmlOf.get(name)?.split('class="source-doc"')[1] ?? '';
		if (body.replace(/<[^>]*>/g, '').trim().length < 80) fail(`${name}: the rendered document is empty or missing`);
	}
	if (!/<section[\s\S]*<footer/.test(htmlOf.get('index.html') ?? '')) fail('index.html: the landing page has lost its sections or footer');

	for (const [name, html] of htmlOf) {
		for (const match of html.matchAll(/\s(?:href|src)=(?:"([^"]*)"|'([^']*)')/g)) {
			const url = (match[1] ?? match[2]).replaceAll('&amp;', '&');
			if (/docs\/(design|spikes)\.md|docs\/superpowers|\/(tree|blob)\/[^/]+\/docs\/?(?:[#?]|$)/.test(url)) {
				fail(`${name}: link to a maintainer document: ${url}`);
			}
			if (url === '' || url.startsWith('//') || /^[a-z][a-z0-9+.-]*:/i.test(url)) continue;
			if (url.startsWith('#')) {
				const id = decodeURIComponent(url.slice(1));
				if (id !== '' && !idsIn(name).has(id)) fail(`${name}: link to a missing anchor: ${url}`);
				continue;
			}
			if (!url.startsWith('/')) {
				fail(`${name}: relative link (write it from ${BASE}): ${url}`);
				continue;
			}
			links += 1;
			if (!url.startsWith(BASE)) {
				fail(`${name}: internal link without the ${BASE} base: ${url}`);
				continue;
			}
			const [pathPart, fragment = ''] = url.slice(BASE.length).split('?')[0].split('#');
			const target = decodeURIComponent(pathPart);
			const asPage = target === '' || target.endsWith('/') ? `${target}index.html` : `${target}/index.html`;
			const hit = onDisk.has(target) ? target : onDisk.has(asPage) ? asPage : null;
			if (hit === null) {
				fail(`${name}: link points at nothing: ${url}`);
			} else if (fragment !== '' && htmlOf.has(hit) && !idsIn(hit).has(decodeURIComponent(fragment))) {
				fail(`${name}: link to a missing anchor: ${url}`);
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
