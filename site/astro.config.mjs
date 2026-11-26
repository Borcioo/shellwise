// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { listRuleIds } from './src/lib/rules.mjs';

export default defineConfig({
	site: 'https://borcioo.github.io',
	base: '/shellwise',
	trailingSlash: 'always',
	integrations: [
		starlight({
			title: 'shellwise',
			description: 'Documentation for shellwise, a guard and linter for the shell commands AI coding agents run.',
			favicon: '/favicon.svg',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/Borcioo/shellwise' }],
			customCss: [
				'@fontsource/inter/400.css',
				'@fontsource/inter/600.css',
				'@fontsource/space-grotesk/500.css',
				'@fontsource/space-grotesk/700.css',
				'@fontsource/jetbrains-mono/400.css',
				'@fontsource/jetbrains-mono/700.css',
				'./src/styles/tokens.css',
				'./src/styles/starlight.css',
			],
			components: {
				ThemeProvider: './src/components/ThemeProvider.astro',
				ThemeSelect: './src/components/ThemeSelect.astro',
			},
			expressiveCode: {
				themes: ['github-dark'],
				shiki: {
					langAlias: {
						'guard-sh': 'sh',
						'proof-bash': 'sh',
						'guard-pwsh': 'powershell',
						'proof-pwsh': 'powershell',
					},
				},
			},
			sidebar: [
				{
					label: 'Start',
					items: [{ label: 'Overview', slug: 'docs' }],
				},
				{
					label: 'Agents',
					items: [{ label: 'Agent setup text', link: '/docs/agents/setup-text/' }],
				},
				{
					label: 'Reference',
					items: [{ label: 'Changelog', link: '/docs/changelog/' }],
				},
				{
					label: 'Rules',
					collapsed: true,
					items: [
						{ label: 'All rules', link: '/docs/rules/' },
						...listRuleIds().map((id) => ({ label: id, link: `/docs/rules/${id}/` })),
					],
				},
			],
		}),
	],
});
