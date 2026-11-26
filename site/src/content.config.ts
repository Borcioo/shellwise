import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

export const collections = {
	// Hand-written pages.
	docs: defineCollection({ loader: docsLoader(), schema: docsSchema() }),
	// One entry per rule, read from the repository's rule files. The id is the file name, case kept.
	rules: defineCollection({
		loader: glob({
			pattern: '*.md',
			base: '../docs/rules',
			generateId: ({ entry }) => entry.replace(/\.md$/, ''),
		}),
	}),
	// Other repository documents the site renders as they are.
	repo: defineCollection({
		loader: glob({
			pattern: ['CHANGELOG.md', 'docs/agent-setup.md'],
			base: '..',
			generateId: ({ entry }) => entry,
		}),
	}),
};
