import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

// The Faro web app: a static SvelteKit build that faro-server embeds and
// serves from the instance's own origin (docs/ARCHITECTURE.md §4.5). There is
// no Node server in production; every page is prerendered and talks to the
// JSON API with fetch.
//
// `npm run dev` proxies the API to a local `faro-server serve --dev` on
// :8080, so pages and API share one origin as they do in production (the
// session cookie is SameSite=Strict).
const API = process.env.FARO_DEV_API ?? 'http://127.0.0.1:8080';

export default defineConfig({
	plugins: [
		sveltekit({
			compilerOptions: {
				// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},
			adapter: adapter({
				// Served by faro-server, with status 404, for paths that are
				// neither a page nor a file.
				fallback: '404.html'
			})
			// Leave `inlineStyleThreshold` at its default of 0: the server's
			// CSP allows stylesheets from 'self' only, never inline <style>.
		})
	],
	server: {
		proxy: {
			'/v1': API,
			'/admin/api': API,
			'/.well-known': API
		}
	}
});
