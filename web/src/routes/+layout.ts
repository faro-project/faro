// Every page is prerendered into the static bundle faro-server embeds.
// `/setup`, not `/setup/`: the server serves `setup.html` and redirects the
// trailing-slash form, so relative asset paths always resolve the same way.
export const prerender = true;
export const trailingSlash = 'never';
