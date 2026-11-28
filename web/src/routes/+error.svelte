<script lang="ts">
	import { page } from '$app/state';
	import { resolve } from '$app/paths';
	import Icon from '#lib/ui/Icon.svelte';
</script>

<svelte:head>
	<title>{page.status === 404 ? 'Page not found' : 'Error'} · Faro</title>
</svelte:head>

<h1>{page.status === 404 ? 'Page not found' : 'Something went wrong'}</h1>
<p class="muted">
	{page.status === 404 ? 'There is no page at this address.' : page.error?.message}
</p>
<p><a class="back" href={resolve('/')}><Icon name="arrow-left" /> Go to the start page</a></p>
