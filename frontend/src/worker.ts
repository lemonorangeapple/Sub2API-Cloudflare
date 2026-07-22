function isStaticAssetPath(pathname: string): boolean {
  return pathname.startsWith('/assets/') || /\.[a-z0-9]+$/i.test(pathname)
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url)
    try {
      const response = await env.ASSETS.fetch(request)
      if (response.status !== 404) return response
    } catch {}

    // Never serve index.html for missing JavaScript/CSS/media assets. Doing so
    // makes browsers reject the response because its MIME type is text/html.
    if (isStaticAssetPath(url.pathname)) {
      return new Response('Not Found', {
        status: 404,
        headers: { 'content-type': 'text/plain; charset=utf-8' }
      })
    }

    return env.ASSETS.fetch(new Request(`${url.origin}/index.html`, request))
  }
}
