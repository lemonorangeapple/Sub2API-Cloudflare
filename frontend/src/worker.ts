export default {
  async fetch(request, env) {
    const url = new URL(request.url)
    try {
      const response = await env.ASSETS.fetch(request)
      if (response.status !== 404) return response
    } catch {}
    return env.ASSETS.fetch(new Request(`${url.origin}/index.html`, request))
  }
}
