// The service worker: precaches this exact build so the page works with no
// network at all, which is the product invariant made literal — verifying needs
// no server, ours or anyone's. `build.mjs` generates the two constants below:
// the list of shipped files and a build id derived from their hashes, so a new
// build gets a new cache and the old one is deleted on activation. Requests are
// answered from the cache first; anything not shipped goes to the network as
// the page asked (today nothing does).
declare const __VCAP_PRECACHE__: string[]
declare const __VCAP_BUILD__: string

// The DOM lib types `self` as a Window; this is the slice of the worker scope
// used here, typed locally rather than pulling the WebWorker lib into a page
// tsconfig that also has DOM.
interface WorkerScope {
  registration: { scope: string }
  skipWaiting (): Promise<void>
  clients: { claim (): Promise<void> }
  addEventListener (type: 'install' | 'activate', listener: (event: { waitUntil (p: Promise<unknown>): void }) => void): void
  addEventListener (type: 'fetch', listener: (event: { request: Request, respondWith (r: Promise<Response>): void }) => void): void
}
const sw = self as unknown as WorkerScope

const CACHE = `vcap-verifier-${__VCAP_BUILD__}`
const scope = sw.registration.scope
const index = new URL('index.html', scope).href
const precache = __VCAP_PRECACHE__.map((name) => new URL(name, scope).href)

sw.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE)
    // `cache: 'reload'` bypasses the HTTP cache: what gets stored is what the
    // server serves now, not a stale copy some intermediary kept.
    await Promise.all(precache.map(async (url) => {
      const response = await fetch(url, { cache: 'reload' })
      if (!response.ok) throw new Error(`[vcap] precache ${url}: ${response.status}`)
      await cache.put(url, response)
    }))
    await sw.skipWaiting()
  })())
})

sw.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) {
      if (key !== CACHE && key.startsWith('vcap-verifier-')) await caches.delete(key)
    }
    await sw.clients.claim()
  })())
})

sw.addEventListener('fetch', (event) => {
  const { request } = event
  if (request.method !== 'GET') return
  // The scope URL itself is the page: the server answers it with index.html
  // and so does the cache. Every other URL is looked up as is.
  const url = new URL(request.url)
  url.search = ''
  const key = url.href === scope ? index : url.href
  event.respondWith(caches.match(key, { cacheName: CACHE }).then((hit) => hit ?? fetch(request)))
})
