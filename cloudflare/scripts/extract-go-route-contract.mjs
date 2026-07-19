// Extracts the literal Gin route surface without starting the Go application.
// The output is a migration contract, not a replacement for runtime route tests.

import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptDir = path.dirname(fileURLToPath(import.meta.url))
const repositoryRoot = path.resolve(scriptDir, '..', '..')
const summaryOnly = process.argv.includes('--summary')

const routeSources = [
    ['legacy/backend/internal/server/routes/common.go', { r: '' }],
    ['legacy/backend/internal/server/routes/auth.go', { v1: '/api/v1' }],
    ['legacy/backend/internal/server/routes/user.go', { v1: '/api/v1' }],
    ['legacy/backend/internal/server/routes/payment.go', { v1: '/api/v1' }],
    ['legacy/backend/internal/server/routes/admin.go', { v1: '/api/v1' }],
    ['legacy/backend/internal/server/routes/gateway.go', { r: '' }],
    ['legacy/backend/internal/handler/page_handler.go', { v1: '/api/v1' }],
    ['legacy/backend/internal/setup/handler.go', { r: '' }]
]

const groupPattern = /\b([A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*([A-Za-z_][A-Za-z0-9_]*)\.Group\(\s*"([^"]*)"/
const routePattern = /\b([A-Za-z_][A-Za-z0-9_]*)\.(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|Any)\(\s*"([^"]*)"/

function joinRoute(prefix, suffix) {
    const combined = `${prefix}/${suffix}`.replaceAll(/\/{2,}/g, '/')
    if (combined.length > 1 && combined.endsWith('/')) {
        return combined.slice(0, -1)
    }
    return combined || '/'
}

async function extractSource(relativePath, initialGroups) {
    const content = await readFile(path.join(repositoryRoot, relativePath), 'utf8')
    const groups = new Map(Object.entries(initialGroups))
    const routes = []
    const unresolved = []

    for (const [index, line] of content.split(/\r?\n/u).entries()) {
        const groupMatch = line.match(groupPattern)
        if (groupMatch) {
            const [, child, parent, suffix] = groupMatch
            const parentPrefix = groups.get(parent)
            if (parentPrefix !== undefined) {
                groups.set(child, joinRoute(parentPrefix, suffix))
            }
        }

        const routeMatch = line.match(routePattern)
        if (!routeMatch) {
            continue
        }

        const [, receiver, method, suffix] = routeMatch
        const prefix = groups.get(receiver)
        if (prefix === undefined) {
            unresolved.push({
                line: index + 1,
                receiver,
                source: relativePath.replaceAll('\\', '/')
            })
            continue
        }

        routes.push({
            method: method === 'Any' ? 'ANY' : method,
            path: joinRoute(prefix, suffix),
            source: relativePath.replaceAll('\\', '/'),
            line: index + 1
        })
    }

    return { routes, unresolved }
}

const extracted = await Promise.all(routeSources.map(([source, groups]) => extractSource(source, groups)))
const routes = extracted.flatMap((result) => result.routes)
const unresolved = extracted.flatMap((result) => result.unresolved)

routes.sort((left, right) => {
    return left.path.localeCompare(right.path) || left.method.localeCompare(right.method)
})

const result = {
    routeCount: routes.length,
    unresolvedCount: unresolved.length,
    unresolved,
    routes
}

process.stdout.write(`${JSON.stringify(summaryOnly ? {
    routeCount: result.routeCount,
    unresolvedCount: result.unresolvedCount,
    routeCountsBySource: Object.fromEntries(routeSources.map(([source]) => [
        source,
        routes.filter((route) => route.source === source).length
    ]))
} : result, null, 2)}\n`)

if (unresolved.length > 0) {
    process.exitCode = 1
}
