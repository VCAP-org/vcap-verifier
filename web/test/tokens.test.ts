import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

/**
 * The design system's contrast gate, on the page's own tokens: every text
 * token 4.5:1 on the surfaces text is drawn on, a control's border and the
 * focus ring 3:1 (WCAG 1.4.3 and 1.4.11), in both themes. Measured here rather
 * than asserted in a comment, because the values used to be 3.45:1 and 1.54:1
 * and nothing noticed.
 */
const html = readFileSync(new URL('../src/index.html', import.meta.url), 'utf8')
const tokens = (block: string): Record<string, string> =>
  Object.fromEntries([...block.matchAll(/--([a-z-]+):\s*(#[0-9a-f]{6})/gi)].map((m) => [m[1]!, m[2]!.toLowerCase()]))
const light = tokens(html.slice(html.indexOf(':root {'), html.indexOf('@media (prefers-color-scheme: dark)')))
const dark = { ...light, ...tokens(html.slice(html.indexOf('@media (prefers-color-scheme: dark)'), html.indexOf('*, *::before'))) }

const luminance = (hex: string): number => {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((c) => c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4)
  return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!
}
const ratio = (a: string, b: string): number => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (hi! + 0.05) / (lo! + 0.05)
}

describe.each([['light', light], ['dark', dark]] as const)('%s theme', (_, t) => {
  it.each(['fg', 'fg-muted', 'fg-subtle'])('--%s is 4.5:1 on bg and bg-subtle', (name) => {
    for (const surface of ['bg', 'bg-subtle']) expect(ratio(t[name]!, t[surface]!), `${name} on ${surface}`).toBeGreaterThanOrEqual(4.5)
  })

  it.each(['border-strong', 'ring'])('--%s is 3:1 on bg and bg-subtle', (name) => {
    for (const surface of ['bg', 'bg-subtle']) expect(ratio(t[name]!, t[surface]!), `${name} on ${surface}`).toBeGreaterThanOrEqual(3)
  })

  it.each(['success', 'warning', 'danger', 'info'])('--%s is 4.5:1 on its own background and on bg', (name) => {
    expect(ratio(t[name]!, t[`${name}-bg`]!)).toBeGreaterThanOrEqual(4.5)
    expect(ratio(t[name]!, t.bg!)).toBeGreaterThanOrEqual(4.5)
  })
})
