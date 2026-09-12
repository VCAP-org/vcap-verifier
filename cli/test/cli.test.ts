import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { run, type Streams } from '../src/main.js'
// The corpus locator the core's own suite uses: same source of truth, same
// refusal to run against an empty directory.
import { corpus } from '../../core/test/corpus.js'

/**
 * The CLI's contract, which is narrower than the library's and more load
 * bearing: a script branches on the exit code, so the code is the contract and
 * the text is a courtesy.
 *
 * Run over the whole corpus, because a tool that reports a verdict is only
 * worth the corpus it agrees with — and in-process, because spawning `tsx`
 * once per vector turns this into a minute of waiting and then into something
 * nobody runs.
 */
const CORPUS = corpus()
const VECTORS = CORPUS.dir
const TRUST = join(VECTORS, '_trust')

const capture = (): { io: Streams, out: () => string, err: () => string } => {
  let out = ''
  let err = ''
  return { io: { out: (t) => { out += t }, err: (t) => { err += t } }, out: () => out, err: () => err }
}

const trustArgs = (): string[] => {
  const args: string[] = []
  const tsa = join(TRUST, 'tsa-roots.pem')
  if (existsSync(tsa)) args.push('--tsa-root', tsa)
  const logsFile = join(TRUST, 'logs.json')
  if (existsSync(logsFile)) {
    for (const log of (JSON.parse(readFileSync(logsFile, 'utf8')) as { logs: { log_id: string, spki: string }[] }).logs) {
      args.push('--log', `${log.log_id}:${log.spki}`)
    }
  }
  return args
}

// The CLI takes a file, so it exercises the `file` and `container` vectors and
// cannot exercise `segments` (a message, no container) or `jcs` (canonical
// bytes, no file). Those are declared, not dropped: the count below is pinned
// against what MANIFEST.json says the corpus holds of the two kinds this
// runner covers, so a corpus that grew — or a filter that stopped matching —
// fails here instead of quietly shrinking the suite.
const RUNS = ['file', 'container']
const fileVectors = CORPUS.names
  .filter((name) => RUNS.includes(CORPUS.kinds[name] ?? ''))
  .map((name) => ({ name, expected: JSON.parse(readFileSync(join(VECTORS, name, 'expected.json'), 'utf8')) }))

const inputOf = (name: string): string => {
  const file = readdirSync(join(VECTORS, name)).find((f) => f.startsWith('input.') && !f.endsWith('.vcap'))
  return join(VECTORS, name, file as string)
}

const VERIFIES = new Set(['authentic', 'verified_clip'])

describe('vcap-verify', () => {
  it(`runs the ${CORPUS.countOfKinds(RUNS)} file-shaped vectors of corpus ${CORPUS.version}`, () => {
    expect(fileVectors.length).toBe(CORPUS.countOfKinds(RUNS))
  })

  for (const { name, expected } of fileVectors) {
    it(`${name}: exit code and JSON outcome`, async () => {
      const { io, out } = capture()
      // No `--sidecar`: the vectors that ship one name it `input.<ext>.vcap`,
      // which is §3.1's discovery rule, so the corpus also proves the tool
      // finds a sidecar where the spec says it is — and nowhere else.
      const args = [...trustArgs(), '--json', inputOf(name)]
      if (typeof expected.verifier_clock === 'number') args.push('--at', new Date(expected.verifier_clock).toISOString())
      if (expected.kind !== 'container') args.push('--no-recompute')
      const code = await run(args, io)

      const verdict = JSON.parse(out().trim())
      expect(verdict.outcome).toBe(expected.outcome)
      // The exit code answers "should I trust this file", so it follows the
      // outcome and nothing else — a tampered file is a successful run.
      expect(code).toBe(VERIFIES.has(expected.outcome) ? 0 : 1)
    })
  }

  it('prints one JSON object per line for many files', async () => {
    const { io, out } = capture()
    const code = await run(['--json', '--no-recompute', inputOf('01-jpeg-sealed'), inputOf('05-jpeg-no-trailer')], io)
    const lines = out().trim().split('\n')

    expect(lines).toHaveLength(2)
    expect(JSON.parse(lines[0] as string).outcome).toBe('authentic')
    expect(JSON.parse(lines[1] as string).outcome).toBe('no_proof_found')
    // The worst answer decides: a script checking a directory must not pass
    // because the last file happened to be fine.
    expect(code).toBe(1)
  })

  it('--require-green fails an amber verdict without failing the file', async () => {
    const { io } = capture()
    const code = await run(['--require-green', '--no-recompute', inputOf('01-jpeg-sealed')], io)
    // 2, not 1: the file verifies. What is missing is evidence, and the two
    // are different questions a script may want to ask separately.
    expect(code).toBe(2)
  })

  it('reads a proof from a named sidecar', async () => {
    const { io, out } = capture()
    const dir = join(VECTORS, '17-jpeg-sidecar-only')
    const sidecar = readdirSync(dir).find((f) => f.endsWith('.vcap')) as string
    const code = await run(['--json', '--no-recompute', '--sidecar', join(dir, sidecar), inputOf('17-jpeg-sidecar-only')], io)

    expect(JSON.parse(out().trim()).outcome).toBe('authentic')
    expect(code).toBe(0)
  })

  it('--no-sidecar verifies the file alone', async () => {
    // Vector 17's file has no trailer: without its sidecar the honest answer
    // is that no proof was found, and a caller may want exactly that answer.
    const { io, out } = capture()
    const code = await run(['--json', '--no-recompute', '--no-sidecar', inputOf('17-jpeg-sidecar-only')], io)

    expect(JSON.parse(out().trim()).outcome).toBe('no_proof_found')
    expect(code).toBe(1)
  })

  it('fails loudly on a named sidecar that is not there', async () => {
    // Discovery may find nothing; a name given by the caller may not.
    const { io } = capture()
    await expect(run(['--json', '--sidecar', join(VECTORS, 'nope.vcap'), inputOf('01-jpeg-sealed')], io)).rejects.toThrow()
  })

  it('applies §3.1 precedence to a discovered sidecar', async () => {
    // Trailer intact and a sidecar that differs: the trailer is the proof,
    // the difference is a label. Trailer found and broken: corrupted, and the
    // intact sidecar beside it changes nothing.
    const differs = capture()
    expect(await run(['--json', '--no-recompute', inputOf('18-jpeg-sidecar-differs')], differs.io)).toBe(0)
    expect(JSON.parse(differs.out().trim()).labels).toContain('sidecar differs')

    const corrupted = capture()
    expect(await run(['--json', '--no-recompute', inputOf('72-jpeg-footer-crc-mismatch-sidecar')], corrupted.io)).toBe(1)
    expect(JSON.parse(corrupted.out().trim()).outcome).toBe('corrupted_proof')
  })

  it('says what it cannot check rather than passing over it', async () => {
    // No `--tsa-root`, on a file carrying a timestamp: the honest answer is
    // that the evidence could not be read, not that the file has no time.
    const timestamped = fileVectors.find((v) => v.name.startsWith('59-'))
    if (!timestamped) return
    const { io, out } = capture()
    await run(['--json', '--no-recompute', inputOf(timestamped.name)], io)
    expect(JSON.parse(out().trim()).labels).toContain('trusted time not evaluated')
  })

  it('renders a verdict a person can read, naming what is missing', async () => {
    const { io, out } = capture()
    await run(['--no-recompute', inputOf('01-jpeg-sealed')], io)
    const text = out()

    expect(text).toContain('outcome   authentic')
    expect(text).toContain('missing or worth knowing')
    // The point of the renderer: every label is explained, because a reader
    // who is not told which evidence is absent assumes it was all there.
    expect(text).toContain('nobody can confirm this signing key was registered')
    expect(text).toContain('the device\'s own clock — a claim')
  })

  it('says what the platform reported about the device, in words', async () => {
    const { io, out } = capture()
    // A `failed` integrity verdict on an otherwise authentic file: the file is
    // real *and* the platform said the device was compromised. Showing only
    // the outcome would let a reader take no news for good news.
    await run([...trustArgs(), '--no-recompute', '--at', '2025-09-09T12:00:00.000Z',
      inputOf('65-jpeg-integrity-failed')], io)
    const text = out()

    expect(text).toContain('outcome   authentic')
    expect(text).toContain('this device as failing its integrity checks')
  })

  it('names the position level in the registry\'s terms, never the operator\'s', async () => {
    // §7.1: a corroborated position is the registry attesting what an operator
    // answered about the SIM's cell, to a radius; a contradicted one is shown
    // on an authentic file, because the position level is not the verdict.
    const corroborated = capture()
    await run([...trustArgs(), '--no-recompute', '--at', '2025-09-09T12:00:00.000Z', inputOf('75-jpeg-location-corroborated')], corroborated.io)
    expect(corroborated.out()).toContain('position  corroborated — the registry attests that the operator confirmed the zone, radius 2000 m')
    expect(corroborated.out()).toContain('45.464664, 9.188540')
    expect(corroborated.out()).not.toMatch(/verified by the operator|guaranteed/)

    const contradicted = capture()
    await run([...trustArgs(), '--no-recompute', '--at', '2025-09-09T12:00:00.000Z', inputOf('79-jpeg-location-contradicted')], contradicted.io)
    expect(contradicted.out()).toContain('outcome   authentic')
    expect(contradicted.out()).toContain('position  declared — ')
    expect(contradicted.out()).toContain('location contradicted: the operator')

    // Every §7.1 label the corpus emits is explained, like every other label.
    const text = capture()
    await run([...trustArgs(), '--no-recompute', inputOf('81-jpeg-location-claimed-authenticated')], text.io)
    expect(text.out()).toContain('location claimed above evidence: the device claims')
    expect(text.out()).toContain('location evidence not evaluated: the core carries')
  })

  it('refuses nonsense with a usage code and the usage text', async () => {
    for (const args of [['--nope', 'x'], [], ['--log', 'no-colon', 'x'], ['--at', 'not-a-date', 'x']]) {
      const { io, err } = capture()
      expect(await run(args, io)).toBe(64)
      expect(err()).toContain('vcap-verify')
    }
  })

  it('--help is not an error', async () => {
    const { io, out } = capture()
    expect(await run(['--help'], io)).toBe(0)
    expect(out()).toContain('Exit codes')
  })
})

/**
 * Spec §8, "A declared watermark that does not come back". This tool contacts
 * nothing and runs no model, so the only source of a detection is the caller
 * and `--watermark` is a file. Without it the answer is the one this CLI has
 * always given for a declared watermark: *watermark not evaluated*.
 */
describe('--watermark', () => {
  const evidenceFile = (body: unknown): string => {
    const path = join(mkdtempSync(join(tmpdir(), 'vcap-cli-')), 'watermark.json')
    writeFileSync(path, JSON.stringify(body))
    return path
  }
  const captureIdOf = (name: string): string => {
    const proof = JSON.parse(readFileSync(join(VECTORS, name, 'proof.json'), 'utf8')) as { capture_id: string }
    return Buffer.from(proof.capture_id, 'base64url').toString('hex')
  }

  it('without it, a declared watermark is *watermark not evaluated* — unchanged', async () => {
    const { io, out } = capture()
    expect(await run(['--json', '--no-recompute', inputOf('01-jpeg-sealed')], io)).toBe(0)
    const verdict = JSON.parse(out().trim())

    expect(verdict.labels).toContain('watermark not evaluated')
    expect(verdict.watermark).toBeUndefined()
  })

  it('*watermark matched* when the file names the declared capture id (§8)', async () => {
    const { io, out } = capture()
    const path = evidenceFile({ layout: 'photo-bch-v3', decoded: captureIdOf('01-jpeg-sealed'), corrected_bits: 2, model_version: 'videoseal-y256b-3' })
    expect(await run(['--json', '--no-recompute', '--watermark', path, inputOf('01-jpeg-sealed')], io)).toBe(0)
    const verdict = JSON.parse(out().trim())

    expect(verdict.labels).toContain('watermark matched')
    expect(verdict.watermark.result).toBe('matched')
  })

  it('a payload that decodes to another id is red, and the exit code says the file does not verify (§8)', async () => {
    const { io, out } = capture()
    const path = evidenceFile({ layout: 'photo-bch-v3', decoded: '0f1e2d3c4b5a69788796a5b4c3d2e1f0' })
    expect(await run(['--json', '--no-recompute', '--watermark', path, inputOf('01-jpeg-sealed')], io)).toBe(1)

    expect(JSON.parse(out().trim()).outcome).toBe('tampered')
  })

  it('refuses to spread one detection over several files', async () => {
    const { io, err } = capture()
    const path = evidenceFile({ decoded: null })
    expect(await run(['--watermark', path, inputOf('01-jpeg-sealed'), inputOf('02-jpeg-c2pa-added-after-sealing')], io)).toBe(64)

    expect(err()).toContain('--watermark takes a single file')
  })

  it('says so when the evidence file is not readable JSON', async () => {
    const { io, err } = capture()
    expect(await run(['--watermark', join(VECTORS, 'nope.json'), inputOf('01-jpeg-sealed')], io)).toBe(64)

    expect(err()).toContain('not readable JSON')
  })
})
