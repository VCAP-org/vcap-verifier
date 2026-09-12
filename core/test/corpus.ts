import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { join } from 'node:path'

/**
 * The vcap-spec conformance corpus, located and *counted*.
 *
 * Every runner in this repository used to enumerate the vectors itself behind
 * a floor — `>= 84` here, `> 30` in the CLI. A floor is the wrong assertion:
 * it passes while the corpus shrinks, and it passes loudest in the case that
 * matters, an enumeration that found nothing at all. A suite that ran zero
 * vectors is the greenest build in any repository and the only one that proves
 * nothing, so `corpus()` throws rather than return an empty list, and every
 * runner pins its count against `MANIFEST.json`.
 *
 * Source of truth: the `spec` submodule. Fallback: the snapshot in
 * `core/vectors`, kept byte-equal by `vectors-sync.mjs`, so a checkout without
 * the submodule still runs the vectors — but never *no* vectors.
 */

const SUBMODULE = join(import.meta.dirname, '..', '..', 'spec', 'vectors')
const SNAPSHOT = join(import.meta.dirname, '..', 'vectors')

export interface Corpus {
  /** Where the vectors were read from. */
  dir: string
  /** `vectors/VERSION`: the corpus version a conformance claim names. */
  version: string
  /** SHA-256 of `MANIFEST.json` as committed: the exact bytes claimed. */
  manifestSha256: string
  /** `vector_count` from the manifest. */
  declaredCount: number
  /** The `NN-*` directory names present, sorted. */
  names: string[]
  /** Expected `kind` per vector name, from the manifest. */
  kinds: Record<string, string>
  /** How many vectors the manifest declares of each kind. */
  countOfKinds: (kinds: string[]) => number
}

export const corpus = (): Corpus => {
  const dir = existsSync(SUBMODULE) && readdirSync(SUBMODULE).length > 0 ? SUBMODULE : SNAPSHOT
  if (!existsSync(dir)) throw new Error(`[vcap] no conformance corpus at ${SUBMODULE} or ${SNAPSHOT}: run \`git submodule update --init\``)
  const names = readdirSync(dir).filter((d) => /^\d\d-/.test(d)).sort()
  if (names.length === 0) throw new Error(`[vcap] the corpus at ${dir} holds no vectors: a run of zero vectors is a failure, not a pass`)
  const manifestFile = join(dir, 'MANIFEST.json')
  const versionFile = join(dir, 'VERSION')
  if (!existsSync(manifestFile) || !existsSync(versionFile)) {
    throw new Error(`[vcap] the corpus at ${dir} carries no VERSION/MANIFEST.json: bump the spec submodule (a runner that cannot name a corpus version cannot claim conformance)`)
  }
  const manifestBytes = readFileSync(manifestFile)
  const manifest = JSON.parse(manifestBytes.toString('utf8')) as { vector_count: number, vectors: Array<{ name: string, kind: string }> }
  const kinds = Object.fromEntries(manifest.vectors.map((v) => [v.name, v.kind]))
  return {
    dir,
    version: readFileSync(versionFile, 'utf8').trim(),
    manifestSha256: createHash('sha256').update(manifestBytes).digest('hex'),
    declaredCount: manifest.vector_count,
    names,
    kinds,
    countOfKinds: (want) => manifest.vectors.filter((v) => want.includes(v.kind)).length
  }
}
