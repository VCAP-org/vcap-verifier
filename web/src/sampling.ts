/**
 * The clip sampling policy: how many frames a verifier reads, and how it
 * chooses them.
 *
 * It sits in its own module because two surfaces need it and only one of them
 * may touch the detector. `detector-runtime.ts` samples by it; `render.ts`
 * explains a refusal by it and is in the page bundle, which must never import
 * the runtime — the engine alone is larger than everything else shipped. Both
 * used to carry their own `8`, and a number in two files with one measurement
 * behind it is a number that drifts. Exported so a test can pin it, here and
 * in the surfaces that vendor these sources.
 *
 * **Eight is what the measurements ask for, not a round number.**
 * `vcap-ml/reports/frames-to-recover.md` finds every chain that recovers at
 * all already recovering from the **first** frame — which used to read as
 * "eight is margin". That was a statement about what the code corrects, not
 * about what a decoder may report, and the 0.85 floor separates the two. On
 * `detector_int8`, the only build published for browsers, the hardest chain
 * that survives at all — crf 36 at 640 px — costs **39 flipped bits from a
 * single frame: agreement 0.848, under the floor**. A one-frame page would
 * answer *watermark not recovered* on a clip whose id it had in fact decoded.
 * Four frames clear it (36 flips / 0.859), eight settle it (34 / 0.867), and
 * eight is where the measurable gain stops: past it, more frames change no
 * outcome and cost a model run each
 * (`vcap-spec/spec/watermark-robustness-1.0.md`, *How many frames a verifier
 * has to read*).
 *
 * Both figures are reported in the evidence because both are settable: two
 * answers taken under different policies are not comparable.
 */
export const VIDEO_FRAMES = 8

/**
 * Evenly spaced across the clip rather than the first N. The two policies give
 * the same recovered/not-recovered outcome on every chain measured, differing
 * by one or two bit errors; `uniform` does not depend on where in the clip the
 * encoder happened to spend its bits, which is a property that will only start
 * to matter once a corpus with real motion exists.
 */
export const SAMPLING_STRATEGY = 'uniform'
