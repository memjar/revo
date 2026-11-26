import {
  detectDecoys,
  type CounterReReport,
} from "../../skill-src/counter-re/index.js";
import {
  scrubSecrets,
  isClean,
  type ScrubReport,
} from "../../skill-src/secrets-scrub/index.js";
import {
  generateProfile,
  rotateIdentity,
  stripToolFingerprints,
  obfuscateTimestamps,
  jitteredDelay,
  type FingerprintProfile,
} from "../../skill-src/fingerprint-evade/index.js";

export interface CounterDetectionKit {
  readonly counterRe: {
    detectDecoys: typeof detectDecoys;
  };
  readonly secretsScrub: {
    scrubSecrets: typeof scrubSecrets;
    isClean: typeof isClean;
  };
  readonly fingerprintEvade: {
    generateProfile: typeof generateProfile;
    rotateIdentity: typeof rotateIdentity;
    stripToolFingerprints: typeof stripToolFingerprints;
    obfuscateTimestamps: typeof obfuscateTimestamps;
    jitteredDelay: typeof jitteredDelay;
  };
}

export const createCounterDetectionKit = (): CounterDetectionKit => ({
  counterRe: { detectDecoys },
  secretsScrub: { scrubSecrets, isClean },
  fingerprintEvade: {
    generateProfile,
    rotateIdentity,
    stripToolFingerprints,
    obfuscateTimestamps,
    jitteredDelay,
  },
});

export type { CounterReReport, ScrubReport, FingerprintProfile };
