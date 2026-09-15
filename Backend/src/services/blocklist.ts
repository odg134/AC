import { readFileSync } from "fs";
import { join } from "path";

// Curated PE TimeDateStamps (UNIX seconds) for high-priority vulnerable drivers.
// Each entry is a uint32 embedded in the PE COFF header of the known-bad binary.
const CORE_TIMESTAMPS: number[] = [
    // capcom.sys
    0x57F29B57,
    // RTCore64.sys (MSI Afterburner / EVGA Precision)
    0x5C988700, 0x54720B8E,
    // gdrv.sys (GIGABYTE)
    0x5C88427C,
    // mhyprot2.sys (Genshin Impact kernel driver)
    0x5F76B656,
    // mhyprot3.sys
    0x62DDD3A6,
    // WinRing0 variants
    0x5EF07EFD, 0x4547CF6F, 0x45F98E25,
    // MsIo.sys
    0x5B9B0C55,
    // IQVM64.sys
    0x4A1FE540,
    // AsrDrv10x.sys (ASRock)
    0x5A0E7B4E,
    // PhyDMACC.sys
    0x5F5F78F3,
    // Novac NTIOLib_x64.sys
    0x4C1D36C5,
    // piddrv / fiddrv (Futuremark)
    0x4EC659EF, 0x46BEAAC5,
    // kbdcap64.sys
    0x5AAAF1B4,
    // LgDCatcher.sys (Lenovo)
    0x5D2C4B68,
    // BEDaisy.sys (BattlEye)
    0x5CBBA9EC,
    // BlackBoneDrv10.sys
    0x596EDAB2,
    // GLCKIO2.sys
    0x5DADF863,
    // HwRwDrv.sys
    0x5DAAA0CA,
    // netfilterdrv.sys (NetFilter SDK)
    0x5FA8AE73,
    // superbmc.sys
    0x4D58B75F,
    // Proxy64.sys / WYProxy64.sys
    0x5AB97FAD, 0x57F5FE09,
];

// Date formats found in loldrivers JSON Date field:
//   "10:20 AM 10/13/2006"   → h:mm AM/PM M/D/YYYY
//   "2026-02-04 12:24:39"   → YYYY-MM-DD HH:mm:ss
//   "2012-07-04"            → YYYY-MM-DD
// All are PE COFF TimeDateStamps rendered as UTC strings.
function parseLoldriversDate(s: string): number | null {
    s = s.trim();
    if (!s) return null;

    // ISO-like: "2026-02-04 12:24:39" or "2012-07-04"
    const iso = /^(\d{4})-(\d{2})-(\d{2})(?:\s+(\d{2}):(\d{2}):(\d{2}))?$/.exec(s);
    if (iso) {
        const [, yr, mo, dy, hh = "0", mm = "0", ss = "0"] = iso;
        const d = Date.UTC(+yr, +mo - 1, +dy, +hh, +mm, +ss);
        return isNaN(d) ? null : Math.floor(d / 1000);
    }

    // US 12-hour: "10:20 AM 10/13/2006"
    const us = /^(\d+):(\d+)\s*(AM|PM)\s+(\d+)\/(\d+)\/(\d+)$/i.exec(s);
    if (us) {
        let [, hStr, mStr, ampm, moStr, dyStr, yrStr] = us;
        let h = +hStr;
        if (ampm.toUpperCase() === "PM" && h < 12) h += 12;
        if (ampm.toUpperCase() === "AM" && h === 12) h = 0;
        const d = Date.UTC(+yrStr, +moStr - 1, +dyStr, h, +mStr, 0);
        return isNaN(d) ? null : Math.floor(d / 1000);
    }

    return null;
}

const badTimestamps = new Set<number>(CORE_TIMESTAMPS);

// Map timestamp → driver name (best-effort, for logging)
const timestampNames = new Map<number, string>();

function loadLoldriversTimestamps() {
    const jsonPath = join(import.meta.dir, "../../data/loldrivers.json");
    let raw: string;
    try {
        raw = readFileSync(jsonPath, "utf8");
    } catch {
        console.warn("blocklist: loldrivers.json not found, using core list only");
        return 0;
    }

    // Parse without ConvertFrom-Json so duplicate keys aren't an issue —
    // we extract Date and Tags with a regex instead of full JSON parsing.
    let added = 0;
    const entryRe = /\{[^{}]*"Tags"\s*:\s*\[([^\]]*)\][^{}]*"KnownVulnerableSamples"\s*:\s*\[([^\]]*)\]/gs;
    const dateRe  = /"Date"\s*:\s*"([^"]*)"/g;
    const tagRe   = /"([^"]+)"/g;

    // simpler: just scan all Date values globally
    const allDateMatches = [...raw.matchAll(/"Date"\s*:\s*"([^"]+)"/g)];
    const allTagBlocks   = [...raw.matchAll(/"Tags"\s*:\s*\[([^\]]*)\]/g)];

    // Build a flat list of (tag, dates[]) per driver block would require
    // full JSON parsing. Since Date fields are sparse (31/total), just add
    // all non-empty Dates to the set with a "unknown" label.
    for (const m of allDateMatches) {
        const ts = parseLoldriversDate(m[1]);
        if (ts !== null && ts > 0) {
            badTimestamps.add(ts);
            if (!timestampNames.has(ts))
                timestampNames.set(ts, "loldrivers");
            added++;
        }
    }

    return added;
}

const lolAdded = loadLoldriversTimestamps();
console.log(`blocklist: ${CORE_TIMESTAMPS.length} core + ${lolAdded} loldrivers timestamps = ${badTimestamps.size} total`);

export function isBlocklistedTimestamp(ts: number): boolean {
    return badTimestamps.has(ts);
}

export function checkDrivers(
    drivers: { timeDateStamp: number; isUnloaded: boolean }[]
): { timeDateStamp: number; isUnloaded: boolean } | null {
    for (const d of drivers) {
        if (d.timeDateStamp && isBlocklistedTimestamp(d.timeDateStamp))
            return d;
    }
    return null;
}
