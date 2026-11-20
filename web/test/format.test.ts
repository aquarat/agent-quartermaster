import { describe, expect, test } from "bun:test";
import { ago, countdown, duration, isPlainName, ttlChoices, visibleText } from "../src/format";

describe("format", () => {
  test("duration", () => {
    expect(duration(900)).toBe("15 min");
    expect(duration(1800)).toBe("30 min");
    expect(duration(3600)).toBe("1 hour");
    expect(duration(5400)).toBe("1 h 30 min");
    expect(duration(28800)).toBe("8 hours");
    expect(duration(45)).toBe("45 s");
  });

  test("countdown and ago", () => {
    const now = 1_000_000_000_000;
    expect(countdown(now + 245_000, now)).toBe("4:05");
    expect(countdown(now - 1, now)).toBe("expired");
    expect(countdown(now + 2 * 3600_000, now)).toBe("2 hours");
    expect(ago(now - 12_000, now)).toBe("12 s ago");
    expect(ago(now - 5 * 60_000, now)).toBe("5 min ago");
  });

  test("ttlChoices caps at ttl_max and defaults to the clamped request", () => {
    expect(ttlChoices(1800, 28800)).toEqual({ options: [900, 1800, 3600, 14400, 28800], def: 1800 });
    expect(ttlChoices(28800, 3600)).toEqual({ options: [900, 1800, 3600], def: 3600 });
    expect(ttlChoices(2700, 28800)).toEqual({ options: [900, 1800, 2700, 3600, 14400, 28800], def: 2700 });
    expect(ttlChoices(600, 600)).toEqual({ options: [600], def: 600 });
  });

  test("visibleText exposes bidi overrides, zero-width and control characters", () => {
    const rlo = String.fromCharCode(0x202e);
    const zwsp = String.fromCharCode(0x200b);
    const bom = String.fromCharCode(0xfeff);
    const out = visibleText(`a${rlo}b${zwsp}c${bom}d` + String.fromCharCode(7));
    expect(out).toBe("a⟨U+202E⟩b⟨U+200B⟩c⟨U+FEFF⟩d⟨U+0007⟩");
    expect(visibleText("line1\nline2\ttab")).toBe("line1\nline2\ttab");
    expect(visibleText("<img src=x onerror=alert(1)>")).toBe("<img src=x onerror=alert(1)>");
    expect(visibleText(undefined)).toBe("");
  });

  test("visibleText also covers astral tag characters, variation selectors and mark runs", () => {
    const tagA = String.fromCodePoint(0xe0041);
    const vs17 = String.fromCodePoint(0xe0100);
    expect(visibleText("x" + tagA + "y")).toBe("x⟨U+E0041⟩y");
    expect(visibleText("x" + vs17)).toBe("x⟨U+E0100⟩");
    const mark = String.fromCharCode(0x301);
    expect(visibleText("e" + mark.repeat(30))).toBe("e" + mark + mark + "⟨…⟩");
    expect(visibleText("café")).toBe("café");
  });

  test("isPlainName", () => {
    expect(isPlainName("gw-host-2")).toBe(true);
    expect(isPlainName("alice")).toBe(true);
    expect(isPlainName("b" + String.fromCharCode(0x430) + "ckup")).toBe(false);
    expect(isPlainName("a b")).toBe(false);
    expect(isPlainName("")).toBe(false);
  });
});

