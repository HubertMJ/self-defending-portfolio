import { describe, expect, it } from "vitest";

// Polish time with its CET/CEST label (ADR 0035, amendment 2026-10-06). The host's zone is set to one
// that is never Warsaw's before the helpers load: a formatter that fell back to the host's zone, or to
// UTC, writes other hours and other labels.
process.env.TZ = "America/Los_Angeles";
const { TIME_ZONE, plClock, plTime, timeEl, when } = await import("../../src/lib/dom");

describe("Polish time across the DST switches", () => {
  it("the host's zone is not Warsaw's, and the helpers name Warsaw", () => {
    expect(new Date("2026-10-24T10:00:00Z").getHours()).toBe(3);
    expect(TIME_ZONE).toBe("Europe/Warsaw");
  });

  it.each([
    ["2026-10-24T10:00:00Z", "2026-10-24 12:00:00 CEST"],
    ["2026-10-25T00:30:00Z", "2026-10-25 02:30:00 CEST"],
    // The repeated hour of the autumn switch: the same wall clock, told apart by the label.
    ["2026-10-25T01:30:00Z", "2026-10-25 02:30:00 CET"],
    ["2026-10-26T10:00:00Z", "2026-10-26 11:00:00 CET"],
    ["2027-03-28T00:59:59Z", "2027-03-28 01:59:59 CET"],
    ["2027-03-28T01:00:00Z", "2027-03-28 03:00:00 CEST"],
  ])("%s reads %s", (iso, text) => {
    expect(plTime(iso)).toBe(text);
    expect(plTime(Date.parse(iso))).toBe(text);
  });

  it("a 24-hour clock with ms when asked, midnight as 00", () => {
    expect(plTime("2026-10-24T22:00:00.007Z", { ms: true })).toBe("2026-10-25 00:00:00.007 CEST");
    expect(plTime("2026-12-31T23:59:59.999Z", { ms: true })).toBe("2027-01-01 00:59:59.999 CET");
    expect(plTime("2026-10-24T13:05:09Z")).toBe("2026-10-24 15:05:09 CEST");
  });

  it("drops the date only on the same Polish day", () => {
    const t = Date.parse("2026-10-24T22:30:00Z"); // 00:30 CEST on the 25th
    expect(plClock(t, Date.parse("2026-10-25T09:00:00Z"))).toBe("00:30:00 CEST");
    // The day is Warsaw's: 23:00 UTC on the 24th is the 25th there, 21:59 UTC still the 24th.
    expect(plClock(t, Date.parse("2026-10-24T23:00:00Z"))).toBe("00:30:00 CEST");
    expect(plClock(t, Date.parse("2026-10-24T21:59:00Z"))).toBe("2026-10-25 00:30:00 CEST");
    expect(plClock("2026-10-25T01:30:00.250Z", Date.parse("2026-10-25T12:00:00Z"), { ms: true })).toBe("02:30:00.250 CET");
  });

  it("when() reads Polish time then how long ago; the <time>'s datetime stays the UTC instant", () => {
    const now = Date.parse("2026-10-26T10:00:00Z");
    expect(when("2026-10-26T04:00:00Z", now)).toBe("05:00:00 CET (6 hours ago)");
    const el = timeEl("2026-10-25T01:30:00+00:00");
    expect(el.getAttribute("datetime")).toBe("2026-10-25T01:30:00.000Z");
    expect(el.textContent).toBe("2026-10-25 02:30:00 CET");
  });

  it("an unparseable value comes back as is", () => {
    expect(plTime("not a time")).toBe("not a time");
    expect(plClock(Number.NaN)).toBe("–");
  });
});
