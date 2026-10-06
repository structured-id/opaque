// The IndexedDB store in a real browser: entries survive reopening the
// database (a later visit), touch moves the last use, delete removes.
import { describe, it, expect } from "vitest";
import { IndexedDbKeyStore, openKeyStore } from "../src/zkpp/key-store.js";

describe("IndexedDB key store", () => {
  it("keeps entries across opens and tracks their use", async () => {
    const a = await IndexedDbKeyStore.open();
    await a.delete("t:1");
    expect(await a.get("t:1")).toBeNull();
    const bytes = Uint8Array.from({ length: 300000 }, (_, i) => i & 0xff);
    await a.put("t:1", bytes);

    const b = await IndexedDbKeyStore.open();
    expect(await b.get("t:1")).toEqual(bytes);
    const before = (await b.list()).find((e) => e.name === "t:1")!.usedAt;
    await new Promise((r) => setTimeout(r, 5));
    await b.touch("t:1");
    const after = (await b.list()).find((e) => e.name === "t:1")!.usedAt;
    expect(after).toBeGreaterThan(before);
    await b.delete("t:1");
    expect(await b.get("t:1")).toBeNull();
  });

  it("is what the client opens in a browser", async () => {
    expect(await openKeyStore()).toBeInstanceOf(IndexedDbKeyStore);
  });
});
