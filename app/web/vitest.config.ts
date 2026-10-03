import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/unit/**/*.test.ts", "test/unit/**/*.test.mjs"],
    environment: "jsdom",
  },
});
