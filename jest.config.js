module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  moduleNameMapper: {
    "^jose/(.*)$": "<rootDir>/node_modules/jose/dist/node/cjs/$1",
  },
  rootDir: ".",
  roots: ["<rootDir>/src/", "<rootDir>/__tests__/"],
  testMatch: ["**/?(*.)+(spec|test).+(ts|tsx|js)"],
  transform: {
    "^.+\\.(ts|tsx)?$": "ts-jest",
  },
  moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json"],
  coverageDirectory: "./coverage/",
  collectCoverageFrom: [
    "src/**/*.{ts,tsx}",
    "!src/schemas/**",
    "!src/**/*.d.ts",
    "!**/node_modules/**",
    "!jest.config.cjs",
    "!generator/**",
    "!index.ts",

  ],
  collectCoverage: true,
  reporters: ["default", ["jest-junit", { outputDirectory: "./coverage" }]],
};
