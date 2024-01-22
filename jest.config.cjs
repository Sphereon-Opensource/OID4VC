module.exports = {
    preset: "ts-jest",
    testEnvironment: "node",
    moduleNameMapper: {
        "^jose/(.*)$": "<rootDir>/node_modules/.pnpm/jose@4.15.4/node_modules/jose/dist/node/cjs/$1",
    },
    rootDir: ".",
    // roots: ["<rootDir>/src/", "<rootDir>/test/"],
    testMatch: ["**/?(*.)+(spec|test).+(ts|tsx|js)"],
    transform: {
        "^.+\\.(ts|tsx)?$": "ts-jest",
    },
    moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json"],
    coverageDirectory: "./coverage/",
    collectCoverageFrom: [
        "packages/**/src/**/*.ts",
        "packages/**/lib/**/*.ts",
        "!**/examples/**",
        "!packages/cli/**",
        "!**/types/**",
        "!**/dist/**",
        "!**/coverage/**",
        "!**/node_modules/**/__tests__/**",
        "!**/node_modules/**/*.test.ts",
        "!**/node_modules/**",
        "!**/packages/**/index.ts",
        "!**/src/schemas/**",
        "!**/src/**/*.d.ts",
        "!jest.config.cjs",
        "!**/generator/**",
        "!index.ts",

    ],
    collectCoverage: true,
    reporters: ["default", ["jest-junit", { outputDirectory: "./coverage" }]],
    "automock": false,
    "verbose": true
};
