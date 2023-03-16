module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  moduleNameMapper: {
    '^jose/(.*)$': '<rootDir>/node_modules/jose/dist/node/cjs/$1',
  },
  rootDir: '.',
  roots: ['<rootDir>/lib/', '<rootDir>/tests/'],
  testMatch: ['**/?(*.)+(spec|test).+(ts|tsx|js)'],
  transform: {
    '^.+\\.(ts|tsx)?$': 'ts-jest',
  },
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json'],
  coverageDirectory: './coverage/',
  collectCoverageFrom: [
    'lib/**/*.{ts,tsx}',
    '!lib/schemas/**',
    '!lib/**/*.d.ts',
    '!**/node_modules/**',
    '!jest.config.js',
    '!generator/**',
    '!index.ts',
  ],
  collectCoverage: true,
  reporters: ['default', ['jest-junit', { outputDirectory: './coverage' }]],
};
