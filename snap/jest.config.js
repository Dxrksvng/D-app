// @metamask/utils@12 (pulled in by snaps-utils) is ESM-only. Node 24 can require() it, but Jest 29 cannot,
// so ts-jest transpiles that package to CommonJS for tests only. The built Snap bundle is unaffected.
module.exports = {
  preset: '@metamask/snaps-jest',
  transform: {
    '^.+\\.(t|j)sx?$': ['ts-jest', { tsconfig: { allowJs: true, isolatedModules: true, module: 'CommonJS', jsx: 'react-jsx', jsxImportSource: '@metamask/snaps-sdk', esModuleInterop: true } }],
  },
  transformIgnorePatterns: ['/node_modules/(?!(@metamask|@noble|@scure)/)'],
  testTimeout: 60000,
};
