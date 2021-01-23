module.exports = {
  env: {
    cjs: {
      presets: [
        ['@babel/preset-env', { targets: { node: '10' }, modules: 'commonjs' }]
      ],
      plugins: ['@babel/plugin-transform-destructuring']
    },
    mjs: {
      presets: [
        [
          '@babel/preset-env',
          { targets: { node: '10', esmodules: true }, modules: false }
        ]
      ]
    }
  }
}
