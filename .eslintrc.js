module.exports = {
  extends: ['airbnb-base'],
  rules: {
    'class-methods-use-this': 'off',
    'comma-dangle': ['error', 'never'],
    'no-console': 'off',
    'no-mixed-operators': 'off',
    'no-param-reassign': ['error', { props: false }],
    'no-restricted-syntax': 'off',
    'no-shadow': 'off',
    'no-template-curly-in-string': 'off',
    semi: ['error', 'never'],
    'import/prefer-default-export': 'off'
  }
}
