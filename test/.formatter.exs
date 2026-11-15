# The test suite's formatting: StreamData's `check all ... do` form. It is
# a test-only dependency, so `import_deps` cannot reach it in :dev.
[
  inputs: ["**/*.{ex,exs}"],
  locals_without_parens: [all: :*, check: 1, check: 2, property: 1, property: 2, property: 3]
]
