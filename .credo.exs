%{
  configs: [
    %{
      name: "default",
      files: %{
        included: ["lib/", "test/", "bench/"],
        excluded: [~r"/_build/", ~r"/deps/"]
      },
      plugins: [],
      requires: [],
      strict: true,
      parse_timeout: 5000,
      color: true,
      # ExSlop: detects low-quality, generated-looking code
      checks: [] ++ Enum.map(ExSlop.recommended_checks(), &{&1, []})
    }
  ]
}
