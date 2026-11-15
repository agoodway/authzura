defmodule Authzura.DocsTest do
  use ExUnit.Case, async: true

  @guide "docs/guides/compatibility.md"

  test "README links the compatibility guide" do
    assert File.read!("README.md") =~ @guide
  end

  test "the guide states the targets, the verdict rules and known gaps" do
    guide = File.read!(@guide)

    for text <- ["1.25×", "1 + L", "1.5×", "15 %", "reviewed divergence", "Known gaps"] do
      assert guide =~ text
    end
  end

  test "the guide is at most 100 lines" do
    assert @guide |> File.read!() |> String.split("\n") |> length() <= 101
  end

  test "usage-rules.md names only public functions that exist and ships in the package" do
    rules = File.read!("usage-rules.md")
    refs = Regex.scan(~r/`(Authzura(?:\.[A-Z][A-Za-z]*)*)\.([a-z_!?]+)\/(\d)`/, rules)

    assert Enum.count(refs) >= 10

    for [_ref, module, fun, arity] <- refs do
      module = Module.concat([module])
      assert Code.ensure_loaded?(module), inspect(module)

      assert function_exported?(module, String.to_atom(fun), String.to_integer(arity)),
             "#{inspect(module)}.#{fun}/#{arity}"
    end

    assert "usage-rules.md" in Mix.Project.config()[:package][:files]
  end

  test "no published doc or bench file names a local path" do
    project = Mix.Project.config()
    markdown = for file <- project[:package][:files], String.ends_with?(file, ".md"), do: file

    files =
      (project[:docs][:extras] ++ markdown ++ Path.wildcard("bench/**/*.{md,json}"))
      |> Enum.uniq()

    assert "docs/guides/security.md" in files and "usage-rules.md" in files

    for file <- files do
      refute File.read!(file) =~ ~r{/Users/|/home/|/private/tmp/}, file
    end
  end
end
