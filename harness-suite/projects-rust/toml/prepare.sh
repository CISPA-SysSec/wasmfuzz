set -e
git clone-rev.sh https://github.com/toml-rs/toml "$PROJECT/repo" 48ba237a70f56706342196624638b711c59bb04f
python3 - <<'PY'
from pathlib import Path
import tomlkit

repo = Path("/projects/toml/repo")

# Keep the fuzz harness out of the workspace so it can be built independently.
workspace_path = repo / "Cargo.toml"
workspace_doc = tomlkit.parse(workspace_path.read_text())
workspace = workspace_doc["workspace"]
workspace["exclude"] = ["crates/toml_edit_fuzz"]
workspace_path.write_text(tomlkit.dumps(workspace_doc))

# Make the fuzz harness self-contained after removing it from workspace.
fuzz_path = repo / "crates/toml_edit_fuzz/Cargo.toml"
fuzz_doc = tomlkit.parse(fuzz_path.read_text())
package = fuzz_doc["package"]
package["edition"] = "2021"
if "lints" in fuzz_doc:
    del fuzz_doc["lints"]
fuzz_text = tomlkit.dumps(fuzz_doc)
fuzz_text = fuzz_text.replace("edition.workspace = true", 'edition = "2021"')
fuzz_text = fuzz_text.replace("rust-version.workspace = true", 'rust-version = "1.85"')
fuzz_path.write_text(fuzz_text)
PY
