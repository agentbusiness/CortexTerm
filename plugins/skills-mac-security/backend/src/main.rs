//! `cc-skills-mac-security` executable: serve `skills@1` to the frame (category
//! `skills-mac-security`) from the folder's `data/skills`.

/// The plugin's id: its category is `skills-<ID>`, as plugin.toml says.
const ID: &str = "mac-security";
const NAME: &str = "Mac security";

fn main() {
    std::process::exit(cc_lang_kit::run_skills_plugin(ID, NAME, env!("CARGO_PKG_VERSION"), None));
}
