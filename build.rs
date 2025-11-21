use vergen::EmitBuilder;

fn main() {
    if let Err(err) = EmitBuilder::builder()
        .git_sha(true)
        .git_describe(true, true, None)
        .build_timestamp()
        .emit()
    {
        println!("cargo:warning=vergen failed: {err}");
    }
}
