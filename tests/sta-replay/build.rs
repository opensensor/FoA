use std::{env, fs, path::Path};

use quote::{ToTokens, quote};
use syn::{ImplItem, Item};

fn self_type(item: &syn::ItemImpl, name: &str) -> bool {
    matches!(&*item.self_ty, syn::Type::Path(path)
        if path.qself.is_none() && path.path.segments.len() == 1
            && path.path.segments[0].ident == name)
}

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let root = Path::new(&manifest_dir).join("../..");
    let rsn_path = root.join("foa_sta/src/rsn.rs");
    let runner_path = root.join("foa_sta/src/runner.rs");
    for path in [&rsn_path, &runner_path] {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    let rsn = syn::parse_file(&fs::read_to_string(rsn_path).unwrap()).unwrap();
    let runner = syn::parse_file(&fs::read_to_string(runner_path).unwrap()).unwrap();
    let mut output = quote! {};
    for name in [
        "PMK_LENGTH",
        "PTK_LENGTH",
        "GTK_LENGTH",
        "WPA2_PSK_AKM",
        "TransientKeySecurityAssociation",
        "SecurityAssociations",
    ] {
        let matches: Vec<_> = rsn
            .items
            .iter()
            .filter(|item| match item {
                Item::Const(item) => item.ident == name,
                Item::Struct(item) => item.ident == name,
                _ => false,
            })
            .collect();
        assert_eq!(matches.len(), 1, "missing/ambiguous production item {name}");
        matches[0].to_tokens(&mut output);
    }
    let associations: Vec<_> = rsn
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(item) if self_type(item, "TransientKeySecurityAssociation") => Some(item),
            _ => None,
        })
        .collect();
    assert_eq!(associations.len(), 1);
    associations[0].to_tokens(&mut output);

    // Compile the actual replay-gate and data-routing methods. The radio and
    // final network-buffer sink are replaced; no second replay implementation.
    let routing: Vec<_> = runner
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(item) if self_type(item, "RoutingRunner") => Some(item),
            _ => None,
        })
        .collect();
    assert_eq!(routing.len(), 1);
    let mut methods = quote! {};
    for name in ["process_potentially_wrapped_payload", "handle_data_rx"] {
        let selected: Vec<_> = routing[0]
            .items
            .iter()
            .filter_map(|item| match item {
                ImplItem::Fn(method) if method.sig.ident == name => Some(method),
                _ => None,
            })
            .collect();
        assert_eq!(
            selected.len(),
            1,
            "missing/ambiguous production routing method {name}"
        );
        selected[0].to_tokens(&mut methods);
    }
    output.extend(quote! { impl RoutingRunner { #methods } });
    fs::write(
        Path::new(&env::var("OUT_DIR").unwrap()).join("production.rs"),
        output.to_string(),
    )
    .unwrap();
}
