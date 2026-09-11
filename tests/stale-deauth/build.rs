use std::{env, fs, path::Path};

use quote::{ToTokens, quote};
use syn::{ImplItem, Item};

fn main() {
    let root = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../..").canonicalize().unwrap();
    let runner = root.join("foa_sta/src/runner.rs");
    let router = root.join("foa/src/util/rx_router.rs");
    let sta_router = root.join("foa_sta/src/rx_router.rs");
    let state = root.join("foa_sta/src/connection_state.rs");
    let probe = root.join("foa_sta/src/handshake_probe.rs");
    for path in [&runner, &router, &sta_router, &state, &probe] {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    let parsed = syn::parse_file(&fs::read_to_string(runner).unwrap()).unwrap();
    let mut handlers = quote! {};
    for name in ["handle_deauth", "handle_bg_rx"] {
        let methods: Vec<_> = parsed.items.iter().filter_map(|item| match item {
            Item::Impl(item) if matches!(&*item.self_ty, syn::Type::Path(path)
                if path.path.segments.last().unwrap().ident == "ConnectionRunner") => Some(item),
            _ => None,
        }).flat_map(|item| item.items.iter()).filter_map(|item| match item {
            ImplItem::Fn(item) if item.sig.ident == name => Some(item),
            _ => None,
        }).collect();
        assert_eq!(methods.len(), 1, "missing/ambiguous production handler {name}");
        methods[0].to_tokens(&mut handlers);
    }
    let events: Vec<_> = parsed.items.iter().filter_map(|item| match item {
        Item::Enum(item) if item.ident == "ConnectionRxEvent" => Some(item),
        _ => None,
    }).collect();
    assert_eq!(events.len(), 1);
    let event = events[0];
    let router = router.to_str().unwrap();
    let sta_router = sta_router.to_str().unwrap();
    let state = state.to_str().unwrap();
    let probe = probe.to_str().unwrap();
    let output = quote! {
        pub mod util { #[path = #router] pub mod rx_router; }
        #[path = #sta_router] mod rx_router;
        #[path = #state] mod connection_state;
        #[path = #probe] mod handshake_probe;
        #event
        impl ConnectionRunner { #handlers }
    };
    fs::write(Path::new(&env::var("OUT_DIR").unwrap()).join("production.rs"), output.to_string()).unwrap();
}
