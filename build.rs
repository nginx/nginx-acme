use std::env;

/// Buildscript for an nginx module.
///
/// Due to the limitations of cargo[1], this buildscript _requires_ adding `nginx-sys` to the
/// direct dependencies of your crate.
///
/// [1]: https://github.com/rust-lang/cargo/issues/3544
fn main() {
    detect_nginx_features();
    detect_libssl_features();

    // Generate required compiler flags
    if cfg!(target_os = "macos") {
        // https://stackoverflow.com/questions/28124221/error-linking-with-cc-failed-exit-code-1
        println!("cargo::rustc-link-arg=-undefined");
        println!("cargo::rustc-link-arg=dynamic_lookup");
    }
}

/// Generates `ngx_os`, `ngx_feature` and nginx version cfg values.
fn detect_nginx_features() {
    // Specify acceptable values for `ngx_feature`
    println!("cargo::rerun-if-env-changed=DEP_NGINX_FEATURES_CHECK");
    println!(
        "cargo::rustc-check-cfg=cfg(ngx_feature, values({}))",
        env::var("DEP_NGINX_FEATURES_CHECK").unwrap_or("any()".to_string())
    );
    // Read feature flags detected by nginx-sys and pass to the compiler.
    println!("cargo::rerun-if-env-changed=DEP_NGINX_FEATURES");
    if let Ok(features) = env::var("DEP_NGINX_FEATURES") {
        for feature in features.split(',').map(str::trim) {
            println!("cargo::rustc-cfg=ngx_feature=\"{feature}\"");
        }
    }

    // Specify acceptable values for `ngx_os`
    println!("cargo::rerun-if-env-changed=DEP_NGINX_OS_CHECK");
    println!(
        "cargo::rustc-check-cfg=cfg(ngx_os, values({}))",
        env::var("DEP_NGINX_OS_CHECK").unwrap_or("any()".to_string())
    );
    // Read operating system detected by nginx-sys and pass to the compiler.
    println!("cargo::rerun-if-env-changed=DEP_NGINX_OS");
    if let Ok(os) = env::var("DEP_NGINX_OS") {
        println!("cargo::rustc-cfg=ngx_os=\"{os}\"");
    }

    // Generate cfg values for version checks

    println!("cargo::rustc-check-cfg=cfg(ngx_ssl_cache)");
    println!("cargo::rerun-if-env-changed=DEP_NGINX_VERSION_NUMBER");
    if let Ok(version) = env::var("DEP_NGINX_VERSION_NUMBER") {
        let version: u64 = version.parse().unwrap();

        if version >= 1_027_002 {
            println!("cargo::rustc-cfg=ngx_ssl_cache");
        }
    }
}

/// Detects libssl implementation and version.
fn detect_libssl_features() {
    // OpenSSL
    let openssl_features = ["awslc", "boringssl", "libressl", "openssl", "openssl111"];
    let openssl_version = env::var("DEP_OPENSSL_VERSION_NUMBER").unwrap_or_default();
    let openssl_version = u64::from_str_radix(&openssl_version, 16).unwrap_or(0);

    println!(
        "cargo::rustc-check-cfg=cfg(openssl, values(\"{}\"))",
        openssl_features.join("\",\"")
    );

    #[allow(clippy::unusual_byte_groupings)]
    let openssl = if env::var("DEP_OPENSSL_AWSLC").is_ok() {
        "awslc"
    } else if env::var("DEP_OPENSSL_BORINGSSL").is_ok() {
        "boringssl"
    } else if env::var("DEP_OPENSSL_LIBRESSL").is_ok() {
        "libressl"
    } else {
        if openssl_version >= 0x01_01_01_00_0 {
            println!("cargo::rustc-cfg=openssl=\"openssl111\"");
        }

        "openssl"
    };

    println!("cargo::rustc-cfg=openssl=\"{openssl}\"");
}
