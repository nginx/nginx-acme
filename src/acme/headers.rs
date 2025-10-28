// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::time::Duration;

use iri_string::types::UriReferenceStr;
use ngx::collections::Vec;

use crate::time::Time;

/// Represents an RFC8288 Link header value.
///
/// The `Link` header is used to indicate relationships between resources,
/// as defined in [RFC8288](https://datatracker.ietf.org/doc/html/rfc8288).
pub struct Link<'a> {
    /// The URI reference target of the link.
    pub target: &'a UriReferenceStr,
    /// The relationship types (the `rel` parameter) associated with the link.
    pub rel: Vec<&'a str>,
}

impl Link<'_> {
    pub fn is_rel(&self, rel: &str) -> bool {
        self.rel.iter().any(|x| x.eq_ignore_ascii_case(rel))
    }
}

/// An iterator over Link header values parsed from an RFC8288-compliant Link header string.
pub struct LinkIter<'a>(&'a str);

impl<'a> LinkIter<'a> {
    pub fn new(val: &'a http::header::HeaderValue) -> Result<Self, http::header::ToStrError> {
        val.to_str().map(Self)
    }
}

impl<'a> Iterator for LinkIter<'a> {
    type Item = Link<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Link       = [ ( "," / link-value ) *( OWS "," [ OWS link-value ] ) ]

        // link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )
        fn consume_link_value(p: &str) -> Option<(Link<'_>, &str)> {
            let p = p.trim_ascii_start().strip_prefix('<')?;

            let (target, mut p) = p.split_once('>')?;
            if target.is_empty() {
                return None;
            }
            let target = UriReferenceStr::new(target).ok()?;

            let mut rel = Vec::new();

            loop {
                p = p.trim_ascii_start();

                if p.is_empty() {
                    break;
                }

                if let Some(rest) = p.strip_prefix(',') {
                    p = rest;
                    break;
                }

                p = p.strip_prefix(';')?;

                let name;
                let value;
                (name, value, p) = consume_link_param(p)?;

                // 9.   Let relations_string be the second item of the first tuple
                //      of link_parameters whose first item matches the string "rel"
                //      or the empty string ("") if it is not present.
                // 10.  Split relations_string on RWS (removing it in the process)
                //      into a list of string relation_types.

                if rel.is_empty() && name.eq_ignore_ascii_case("rel") {
                    rel.extend(value.split_ascii_whitespace());
                }
            }

            Some((Link { target, rel }, p))
        }

        // link-param = token BWS [ "=" BWS ( token / quoted-string ) ]
        fn consume_link_param(p: &str) -> Option<(&str, &str, &str)> {
            let p = p.trim_ascii_start();

            let Some(end) = p.find(['=', ';', ',']) else {
                return Some((p, "", ""));
            };

            let (name, p) = p.split_at(end);

            let (value, p) = if let Some(mut p) = p.strip_prefix('=') {
                p = p.trim_ascii_start();

                if let Some(p) = p.strip_prefix('"') {
                    consume_quoted_string(p)?
                } else if let Some(end) = p.find([';', ',']) {
                    let (value, p) = p.split_at(end);
                    (value.trim_ascii_end(), p)
                } else {
                    (p.trim_ascii_end(), "")
                }
            } else {
                ("", p)
            };

            Some((name.trim_ascii_end(), value, p))
        }

        fn consume_quoted_string(p: &str) -> Option<(&str, &str)> {
            let mut escape = false;

            for (i, c) in p.char_indices() {
                if c == '\\' {
                    escape = !escape;
                } else if c == '"' && !escape {
                    let (head, tail) = p.split_at(i);
                    return Some((head, tail.strip_prefix('"')?));
                } else {
                    escape = false;
                }
            }

            Some((p, ""))
        }

        let link;

        self.0 = self.0.trim_ascii_start();
        while let Some(p) = self.0.strip_prefix(',') {
            self.0 = p.trim_ascii_start();
        }

        (link, self.0) = consume_link_value(self.0)?;

        Some(link)
    }
}

pub fn parse_link(val: &http::HeaderValue) -> Option<LinkIter<'_>> {
    LinkIter::new(val).ok()
}

pub fn parse_retry_after(val: &http::HeaderValue) -> Option<Duration> {
    let val = val.to_str().ok()?;

    // Retry-After: <http-date>
    if let Ok(time) = Time::parse(val) {
        return Some(time - Time::now());
    }

    // Retry-After: <delay-seconds>
    val.parse().map(Duration::from_secs).ok()
}

#[cfg(test)]
mod tests {

    #[test]
    fn parse_link() {
        type Expected<'a> = (&'a str, &'a [&'a str]);

        const LINKS: &[(&str, &[Expected])] = &[
            (
                // index
                "<https://example.com/acme/directory>;rel=\"index\"",
                &[("https://example.com/acme/directory", &["index"])],
            ),
            (
                // alternate quoted
                "<https://example.com/acme/cert/mAt3xBGaobw/1>; rel=\"alternate\"",
                &[(
                    "https://example.com/acme/cert/mAt3xBGaobw/1",
                    &["alternate"],
                )],
            ),
            (
                // alternate unquoted
                "<https://example.com/acme/cert/mAt3xBGaobw/1>; rel=alternate",
                &[(
                    "https://example.com/acme/cert/mAt3xBGaobw/1",
                    &["alternate"],
                )],
            ),
            (
                // no rel
                "<https://example.com/acme/directory>;",
                &[("https://example.com/acme/directory", &[])],
            ),
            (
                // rel splitting
                "<test>; rel=\"alternate index\"",
                &[("test", &["alternate", "index"])],
            ),
            (
                // multiple parameters
                "<test>; foo=bar; foobar; rel=\"alternate\"; rel=\"index\"",
                &[("test", &["alternate"])],
            ),
            (
                // spaces, commas and other parser sanity checks
                concat!(
                    " , <https://example.com/acme/directory> ;\t foo=\";,=<>\"; rel = \"index\"\t,  ,,, ",
                    " , <https://example.com/acme/directory> ;\t foo=\";,=<>\"; rel = \"index\"\t,  ,,, "
                ),
                &[
                    ("https://example.com/acme/directory", &["index"]),
                    ("https://example.com/acme/directory", &["index"])
                ],
            ),
            (
                "<https://example.com/acme/directory>;rel=\"index",
                &[("https://example.com/acme/directory", &["index"])],
            ),
            (
                r#"<https://example.com/acme/directory>;rel="index\""#,
                &[("https://example.com/acme/directory", &["index\\\""])],
            ),
            (
                // multiple link-values
                concat!(
                    "<https://example.com/acme/directory>;rel=\"index\",",
                    "<https://example.com/acme/cert/mAt3xBGaobw/1>;rel=alternate,",
                    "<https://example.com/acme/cert/mAt3xBGaobw/2>;rel=alternate"
                ),
                &[
                    ("https://example.com/acme/directory", &["index"]),
                    (
                        "https://example.com/acme/cert/mAt3xBGaobw/1",
                        &["alternate"],
                    ),
                    (
                        "https://example.com/acme/cert/mAt3xBGaobw/2",
                        &["alternate"],
                    ),
                ],
            ),
            (
                // title encoding
                concat!(
                    "</TheBook/chapter2>;",
                    "rel=\"previous\"; title*=UTF-8'de'letztes%20Kapitel,",
                    "</TheBook/chapter4>;",
                    "title*=UTF-8'de'n%c3%a4chstes%20Kapitel; rel=\"next\"",
                ),
                &[
                    ("/TheBook/chapter2", &["previous"]),
                    ("/TheBook/chapter4", &["next"]),
                ],
            ),
            // bad values
            ("<asdf", &[]),
            ("rel=alternate", &[]),
            ("<>; rel=alternate", &[]),
            ("<>, rel=alternate", &[]),
        ];

        for (val, expected) in LINKS {
            let val = http::HeaderValue::from_static(val);
            let mut links = super::parse_link(&val).expect("valid header encoding");

            for (uri, rel) in *expected {
                let link = links.next().expect("link-value");
                assert_eq!(link.target, *uri);
                assert_eq!(&link.rel, rel);
            }

            assert!(links.next().is_none());
        }
    }
}
