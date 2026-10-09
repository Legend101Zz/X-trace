//! Framework-neutral route normalization (03a section 2, steps 1-5).
//!
//! The normalizer is pure: no IO, no clock, no allocation of handles. It turns
//! the route template a framework declares (`/users/:id`, `/users/{id:[0-9]+}`,
//! `/users/<int:id>`) into the identity form used for matching and
//! deduplication, and keeps the display form and parameter metadata that the
//! identity deliberately drops.
//!
//! Identity rules:
//!
//! 1. Framework escape syntax is decoded without decoding a literal encoded
//!    slash. Percent escapes of unreserved characters are decoded, every other
//!    escape keeps its bytes with upper-case hexadecimal digits (`%2f` becomes
//!    `%2F`). A backslash escape of a syntax character (`\:`) becomes the
//!    percent escape of that character, so the identity never contains a
//!    literal syntax character that a later pass could reread as a parameter.
//! 2. The route has one leading slash and no repeated separators.
//! 3. A trailing slash is removed (except for `/`); its presence is reported
//!    separately as `strict_slash`.
//! 4. Parameters (`:id`, `<id>`, `{id:[0-9]+}`) become `{id}`. The original
//!    name and constraint stay in [`RouteParam`].
//! 5. Parameter names do not take part in identity: `/users/{id}` and
//!    `/users/{userId}` have the same identity. [`NormalizedRoute::display`]
//!    keeps the name the declaring claim used.
//!
//! Catch-all parameters (`{*rest}`, `*rest`) become `{*}`; a bare `*` or `**`
//! segment stays literal. Both set [`NormalizedRoute::wildcard`] so static
//! analyzers can attach a limitation code. The same input vectors are shared
//! with the Java and Node analyzers through
//! `schema/fixtures/normalizer-vectors.json`.

use std::fmt;

use thiserror::Error;

/// Longest route (input or output) the normalizer accepts, in bytes.
pub const MAX_ROUTE_BYTES: usize = 1024;
/// Most parameters one route may declare.
pub const MAX_ROUTE_PARAMS: usize = 32;
/// Longest parameter name, in bytes.
pub const MAX_PARAM_NAME_BYTES: usize = 64;
/// Longest parameter constraint kept as metadata, in bytes.
pub const MAX_PARAM_CONSTRAINT_BYTES: usize = 256;

/// Framework whose route syntax the input uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RouteFramework {
    /// Spring MVC / WebFlux annotated controllers (`{id}`, `{id:regex}`, `{*rest}`).
    SpringMvc,
    /// JAX-RS `@Path` (`{id}`, `{id: regex}`).
    JaxRs,
    /// Express (`:id`, `:id(\\d+)`, `:id?`).
    Express,
    /// Fastify (`:id`, `*`).
    Fastify,
    /// Nest controllers (`:id`).
    Nest,
    /// Accepts every syntax; used for already normalized routes and vectors.
    Generic,
}

impl RouteFramework {
    /// Stable vocabulary string, also used in the shared vector file.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SpringMvc => "spring-mvc",
            Self::JaxRs => "jaxrs",
            Self::Express => "express",
            Self::Fastify => "fastify",
            Self::Nest => "nest",
            Self::Generic => "generic",
        }
    }

    /// Parses the stable vocabulary string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "spring-mvc" => Self::SpringMvc,
            "jaxrs" => Self::JaxRs,
            "express" => Self::Express,
            "fastify" => Self::Fastify,
            "nest" => Self::Nest,
            "generic" => Self::Generic,
            _ => return None,
        })
    }

    const fn colon_params(self) -> bool {
        matches!(self, Self::Express | Self::Fastify | Self::Nest | Self::Generic)
    }

    const fn splat_params(self) -> bool {
        matches!(self, Self::Express | Self::Fastify | Self::Nest)
    }

    const fn angle_params(self) -> bool {
        matches!(self, Self::Generic)
    }
}

/// One declared route parameter, in order of appearance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteParam {
    /// Name as declared (`userId`). Empty only for an unnamed catch-all.
    pub name: String,
    /// Regex or converter constraint as declared; metadata only.
    pub constraint: Option<String>,
    /// The declaration marks the parameter optional (`:id?`).
    pub optional: bool,
}

/// Normalized route: identity form plus the metadata identity drops.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedRoute {
    /// Identity template, parameters as `{id}`; feed this to `EndpointIdentity`.
    pub identity: String,
    /// Same shape with the declared parameter names (`/users/{userId}`).
    pub display: String,
    /// The declared route ended in a separator (a separate strict-slash claim).
    pub strict_slash: bool,
    /// A wildcard or catch-all segment makes the route a pattern, not one path.
    pub wildcard: bool,
    /// Declared parameters in order.
    pub params: Vec<RouteParam>,
}

/// Reason a template cannot be normalized. The codes are stable and are the
/// strings used by the shared vector file.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RouteNormalizationError {
    /// The route (input or output) is longer than [`MAX_ROUTE_BYTES`].
    #[error("route is longer than {MAX_ROUTE_BYTES} bytes")]
    TooLong,
    /// The route contains a control character.
    #[error("route contains a control character")]
    ControlCharacter,
    /// A query string or fragment marker appears outside a parameter.
    #[error("route contains a query or fragment marker")]
    QueryOrFragment,
    /// A parameter brace, bracket or group is not closed (or closed without opening).
    #[error("route has an unbalanced parameter delimiter")]
    UnbalancedParameter,
    /// A parameter name is empty, too long or uses characters outside the safe set.
    #[error("route has an invalid parameter name")]
    InvalidParameterName,
    /// More than [`MAX_ROUTE_PARAMS`] parameters.
    #[error("route declares more than {MAX_ROUTE_PARAMS} parameters")]
    TooManyParameters,
    /// A percent escape is not followed by two hexadecimal digits.
    #[error("route contains a malformed percent escape")]
    InvalidEscape,
}

impl RouteNormalizationError {
    /// Stable snake_case code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TooLong => "too_long",
            Self::ControlCharacter => "control_character",
            Self::QueryOrFragment => "query_or_fragment",
            Self::UnbalancedParameter => "unbalanced_parameter",
            Self::InvalidParameterName => "invalid_parameter_name",
            Self::TooManyParameters => "too_many_parameters",
            Self::InvalidEscape => "invalid_escape",
        }
    }
}

impl fmt::Display for RouteFramework {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Normalizes one route template.
///
/// An empty template is the root route `/`.
pub fn normalize_route(
    framework: RouteFramework,
    template: &str,
) -> Result<NormalizedRoute, RouteNormalizationError> {
    if template.len() > MAX_ROUTE_BYTES {
        return Err(RouteNormalizationError::TooLong);
    }
    Parser::new(framework, template).run()
}

/// Joins path parts (class prefix, mount path, method path, base path) and
/// normalizes the result. Empty parts are skipped. The strict-slash flag is
/// taken from the last non-empty part.
pub fn join_and_normalize(
    framework: RouteFramework,
    parts: &[&str],
) -> Result<NormalizedRoute, RouteNormalizationError> {
    let mut joined = String::new();
    for part in parts.iter().filter(|part| !part.is_empty()) {
        if !joined.is_empty() {
            joined.push('/');
        }
        joined.push_str(part);
        if joined.len() > MAX_ROUTE_BYTES {
            return Err(RouteNormalizationError::TooLong);
        }
    }
    normalize_route(framework, &joined)
}

#[derive(Default)]
struct Segment {
    identity: String,
    display: String,
}

struct Parser<'a> {
    framework: RouteFramework,
    input: &'a str,
    bytes: &'a [u8],
    pos: usize,
    segments: Vec<Segment>,
    current: Segment,
    params: Vec<RouteParam>,
    wildcard: bool,
    last_was_separator: bool,
}

impl<'a> Parser<'a> {
    fn new(framework: RouteFramework, input: &'a str) -> Self {
        Self {
            framework,
            input,
            bytes: input.as_bytes(),
            pos: 0,
            segments: Vec::new(),
            current: Segment::default(),
            params: Vec::new(),
            wildcard: false,
            last_was_separator: false,
        }
    }

    fn run(mut self) -> Result<NormalizedRoute, RouteNormalizationError> {
        while self.pos < self.bytes.len() {
            let byte = self.bytes[self.pos];
            let separator = byte == b'/';
            match byte {
                b'/' => {
                    self.pos += 1;
                    self.finish_segment();
                }
                b'{' => self.brace()?,
                b'}' => return Err(RouteNormalizationError::UnbalancedParameter),
                b':' if self.framework.colon_params() => self.colon()?,
                b'<' if self.framework.angle_params() => self.angle()?,
                b'*' => self.star(),
                b'?' | b'#' => return Err(RouteNormalizationError::QueryOrFragment),
                b'%' => self.percent()?,
                b'\\' => self.backslash()?,
                0..=0x1f | 0x7f => return Err(RouteNormalizationError::ControlCharacter),
                b':' | b'<' | b'>' => {
                    self.pos += 1;
                    self.push_encoded(byte);
                }
                _ => self.literal_char(),
            }
            self.last_was_separator = separator;
        }
        self.finish_segment();
        self.finish()
    }

    fn finish(self) -> Result<NormalizedRoute, RouteNormalizationError> {
        let strict_slash = self.last_was_separator && !self.segments.is_empty();
        let (identity, display) = if self.segments.is_empty() {
            ("/".to_owned(), "/".to_owned())
        } else {
            let mut identity = String::new();
            let mut display = String::new();
            for segment in &self.segments {
                identity.push('/');
                identity.push_str(&segment.identity);
                display.push('/');
                display.push_str(&segment.display);
            }
            (identity, display)
        };
        if identity.len() > MAX_ROUTE_BYTES || display.len() > MAX_ROUTE_BYTES {
            return Err(RouteNormalizationError::TooLong);
        }
        Ok(NormalizedRoute {
            identity,
            display,
            strict_slash,
            wildcard: self.wildcard,
            params: self.params,
        })
    }

    fn finish_segment(&mut self) {
        if !self.current.identity.is_empty() {
            self.segments.push(std::mem::take(&mut self.current));
        }
    }

    fn push_both(&mut self, text: &str) {
        self.current.identity.push_str(text);
        self.current.display.push_str(text);
    }

    fn push_encoded(&mut self, byte: u8) {
        let text = format!("%{byte:02X}");
        self.push_both(&text);
    }

    fn literal_char(&mut self) {
        // `pos` always sits on a char boundary here: syntax bytes are ASCII and
        // every other branch consumes whole characters.
        if let Some(ch) = self.input[self.pos..].chars().next() {
            self.pos += ch.len_utf8();
            let mut buffer = [0_u8; 4];
            self.push_both(ch.encode_utf8(&mut buffer));
        }
    }

    fn star(&mut self) {
        self.wildcard = true;
        self.pos += 1;
        // Express 5 / Fastify style named catch-all: `*splat`.
        if self.framework.splat_params() && self.peek_is_name_start() {
            let name = self.take_name();
            self.params.push(RouteParam { name: name.clone(), constraint: None, optional: false });
            self.current.identity.push_str("{*}");
            self.current.display.push_str(&format!("{{*{name}}}"));
        } else {
            self.push_both("*");
        }
    }

    fn peek_is_name_start(&self) -> bool {
        self.bytes.get(self.pos).is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
    }

    fn take_name(&mut self) -> String {
        let start = self.pos;
        while self.bytes.get(self.pos).is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_') {
            self.pos += 1;
        }
        self.input[start..self.pos].to_owned()
    }

    fn percent(&mut self) -> Result<(), RouteNormalizationError> {
        let hex = |index: usize| -> Option<u8> {
            self.bytes.get(index).and_then(|b| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            })
        };
        let (Some(high), Some(low)) = (hex(self.pos + 1), hex(self.pos + 2)) else {
            return Err(RouteNormalizationError::InvalidEscape);
        };
        let value = high * 16 + low;
        self.pos += 3;
        if value.is_ascii_alphanumeric() || matches!(value, b'-' | b'.' | b'_' | b'~') {
            let ch = char::from(value);
            let mut buffer = [0_u8; 4];
            self.push_both(ch.encode_utf8(&mut buffer));
        } else {
            self.push_encoded(value);
        }
        Ok(())
    }

    fn backslash(&mut self) -> Result<(), RouteNormalizationError> {
        self.pos += 1;
        let Some(ch) = self.input[self.pos..].chars().next() else {
            // A trailing backslash escapes nothing.
            self.push_encoded(b'\\');
            return Ok(());
        };
        if ch.is_ascii() {
            let byte = ch as u8;
            if byte < 0x20 || byte == 0x7f {
                return Err(RouteNormalizationError::ControlCharacter);
            }
            self.pos += 1;
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                self.push_both(ch.encode_utf8(&mut [0_u8; 4]));
            } else {
                self.push_encoded(byte);
            }
        } else {
            self.pos += ch.len_utf8();
            self.push_both(ch.encode_utf8(&mut [0_u8; 4]));
        }
        Ok(())
    }

    fn add_param(
        &mut self,
        name: &str,
        constraint: Option<String>,
        optional: bool,
    ) -> Result<(), RouteNormalizationError> {
        if self.params.len() >= MAX_ROUTE_PARAMS {
            return Err(RouteNormalizationError::TooManyParameters);
        }
        let constraint = constraint.filter(|c| !c.is_empty());
        if constraint.as_ref().is_some_and(|c| c.len() > MAX_PARAM_CONSTRAINT_BYTES) {
            // Constraint is metadata; keep the route, drop the oversize text.
            self.params.push(RouteParam { name: name.to_owned(), constraint: None, optional });
        } else {
            self.params.push(RouteParam { name: name.to_owned(), constraint, optional });
        }
        self.current.identity.push_str("{id}");
        self.current.display.push('{');
        self.current.display.push_str(name);
        self.current.display.push('}');
        Ok(())
    }

    /// Reads from `{` to the matching `}` honoring nested braces and `\x`.
    fn brace(&mut self) -> Result<(), RouteNormalizationError> {
        let open = self.pos;
        let mut depth = 0_usize;
        let mut index = open;
        let close = loop {
            let Some(byte) = self.bytes.get(index) else {
                return Err(RouteNormalizationError::UnbalancedParameter);
            };
            match byte {
                b'\\' => index += 1,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        break index;
                    }
                }
                _ => {}
            }
            index += 1;
        };
        let content = &self.input[open + 1..close];
        self.pos = close + 1;
        if let Some(rest) = content.strip_prefix('*') {
            // Spring `{*rest}` / `{**rest}` catch-all.
            let name = rest.trim_start_matches('*').trim();
            self.wildcard = true;
            if !name.is_empty() {
                validate_param_name(name)?;
            }
            if self.params.len() >= MAX_ROUTE_PARAMS {
                return Err(RouteNormalizationError::TooManyParameters);
            }
            self.params.push(RouteParam {
                name: name.to_owned(),
                constraint: None,
                optional: false,
            });
            self.current.identity.push_str("{*}");
            self.current.display.push_str(&format!("{{*{name}}}"));
            return Ok(());
        }
        let (name, constraint) = match content.split_once(':') {
            Some((name, constraint)) => (name.trim(), Some(constraint.trim().to_owned())),
            None => (content.trim(), None),
        };
        validate_param_name(name)?;
        self.add_param(name, constraint, false)
    }

    /// `:name`, `:name(regex)`, `:name?`, `:name*`, `:name+`.
    fn colon(&mut self) -> Result<(), RouteNormalizationError> {
        self.pos += 1;
        let name = self.take_name();
        if name.is_empty() {
            self.push_encoded(b':');
            return Ok(());
        }
        validate_param_name(&name)?;
        let mut constraint = None;
        if self.bytes.get(self.pos) == Some(&b'(') {
            constraint = Some(self.balanced_group(b'(', b')')?);
        }
        let mut optional = false;
        match self.bytes.get(self.pos) {
            Some(b'?') => {
                optional = true;
                self.pos += 1;
            }
            Some(b'*' | b'+') => {
                self.wildcard = true;
                self.pos += 1;
            }
            _ => {}
        }
        self.add_param(&name, constraint, optional)
    }

    /// `<name>` and `<converter:name>`.
    fn angle(&mut self) -> Result<(), RouteNormalizationError> {
        let open = self.pos;
        let mut index = open + 1;
        let close = loop {
            match self.bytes.get(index) {
                None | Some(b'/') => return Err(RouteNormalizationError::UnbalancedParameter),
                Some(b'>') => break index,
                _ => index += 1,
            }
        };
        let content = &self.input[open + 1..close];
        self.pos = close + 1;
        let (converter, name) = match content.rsplit_once(':') {
            Some((converter, name)) => (Some(converter.trim().to_owned()), name.trim()),
            None => (None, content.trim()),
        };
        validate_param_name(name)?;
        if converter.as_deref() == Some("path") {
            self.wildcard = true;
        }
        self.add_param(name, converter, false)
    }

    fn balanced_group(&mut self, open: u8, close: u8) -> Result<String, RouteNormalizationError> {
        let start = self.pos;
        let mut depth = 0_usize;
        let mut index = start;
        loop {
            let Some(byte) = self.bytes.get(index) else {
                return Err(RouteNormalizationError::UnbalancedParameter);
            };
            if *byte == b'\\' {
                index += 2;
                continue;
            }
            if *byte == open {
                depth += 1;
            } else if *byte == close {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            index += 1;
        }
        let text = self.input[start + 1..index].to_owned();
        self.pos = index + 1;
        Ok(text)
    }
}

fn validate_param_name(name: &str) -> Result<(), RouteNormalizationError> {
    let valid = !name.is_empty()
        && name.len() <= MAX_PARAM_NAME_BYTES
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    if valid { Ok(()) } else { Err(RouteNormalizationError::InvalidParameterName) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(framework: RouteFramework, template: &str) -> String {
        normalize_route(framework, template).expect("normalizes").identity
    }

    #[test]
    fn normalize_converts_colon_angle_and_brace_params_to_brace_id() {
        assert_eq!(identity(RouteFramework::Express, "/users/:id"), "/users/{id}");
        assert_eq!(identity(RouteFramework::Generic, "/users/<id>"), "/users/{id}");
        assert_eq!(identity(RouteFramework::Generic, "/users/<int:id>"), "/users/{id}");
        assert_eq!(identity(RouteFramework::SpringMvc, "/users/{id:[0-9]+}"), "/users/{id}");
        assert_eq!(identity(RouteFramework::JaxRs, "/users/{ id : [0-9]{1,3} }"), "/users/{id}");
        assert_eq!(identity(RouteFramework::Express, "/users/:id(\\d+)"), "/users/{id}");
    }

    #[test]
    fn constraint_and_declared_name_are_kept_as_metadata() {
        let route =
            normalize_route(RouteFramework::SpringMvc, "/owners/{ownerId:\\d+}/pets").unwrap();
        assert_eq!(route.identity, "/owners/{id}/pets");
        assert_eq!(route.display, "/owners/{ownerId}/pets");
        assert_eq!(
            route.params,
            vec![RouteParam {
                name: "ownerId".to_owned(),
                constraint: Some("\\d+".to_owned()),
                optional: false,
            }]
        );
    }

    #[test]
    fn normalize_param_rename_keeps_identity() {
        let a = normalize_route(RouteFramework::SpringMvc, "/users/{id}").unwrap();
        let b = normalize_route(RouteFramework::SpringMvc, "/users/{userId}").unwrap();
        assert_eq!(a.identity, b.identity);
        assert_ne!(a.display, b.display);
    }

    #[test]
    fn regex_constraint_may_contain_slash_and_braces() {
        let route =
            normalize_route(RouteFramework::JaxRs, "/files/{path: .+/[a-z]{2}}/raw").unwrap();
        assert_eq!(route.identity, "/files/{id}/raw");
        assert_eq!(route.params[0].constraint.as_deref(), Some(".+/[a-z]{2}"));
    }

    #[test]
    fn normalize_trailing_slash_and_repeated_separators() {
        let route = normalize_route(RouteFramework::Generic, "//a///b//").unwrap();
        assert_eq!(route.identity, "/a/b");
        assert!(route.strict_slash);
        let root = normalize_route(RouteFramework::Generic, "///").unwrap();
        assert_eq!(root.identity, "/");
        assert!(!root.strict_slash);
        assert_eq!(identity(RouteFramework::Generic, ""), "/");
        assert!(!normalize_route(RouteFramework::Generic, "/a").unwrap().strict_slash);
    }

    #[test]
    fn normalize_preserves_encoded_slash() {
        assert_eq!(identity(RouteFramework::Generic, "/a%2fb"), "/a%2Fb");
        assert_eq!(identity(RouteFramework::Generic, "/a%2Fb/c"), "/a%2Fb/c");
        assert_eq!(identity(RouteFramework::Generic, "/a%41%7e"), "/aA~");
    }

    #[test]
    fn backslash_escapes_become_percent_escapes() {
        assert_eq!(identity(RouteFramework::Express, "/a\\:b"), "/a%3Ab");
        assert_eq!(identity(RouteFramework::Express, "/a\\/b"), "/a%2Fb");
        assert_eq!(identity(RouteFramework::Express, "/a\\{b"), "/a%7Bb");
    }

    #[test]
    fn literal_colon_is_encoded_outside_colon_frameworks() {
        assert_eq!(identity(RouteFramework::SpringMvc, "/a:b"), "/a%3Ab");
        assert_eq!(
            identity(RouteFramework::Generic, &identity(RouteFramework::SpringMvc, "/a:b")),
            "/a%3Ab"
        );
    }

    #[test]
    fn wildcards_are_flagged() {
        let spring = normalize_route(RouteFramework::SpringMvc, "/static/{*rest}").unwrap();
        assert_eq!(spring.identity, "/static/{*}");
        assert_eq!(spring.display, "/static/{*rest}");
        assert!(spring.wildcard);
        let star = normalize_route(RouteFramework::Fastify, "/files/*").unwrap();
        assert_eq!(star.identity, "/files/*");
        assert!(star.wildcard);
        let named = normalize_route(RouteFramework::Express, "/files/*splat").unwrap();
        assert_eq!(named.identity, "/files/{*}");
        assert!(named.wildcard);
        assert!(!normalize_route(RouteFramework::Generic, "/a/{id}").unwrap().wildcard);
    }

    #[test]
    fn optional_parameter_is_reported() {
        let route = normalize_route(RouteFramework::Express, "/users/:id?").unwrap();
        assert_eq!(route.identity, "/users/{id}");
        assert!(route.params[0].optional);
    }

    #[test]
    fn mixed_segment_parameters_keep_their_literals() {
        assert_eq!(identity(RouteFramework::Fastify, "/:file.:ext"), "/{id}.{id}");
        assert_eq!(identity(RouteFramework::Express, "/flights/:from-:to"), "/flights/{id}-{id}");
    }

    #[test]
    fn invalid_templates_are_rejected_with_stable_codes() {
        let cases = [
            ("/a?x=1", RouteNormalizationError::QueryOrFragment),
            ("/a#frag", RouteNormalizationError::QueryOrFragment),
            ("/a/{id", RouteNormalizationError::UnbalancedParameter),
            ("/a/id}", RouteNormalizationError::UnbalancedParameter),
            ("/a/{}", RouteNormalizationError::InvalidParameterName),
            ("/a/{bad name}", RouteNormalizationError::InvalidParameterName),
            ("/a/%zz", RouteNormalizationError::InvalidEscape),
            ("/a/%2", RouteNormalizationError::InvalidEscape),
            ("/a\u{1}b", RouteNormalizationError::ControlCharacter),
        ];
        for (input, expected) in cases {
            assert_eq!(normalize_route(RouteFramework::Generic, input), Err(expected), "{input:?}");
        }
        assert_eq!(
            normalize_route(RouteFramework::Generic, &"a".repeat(MAX_ROUTE_BYTES + 1)),
            Err(RouteNormalizationError::TooLong)
        );
        let many = "/{p}".repeat(MAX_ROUTE_PARAMS + 1);
        assert_eq!(
            normalize_route(RouteFramework::Generic, &many),
            Err(RouteNormalizationError::TooManyParameters)
        );
    }

    #[test]
    fn join_and_normalize_joins_class_and_method_paths() {
        let route =
            join_and_normalize(RouteFramework::SpringMvc, &["/owners/{ownerId}", "pets/{petId}/"])
                .unwrap();
        assert_eq!(route.identity, "/owners/{id}/pets/{id}");
        assert!(route.strict_slash);
        assert_eq!(join_and_normalize(RouteFramework::SpringMvc, &["", ""]).unwrap().identity, "/");
        assert_eq!(
            join_and_normalize(RouteFramework::SpringMvc, &["/api", ""]).unwrap().identity,
            "/api"
        );
        assert_eq!(
            join_and_normalize(RouteFramework::SpringMvc, &["/api", "/"]).unwrap().identity,
            "/api"
        );
    }

    #[test]
    fn framework_vocabulary_round_trips() {
        for framework in [
            RouteFramework::SpringMvc,
            RouteFramework::JaxRs,
            RouteFramework::Express,
            RouteFramework::Fastify,
            RouteFramework::Nest,
            RouteFramework::Generic,
        ] {
            assert_eq!(RouteFramework::parse(framework.as_str()), Some(framework));
        }
        assert_eq!(RouteFramework::parse("rails"), None);
    }

    /// Deterministic generator so property tests are reproducible without a
    /// property-testing dependency.
    struct Xorshift(u64);

    impl Xorshift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: usize) -> usize {
            usize::try_from(self.next() % u64::try_from(bound).unwrap()).unwrap()
        }
    }

    const NOISE: &[&str] = &[
        "/",
        "//",
        "a",
        "b",
        "users",
        ":",
        ":id",
        "{",
        "}",
        "{id}",
        "{id:[0-9]+}",
        "<",
        ">",
        "<n>",
        "*",
        "**",
        "{*r}",
        "%",
        "%2f",
        "%41",
        "\\",
        "?",
        "#",
        ".",
        "-",
        "(",
        ")",
        "é",
        "\u{1}",
        " ",
    ];

    fn noise(rng: &mut Xorshift) -> String {
        let mut text = String::new();
        for _ in 0..rng.below(12) {
            text.push_str(NOISE[rng.below(NOISE.len())]);
        }
        text
    }

    #[test]
    fn normalize_never_emits_query_or_fragment_and_never_panics() {
        let mut rng = Xorshift(0x9E37_79B9_7F4A_7C15);
        let frameworks = [
            RouteFramework::SpringMvc,
            RouteFramework::JaxRs,
            RouteFramework::Express,
            RouteFramework::Fastify,
            RouteFramework::Nest,
            RouteFramework::Generic,
        ];
        let mut accepted = 0_u32;
        for round in 0..20_000 {
            let framework = frameworks[round % frameworks.len()];
            let input = noise(&mut rng);
            if let Ok(route) = normalize_route(framework, &input) {
                accepted += 1;
                for text in [&route.identity, &route.display] {
                    assert!(!text.contains('?') && !text.contains('#'), "{input:?} -> {text:?}");
                    assert!(text.starts_with('/'), "{input:?} -> {text:?}");
                    assert!(!text.contains("//"), "{input:?} -> {text:?}");
                    assert!(text == "/" || !text.ends_with('/'), "{input:?} -> {text:?}");
                }
            }
        }
        assert!(accepted > 1_000, "generator must exercise the accept path, got {accepted}");
    }

    #[test]
    fn normalize_is_idempotent() {
        let mut rng = Xorshift(0xD1B5_4A32_D192_ED03);
        let frameworks = [
            RouteFramework::SpringMvc,
            RouteFramework::JaxRs,
            RouteFramework::Express,
            RouteFramework::Fastify,
            RouteFramework::Nest,
            RouteFramework::Generic,
        ];
        let mut checked = 0_u32;
        for round in 0..20_000 {
            let framework = frameworks[round % frameworks.len()];
            let input = noise(&mut rng);
            let Ok(first) = normalize_route(framework, &input) else { continue };
            checked += 1;
            let again = normalize_route(RouteFramework::Generic, &first.identity);
            assert!(again.is_ok(), "identity of {input:?} = {:?} fails: {again:?}", first.identity);
            let again = again.unwrap();
            assert_eq!(again.identity, first.identity, "{input:?}");
            let from_display = normalize_route(RouteFramework::Generic, &first.display);
            assert!(
                from_display.is_ok(),
                "display of {input:?} = {:?} fails: {from_display:?}",
                first.display
            );
            let from_display = from_display.unwrap();
            assert_eq!(from_display.identity, first.identity, "{input:?}");
        }
        assert!(checked > 1_000, "generator must exercise the accept path, got {checked}");
    }

    #[test]
    fn identity_is_invariant_under_parameter_renames_in_every_syntax() {
        let mut rng = Xorshift(0xA076_1D64_78BD_642F);
        let literals = ["users", "api", "v1", "orders", "x-y", "a.b"];
        let names = ["id", "userId", "order_id", "k", "name_1"];
        for _ in 0..5_000 {
            let mut shape: Vec<(bool, usize)> = Vec::new();
            for _ in 0..=rng.below(5) {
                shape.push((rng.below(2) == 0, rng.below(literals.len())));
            }
            let render = |colon: bool, name_offset: usize| -> String {
                let mut out = String::new();
                for (index, (is_param, pick)) in shape.iter().enumerate() {
                    out.push('/');
                    if *is_param {
                        let name = names[(pick + index + name_offset) % names.len()];
                        if colon {
                            out.push_str(&format!(":{name}"));
                        } else {
                            out.push_str(&format!("{{{name}}}"));
                        }
                    } else {
                        out.push_str(literals[*pick]);
                    }
                }
                out
            };
            let baseline = identity(RouteFramework::SpringMvc, &render(false, 0));
            for (framework, colon) in [
                (RouteFramework::SpringMvc, false),
                (RouteFramework::JaxRs, false),
                (RouteFramework::Express, true),
                (RouteFramework::Fastify, true),
                (RouteFramework::Nest, true),
                (RouteFramework::Generic, true),
            ] {
                for offset in 0..3 {
                    assert_eq!(identity(framework, &render(colon, offset)), baseline);
                }
            }
        }
    }

    #[test]
    fn shared_vectors_pass() {
        let text = include_str!("../../../schema/fixtures/normalizer-vectors.json");
        let document: serde_json::Value = serde_json::from_str(text).expect("vector file is JSON");
        assert_eq!(document["version"], 1);
        let mut cases = 0_u32;
        for case in document["cases"].as_array().expect("cases array") {
            let name = case["name"].as_str().expect("name");
            let framework = RouteFramework::parse(case["framework"].as_str().expect("framework"))
                .expect("known framework");
            let parts: Vec<&str> = case["input"].as_array().map_or_else(
                || vec![case["input"].as_str().expect("input")],
                |parts| parts.iter().map(|p| p.as_str().expect("part")).collect(),
            );
            let result = join_and_normalize(framework, &parts);
            if let Some(code) = case.get("error").and_then(|e| e.as_str()) {
                assert_eq!(result.expect_err(name).code(), code, "{name}");
            } else {
                assert!(result.is_ok(), "{name}: {result:?}");
                let route = result.unwrap();
                assert_eq!(route.identity, case["identity"].as_str().expect("identity"), "{name}");
                assert_eq!(route.display, case["display"].as_str().expect("display"), "{name}");
                assert_eq!(
                    route.strict_slash,
                    case["strictSlash"].as_bool().expect("strictSlash"),
                    "{name}"
                );
                assert_eq!(route.wildcard, case["wildcard"].as_bool().expect("wildcard"), "{name}");
                let params: Vec<&str> = case["params"]
                    .as_array()
                    .expect("params")
                    .iter()
                    .map(|p| p.as_str().expect("p"))
                    .collect();
                let actual: Vec<&str> = route.params.iter().map(|p| p.name.as_str()).collect();
                assert_eq!(actual, params, "{name}");
            }
            cases += 1;
        }
        assert!(cases >= 25, "vector file must stay substantial, found {cases}");
    }
}
