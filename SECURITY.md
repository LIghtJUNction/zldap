# Security boundary

zldap decodes protocol data. A parsed BindRequest contains authentication data supplied by the peer; parsing it does not verify a password, establish an identity, or grant access. The application owns authentication, authorization, transport protection, and connection state.

## Resource policy

Choose `ParseLimits` for the deployment and provide a bounded workspace. Message bytes, field count, nesting depth, and string length are separate limits: a short packet can still contain excessive nesting or many empty fields. Check every `Result` before using protocol data. Treat incomplete framing as incomplete input only while the connection's own receive-size and time budgets allow more data.

The crate uses only safe Rust, forbids `unsafe_code`, and has no allocator or third-party dependencies. The test suite covers malformed encodings, integer overflow, resource limits, and randomized inputs. CI also interprets the core tests under Miri. These checks support the implementation's safety claims; they do not make an application's authentication or network policy correct automatically.

## Reporting

For a suspected vulnerability, provide the crate version, a minimal synthetic byte sequence, `ParseLimits`, workspace capacity, observed behavior, and expected behavior. Use GitHub private vulnerability reporting when available, or contact the maintainer privately. Exclude real passwords, directory data, and access tokens from a reproducer.

## Release integrity

The release workflow validates the exact commit before publishing. Only its publication step receives `CARGO_REGISTRY_TOKEN`; pull-request checks receive no publication credential. Version occupancy checks fail on registry errors. An explicit recovery accepts an existing version only when its archive SHA-256 matches the validated artifact, and an existing tag must point to the validated commit. Tag creation and GitHub Release creation happen in the same workflow run.
