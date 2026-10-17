// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package buildinfo

// SourceRevision comes only from the CI build argument. Empty builds cannot
// start an admitted node or watchdog service.
var SourceRevision string
