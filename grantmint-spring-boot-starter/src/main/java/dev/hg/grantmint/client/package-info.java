/**
 * Grantmint Spring Boot starter: the Apache-2.0 client SDK.
 *
 * <p>This module auto-configures a {@code LicenseValidator} bean that any consuming Spring
 * application can use to verify Grantmint license tokens <em>offline</em> against an embedded
 * public key, plus an optional online layer (activate / deactivate / heartbeat / validate).
 * The auto-configuration and validator land in milestone M9; this is the M0 skeleton.
 *
 * <p><strong>Licensing:</strong> this module is Apache-2.0 so it can be embedded in downstream
 * products — including closed commercial apps — without copyleft contagion. No AGPL code may be
 * moved here. See docs/security/OPERATOR_AND_LICENSE_NOTES.md.
 */
package dev.hg.grantmint.client;
