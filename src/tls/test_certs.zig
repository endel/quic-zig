//! Certificates shared by the TLS tests.
const std = @import("std");
const tls13 = @import("../quic/tls13.zig");

const CertEntry = tls13.CertEntry;

// Self-signed, valid to 2056. localhost and *.example.com share one P-256 key.
pub const test_ec_key_pem =
    \\-----BEGIN EC PRIVATE KEY-----
    \\MHcCAQEEIAKIla+65TNSSfs8RKsI9dq3KKp/WC0RUKceTUDNQYgPoAoGCCqGSM49
    \\AwEHoUQDQgAETSp/wPgU7+juILb0Ugk7IpUQd/TAcTd69dibi8gbAY23ktARkE9C
    \\53VIGla7Uzbu4gkotGeZg8ufOEbX4cC44w==
    \\-----END EC PRIVATE KEY-----
;
pub const test_localhost_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBlTCCATugAwIBAgIUJ0VVpBMXbR+m2qeJVtlLPwMGrS8wCgYIKoZIzj0EAwIw
    \\FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDkxODAyMjc1MVoYDzIwNTYwOTEw
    \\MDIyNzUxWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
    \\PQMBBwNCAARNKn/A+BTv6O4gtvRSCTsilRB39MBxN3r12JuLyBsBjbeS0BGQT0Ln
    \\dUgaVrtTNu7iCSi0Z5mDy584RtfhwLjjo2kwZzAdBgNVHQ4EFgQUgsQXmkDpwyyD
    \\DE+urWAkJzlvp4gwHwYDVR0jBBgwFoAUgsQXmkDpwyyDDE+urWAkJzlvp4gwDwYD
    \\VR0TAQH/BAUwAwEB/zAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwID
    \\SAAwRQIhAL/ObOrd87Ioq197659prUHNDVOQ8y9LpqKlXroBCK0+AiBu5JczdLo0
    \\paz/2uMhZZ65w/QAplKh2+e0QSDAcZreyA==
    \\-----END CERTIFICATE-----
;
pub const test_wildcard_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBnDCCAUOgAwIBAgIUBeGIcIZGlWQDw9k8EVl0eQn+0i8wCgYIKoZIzj0EAwIw
    \\FjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wIBcNMjYwOTE4MDIyNzUxWhgPMjA1NjA5
    \\MTAwMjI3NTFaMBYxFDASBgNVBAMMC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYI
    \\KoZIzj0DAQcDQgAETSp/wPgU7+juILb0Ugk7IpUQd/TAcTd69dibi8gbAY23ktAR
    \\kE9C53VIGla7Uzbu4gkotGeZg8ufOEbX4cC446NtMGswHQYDVR0OBBYEFILEF5pA
    \\6cMsgwxPrq1gJCc5b6eIMB8GA1UdIwQYMBaAFILEF5pA6cMsgwxPrq1gJCc5b6eI
    \\MA8GA1UdEwEB/wQFMAMBAf8wGAYDVR0RBBEwD4INKi5leGFtcGxlLmNvbTAKBggq
    \\hkjOPQQDAgNHADBEAiBaUMdxsQOU9V2gfaL6EW0cblAScC1OvxJl+4P07YUxDAIg
    \\ffw63xlHzM5X1n+gB6U2k9pqnk+IQYwD2pyylUk/I74=
    \\-----END CERTIFICATE-----
;
pub const test_ed25519_key_pem =
    \\-----BEGIN PRIVATE KEY-----
    \\MC4CAQAwBQYDK2VwBCIEIC7QOG4KwXQFSsbxdpxWvVUO5ON7JPjpewzoDqKPZSoO
    \\-----END PRIVATE KEY-----
;
pub const test_ed25519_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBTzCCAQGgAwIBAgIUElLBZ3M+v85vUwlfAtwMIFA8fvQwBQYDK2VwMBIxEDAO
    \\BgNVBAMMB2VkLnRlc3QwIBcNMjYwOTE4MDIyNzUxWhgPMjA1NjA5MTAwMjI3NTFa
    \\MBIxEDAOBgNVBAMMB2VkLnRlc3QwKjAFBgMrZXADIQDDb3XnRnNGl7VnUxtvlAM3
    \\Wx++JEtaulpTtA6HsXZ5HaNnMGUwHQYDVR0OBBYEFLT9KJDLMqFxXjDiduG7N1zR
    \\HoZTMB8GA1UdIwQYMBaAFLT9KJDLMqFxXjDiduG7N1zRHoZTMA8GA1UdEwEB/wQF
    \\MAMBAf8wEgYDVR0RBAswCYIHZWQudGVzdDAFBgMrZXADQQCnjUP9Av1Ugtg6dE+7
    \\VljHsDK78pyjUZWFgeuzx/aQ2obYNKv3HLka/NYNWMQNiNeEFVpfwqDhBCAUe9ia
    \\angI
    \\-----END CERTIFICATE-----
;

/// interop/certs: a CA, and a leaf it signed for localhost, 127.0.0.1 and ::1
/// (valid to 2036).
pub const interop_ca_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBVTCB/KADAgECAgkAs84+0pSp5UkwCgYIKoZIzj0EAwIwHjEcMBoGA1UEAwwT
    \\cXVpYy16aWcgaW50ZXJvcCBDQTAeFw0yNjAzMTIwNDI1MDdaFw0zNjAzMDkwNDI1
    \\MDdaMB4xHDAaBgNVBAMME3F1aWMtemlnIGludGVyb3AgQ0EwWTATBgcqhkjOPQIB
    \\BggqhkjOPQMBBwNCAAS3jQ8iTpDTZ87j4sfrPztu4hr8d/Ep3m9Vt/+QmhVtVdrC
    \\uL+E7wLBHXKqkY7oBWt7WMjuTJHfsMzaQwNQvFm/oyMwITAPBgNVHRMBAf8EBTAD
    \\AQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNIADBFAiAbTTSRHrX8prIw
    \\4IJHkUCOEjBHCjflLVAlc3MnopJ/1AIhAIOQS3USGjl6TbHMGvRt2gZUNe+HXjq5
    \\64pxXZ9qM6nG
    \\-----END CERTIFICATE-----
;
pub const interop_server_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBgzCCASqgAwIBAgIJAMklErU+FL04MAoGCCqGSM49BAMCMB4xHDAaBgNVBAMM
    \\E3F1aWMtemlnIGludGVyb3AgQ0EwHhcNMjYwMzEyMTUzMzM1WhcNMzYwMzA5MTUz
    \\MzM1WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB
    \\BwNCAARTMns09goeQ3p8Ws6i8oCqHHbbt+czZfUUMjWDVoO93AlWvUHu9HLTNQ7W
    \\BWRA8kZ6cncadFzlVtUZYeZHFG6fo1swWTA/BgNVHREEODA2gglsb2NhbGhvc3SC
    \\B3NlcnZlcjSCCHNlcnZlcjQ2hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMAkGA1Ud
    \\EwQCMAAwCwYDVR0PBAQDAgeAMAoGCCqGSM49BAMCA0cAMEQCIFKWL/UrEDzNdWCZ
    \\5us833b7ESITAHSb6bJFu6ZppJsGAiBgalDEBhK/fbDti9LZuhvEqIZlLBuFCYGJ
    \\jU0l+QUuXQ==
    \\-----END CERTIFICATE-----
;
pub const interop_server_key_pem =
    \\-----BEGIN EC PRIVATE KEY-----
    \\MHcCAQEEIDJQwRgYq5iuftGgBAqU8fTDw9HztFH2Ky3kR0N/wMLcoAoGCCqGSM49
    \\AwEHoUQDQgAEUzJ7NPYKHkN6fFrOovKAqhx227fnM2X1FDI1g1aDvdwJVr1B7vRy
    \\0zUO1gVkQPJGenJ3GnRc5VbVGWHmRxRunw==
    \\-----END EC PRIVATE KEY-----
;

pub const TestCerts = struct {
    der: [3][1024]u8,
    chains: [3][1][]const u8,
    key_der: [2][256]u8,
    entries: [3]CertEntry,

    /// Entry 0 (default) is localhost, 1 is *.example.com, 2 is Ed25519 ed.test.
    pub fn load(self: *TestCerts) !void {
        const pems = [3][]const u8{ test_localhost_pem, test_wildcard_pem, test_ed25519_pem };
        for (pems, 0..) |pem, i| self.chains[i] = .{try tls13.parsePemCert(pem, &self.der[i])};
        const ec = try tls13.extractEcPrivateKey(try tls13.parsePemPrivateKey(test_ec_key_pem, &self.key_der[0]));
        const ed = try tls13.extractEd25519PrivateKey(try tls13.parsePemPrivateKey(test_ed25519_key_pem, &self.key_der[1]));
        self.entries = .{
            .{ .server_names = &.{"localhost"}, .cert = .{ .cert_chain_der = &self.chains[0], .private_key_bytes = ec } },
            .{ .server_names = &.{"*.example.com"}, .cert = .{ .cert_chain_der = &self.chains[1], .private_key_bytes = ec } },
            .{ .server_names = &.{"ed.test"}, .cert = .{
                .cert_chain_der = &self.chains[2],
                .private_key_bytes = ed,
                .private_key_algorithm = .ed25519,
            } },
        };
    }
};
