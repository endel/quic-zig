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

// Self-signed RSA 2048 for rsa.test, valid to 2056; one key in both encodings.
pub const test_rsa_key_pem =
    \\-----BEGIN PRIVATE KEY-----
    \\MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCLluUTpduczsUW
    \\qxEOHAufcwrxDexevRw3afmCGxJVQrbW039Jye7RjlX4Ex3SXQlv6Irtpsd5bzdo
    \\A6zCFMotV2fLf38tkP/CDo+7uQzPCeVsi60a+MoDJDnhtIbw+WdL1gJ3Bu1ASK9N
    \\BYn2mtc2FX2GJPOpWwgzGdindm867UOfa8g1MTPwC1IRpjcqdydfbO+RzRMJYoCs
    \\Qvw01MjwdoCUdB7sJGZ/mEfeONSc/yzzei1c1rXCoUKj05rtEHNfiV43KIZJoVz2
    \\1fZQk8D3n/3/UOlMPHmp5e3lFnSwfsKaIKuYE6pBa031Y1k3N/UHAKJ7Fj3p9+4o
    \\4RKGWdl/AgMBAAECggEAGL7dSUhj0D6Pjd8xnNC39sJMNEOFnZ3kvKYax0fJTjgP
    \\dbH0pL4ZiiizcNDivoIjxCTzTAH+5rYimlvcamOJG9Sc3+RwRUGpNVuje2HotWNJ
    \\up5gR6HHHhtz72EzctCj0TvVIAioUncQLJVIyeDVOg9BO2CdmW472+M/FyDVwxo9
    \\jq9DKXbQUd7h+fuBlBG3UcC+Nq7psUJfSjpzAmH9GU/58fPgHtioq1js3o2iEHN5
    \\wVx7VE01nbkG1pPV/Pl0EYA5Bty30+x5mp5F7CQP0yJKykoq12JYXOqSVFNsYQ4u
    \\AhILGmtHSN60kSfiArLCS6poG+d/hIPryLKY/zHRYQKBgQDC4MJmhQYN4Mwfi0do
    \\F8jqfVSoYAZvt7DtzfkE8NFC3K59x2/U4bOxF3D6i+3s4ZssQuG+8WrSaRawijRV
    \\xnomZhkZuwnTelYOUgw5wEaYQ39G6Qg9gnJH4Q5+b5hAcHRVarzXP2SOonSyGxN6
    \\wU4Crtsb1DnwaEotAl3m5v8ihwKBgQC3XuFluf8gwZHgDTwMNPAt6UbcQBLeuJg4
    \\u5yoOwuwIpChwuJ8fAjNpRxS7gX3gc1HwWy+QaGy5ZSEn59vFksu5d2BGcMmnEFF
    \\DngyLRnoKNJF51Ql9XsNF0PGY24PIg+luIiDd/cJMlUEpzm4anBWPZnrKubN1jdr
    \\0XMixOI3SQKBgDnZvPvwG1b9V7s5fm4hOWya3gnJz79UWXqOvZDA6G4f0tDV5pXc
    \\lppIqipGZc//PTBLfnZPdnWV6r1nmZeo/tPtVSA1TPpxg6BmrOhr8sj6qIrlXKPd
    \\2I0L+2B/QkRG3dIJiJuhXvmUsm246fRz8/OJ8tN1EeoTG4n2/OcxxaV7AoGBAJtp
    \\zg1C0+n2RWWoseECqSGwWf9oStX7jABhekfXK3PQB9ch7oVlNqzcqKHc3K/Gkq6j
    \\UD/8LkkKbZLuGtmzAmuwJMk7hXve6S7XMaYNNazflD/s7RPy96TDuAyXzvsCelKR
    \\kRoj/fsMbqQv+yrDA40ETsTTKqUATx6ReUzZo4UJAoGATbmjzfHw8t8AI8gYk1oy
    \\J3ct6TvTgtVsxyI6V1Yt+LfHbYQGP/GQu934hVmKD/k9YTl3o/P8YhWetM2uZKj2
    \\nqZoZHlMtBeOFR3g971pKHpLjivELoUn2V4GhThuoOwx5vgQjfwOz9A/YzOu4dfi
    \\O7/RxOnTzgGPD6q2hDukKUg=
    \\-----END PRIVATE KEY-----
;
pub const test_rsa_key_pkcs1_pem =
    \\-----BEGIN RSA PRIVATE KEY-----
    \\MIIEowIBAAKCAQEAi5blE6XbnM7FFqsRDhwLn3MK8Q3sXr0cN2n5ghsSVUK21tN/
    \\Scnu0Y5V+BMd0l0Jb+iK7abHeW83aAOswhTKLVdny39/LZD/wg6Pu7kMzwnlbIut
    \\GvjKAyQ54bSG8PlnS9YCdwbtQEivTQWJ9prXNhV9hiTzqVsIMxnYp3ZvOu1Dn2vI
    \\NTEz8AtSEaY3KncnX2zvkc0TCWKArEL8NNTI8HaAlHQe7CRmf5hH3jjUnP8s83ot
    \\XNa1wqFCo9Oa7RBzX4leNyiGSaFc9tX2UJPA95/9/1DpTDx5qeXt5RZ0sH7CmiCr
    \\mBOqQWtN9WNZNzf1BwCiexY96ffuKOEShlnZfwIDAQABAoIBABi+3UlIY9A+j43f
    \\MZzQt/bCTDRDhZ2d5LymGsdHyU44D3Wx9KS+GYoos3DQ4r6CI8Qk80wB/ua2Ippb
    \\3GpjiRvUnN/kcEVBqTVbo3th6LVjSbqeYEehxx4bc+9hM3LQo9E71SAIqFJ3ECyV
    \\SMng1ToPQTtgnZluO9vjPxcg1cMaPY6vQyl20FHe4fn7gZQRt1HAvjau6bFCX0o6
    \\cwJh/RlP+fHz4B7YqKtY7N6NohBzecFce1RNNZ25BtaT1fz5dBGAOQbct9PseZqe
    \\RewkD9MiSspKKtdiWFzqklRTbGEOLgISCxprR0jetJEn4gKywkuqaBvnf4SD68iy
    \\mP8x0WECgYEAwuDCZoUGDeDMH4tHaBfI6n1UqGAGb7ew7c35BPDRQtyufcdv1OGz
    \\sRdw+ovt7OGbLELhvvFq0mkWsIo0VcZ6JmYZGbsJ03pWDlIMOcBGmEN/RukIPYJy
    \\R+EOfm+YQHB0VWq81z9kjqJ0shsTesFOAq7bG9Q58GhKLQJd5ub/IocCgYEAt17h
    \\Zbn/IMGR4A08DDTwLelG3EAS3riYOLucqDsLsCKQocLifHwIzaUcUu4F94HNR8Fs
    \\vkGhsuWUhJ+fbxZLLuXdgRnDJpxBRQ54Mi0Z6CjSRedUJfV7DRdDxmNuDyIPpbiI
    \\g3f3CTJVBKc5uGpwVj2Z6yrmzdY3a9FzIsTiN0kCgYA52bz78BtW/Ve7OX5uITls
    \\mt4Jyc+/VFl6jr2QwOhuH9LQ1eaV3JaaSKoqRmXP/z0wS352T3Z1leq9Z5mXqP7T
    \\7VUgNUz6cYOgZqzoa/LI+qiK5Vyj3diNC/tgf0JERt3SCYiboV75lLJtuOn0c/Pz
    \\ifLTdRHqExuJ9vznMcWlewKBgQCbac4NQtPp9kVlqLHhAqkhsFn/aErV+4wAYXpH
    \\1ytz0AfXIe6FZTas3Kih3NyvxpKuo1A//C5JCm2S7hrZswJrsCTJO4V73uku1zGm
    \\DTWs35Q/7O0T8vekw7gMl877AnpSkZEaI/37DG6kL/sqwwONBE7E0yqlAE8ekXlM
    \\2aOFCQKBgE25o83x8PLfACPIGJNaMid3Lek704LVbMciOldWLfi3x22EBj/xkLvd
    \\+IVZig/5PWE5d6Pz/GIVnrTNrmSo9p6maGR5TLQXjhUd4Pe9aSh6S44rxC6FJ9le
    \\BoU4bqDsMeb4EI38Ds/QP2MzruHX4ju/0cTp084Bjw+qtoQ7pClI
    \\-----END RSA PRIVATE KEY-----
;
pub const test_rsa_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIDHjCCAgagAwIBAgIUUGw1tStpk7PuXgITczXn9WCmMYMwDQYJKoZIhvcNAQEL
    \\BQAwEzERMA8GA1UEAwwIcnNhLnRlc3QwIBcNMjYwOTE4MjMxMDEzWhgPMjA1NjA5
    \\MTAyMzEwMTNaMBMxETAPBgNVBAMMCHJzYS50ZXN0MIIBIjANBgkqhkiG9w0BAQEF
    \\AAOCAQ8AMIIBCgKCAQEAi5blE6XbnM7FFqsRDhwLn3MK8Q3sXr0cN2n5ghsSVUK2
    \\1tN/Scnu0Y5V+BMd0l0Jb+iK7abHeW83aAOswhTKLVdny39/LZD/wg6Pu7kMzwnl
    \\bIutGvjKAyQ54bSG8PlnS9YCdwbtQEivTQWJ9prXNhV9hiTzqVsIMxnYp3ZvOu1D
    \\n2vINTEz8AtSEaY3KncnX2zvkc0TCWKArEL8NNTI8HaAlHQe7CRmf5hH3jjUnP8s
    \\83otXNa1wqFCo9Oa7RBzX4leNyiGSaFc9tX2UJPA95/9/1DpTDx5qeXt5RZ0sH7C
    \\miCrmBOqQWtN9WNZNzf1BwCiexY96ffuKOEShlnZfwIDAQABo2gwZjAdBgNVHQ4E
    \\FgQUk5aWIT9A0Vwn1zm9PSQDHymGn0YwHwYDVR0jBBgwFoAUk5aWIT9A0Vwn1zm9
    \\PSQDHymGn0YwDwYDVR0TAQH/BAUwAwEB/zATBgNVHREEDDAKgghyc2EudGVzdDAN
    \\BgkqhkiG9w0BAQsFAAOCAQEAIKPceZej+AG5DmqR6iolJqGmHmSackCfrnAn9+aO
    \\tsUuUxbt1ysZhlRjXmIyrOn3JgsLQ2/f25uY1J4M1N3ym0T++jf4l2I+VVXiaMju
    \\2OozAZ7hidrSiJKbj8zn1iZEuBqbO0gNrqYjGD7FZ6DSQ7kF8ybVm3LdsvC+jOfu
    \\MKBzanEj3FrYCLZ5RCZM9BX6zv46V0ZKy73zFygxuO6imSBaWzDu13z0h/3Zs41E
    \\3cEMghT7DuKeXjdMf305maATFQXwHCBzCuILoyw23zGvwC9sWRFLTxp1vmE27dvB
    \\KJo55A5fPAirdh6Fhbp9m9QOGfDOmksPhLjIBrG+Kj3wEQ==
    \\-----END CERTIFICATE-----
;
/// Checked with openssl; see "a PSS signature matches one OpenSSL verified" in quic/rsa.zig.
pub const test_rsa_pss_fixture_hex =
    "0ab1f504ca9b6fa0786a9695a3166e0d1fc327e6faa2b9e1783dc38ef1c4ddf2" ++
    "ff7c023f44a2652bf79487d497a9928d96039643c99e05036e64cafce95b7a0e" ++
    "8f98ab5c82ea9cced5a3a60534054444d9463d0019a1dba0bf37571e9cc2f021" ++
    "a0b6d1ebef898b31b98d998393989a7bd35fcb6515a8f3a7b6cf79e3836df06d" ++
    "500ca2f5651993cb557fbe6da15251dbc8dfd51c3634c8cdcb18ad6b32edfa1d" ++
    "7954e2824def11094b3da8139daa08daa01c8062c9205d766b4e284dba30231e" ++
    "a1d18d9f4fadb58e7d0a2e3073eba52ad548e49a1875f94f24279ac4e7bd213b" ++
    "3f882c2c0bee88be1e08b489adc6d1f5df504bcd8c06890eecfca53b6c3398fb";

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

/// rsa.test's certificate with its key, read from either encoding.
pub const RsaCert = struct {
    der: [1536]u8,
    chain: [1][]const u8,
    key_der: [2048]u8,
    cert: tls13.ServerCertificate,

    pub fn load(self: *RsaCert, pkcs1: bool) !void {
        self.chain = .{try tls13.parsePemCert(test_rsa_pem, &self.der)};
        const pem = if (pkcs1) test_rsa_key_pkcs1_pem else test_rsa_key_pem;
        const key = try tls13.extractPrivateKey(try tls13.parsePemPrivateKey(pem, &self.key_der));
        self.cert = .{ .cert_chain_der = &self.chain, .private_key_bytes = key.bytes, .private_key_algorithm = key.algorithm };
    }
};
