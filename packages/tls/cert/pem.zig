//! Implements PEM decoding according to https://datatracker.ietf.org/doc/html/rfc7468

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Convenience type that contains the `AsnType`
/// and the base64 decoded content of the file.
pub const Pem = struct {
    asn_type: AsnType,
    /// Decoded content of a PEM file
    content: []const u8,

    /// Frees any memory that was allocated during Pem decoding.
    /// Must provide the same `Allocator` that was given to the decoder.
    pub fn deinit(self: *Pem, gpa: Allocator) void {
        gpa.free(self.content);
        self.* = undefined;
    }
};

/// All ASN.1 types
pub const AsnType = enum {
    certificate,
    certificate_list,
    certificate_request,
    content_info,
    private_key_info,
    encrypted_private_key_info,
    attribute_certificate,
    subject_public_key_info,

    /// From a given label string, returns a corresponding `AsnType`.
    /// Will return null when label does not provide any match.
    pub fn fromLabel(label: []const u8) ?AsnType {
        if (mem.eql(u8, label, "CERTIFICATE")) return .certificate;
        if (mem.eql(u8, label, "X509 XRL")) return .certificate_list;
        if (mem.eql(u8, label, "CERTIFICATE REQUEST")) return .certificate_request;
        if (mem.eql(u8, label, "PKCS7")) return .content_info;
        if (mem.eql(u8, label, "CMS")) return .content_info;
        if (mem.eql(u8, label, "PRIVATE KEY")) return .private_key_info;
        if (mem.eql(u8, label, "ENCRYPTED PRIVATE KEY")) return .encrypted_private_key_info;
        if (mem.eql(u8, label, "ATTRIBUTE CERTIFICATE")) return .attribute_certificate;
        if (mem.eql(u8, label, "PUBLIC KEY")) return .subject_public_key_info;

        return null;
    }
};

/// Error set containing all possible errors when decoding a PEM file.
pub const DecodeError = error{
    /// Given PEM file is missing '-----BEGIN'
    MissingBegin,
    /// Given PEM file is missing '-----END'
    MissingEnd,
    /// -----BEGIN section is missing closing '-----'
    InvalidBegin,
    /// -----END section is missing closing '-----'
    InvalidEnd,
    /// Unknown or missing ASN.1 type
    InvalidAsnType,
    /// The ASN.1 type found in BEGIN and END are not matching
    MismatchingAsnType,
    /// A character was expected during encoding, but was either missing
    /// or a different character was found.
    MalformedFile,
    /// Tried to allocate memory during decoding, but no memory was available
    OutOfMemory,
};

/// Decodes given bytes into a `Pem` instance.
/// Memory is owned by caller and can be freed upon calling `deinit` on
/// the returned instance.
pub fn decode(gpa: Allocator, data: []const u8) (DecodeError || std.base64.Error)!Pem {
    var maybe_asn_type: ?AsnType = null;
    const begin_offset = if (mem.indexOf(u8, data, "-----BEGIN ")) |offset| blk: {
        const end_offset = mem.indexOfPos(u8, data, offset + 11, "-----") orelse return error.InvalidBegin;
        maybe_asn_type = AsnType.fromLabel(data[offset + 11 .. end_offset]);
        if (data[end_offset + 5] == '\n') break :blk end_offset + 6;
        if (data[end_offset + 5] == '\r') break :blk end_offset + 7;
        return error.MalformedFile;
    } else return error.MissingBegin;
    var end_offset = mem.indexOf(u8, data, "-----END ") orelse return error.MissingEnd;
    const asn_type = maybe_asn_type orelse return error.InvalidAsnType;

    // verify end
    {
        const start = end_offset + 9;
        const end = mem.indexOfPos(u8, data, start, "-----") orelse return error.InvalidEnd;
        const end_asn = AsnType.fromLabel(data[start..end]) orelse return error.InvalidAsnType;
        if (asn_type != end_asn) return error.MismatchingAsnType;
    }

    end_offset -= @boolToInt(data[end_offset - 1] == '\n');
    end_offset -= @boolToInt(data[end_offset - 1] == '\r');
    const content_to_decode = data[begin_offset..end_offset];
    const len = try std.base64.standard.Decoder.calcSizeForSlice(content_to_decode);
    const decoded_data = try gpa.alloc(u8, len);
    errdefer gpa.free(decoded_data);
    try std.base64.standard.Decoder.decode(decoded_data, content_to_decode);
    return Pem{
        .asn_type = asn_type,
        .content = decoded_data,
    };
}

/// Given a file path, will attempt to decode its content into a `Pem` instance.
/// Memory is owned by the caller.
pub fn fromFile(gpa: Allocator, file_path: []const u8) (DecodeError || std.base64.Error)!Pem {
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();

    const file_length = (try file.stat()).size;
    const content = try file.readToEndAlloc(gpa, file_length);
    defer gpa.free(content);

    return decode(gpa, content);
}

test "ASN.1 type CERTIFICATE" {
    const bytes =
        "-----BEGIN CERTIFICATE-----\n" ++
        "MIIBmTCCAUegAwIBAgIBKjAJBgUrDgMCHQUAMBMxETAPBgNVBAMTCEF0bGFudGlz" ++
        "MB4XDTEyMDcwOTAzMTAzOFoXDTEzMDcwOTAzMTAzN1owEzERMA8GA1UEAxMIQXRs" ++
        "YW50aXMwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAu+BXo+miabDIHHx+yquqzqNh" ++
        "Ryn/XtkJIIHVcYtHvIX+S1x5ErgMoHehycpoxbErZmVR4GCq1S2diNmRFZCRtQID" ++
        "AQABo4GJMIGGMAwGA1UdEwEB/wQCMAAwIAYDVR0EAQH/BBYwFDAOMAwGCisGAQQB" ++
        "gjcCARUDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAzA1BgNVHQEE" ++
        "LjAsgBA0jOnSSuIHYmnVryHAdywMoRUwEzERMA8GA1UEAxMIQXRsYW50aXOCASow" ++
        "CQYFKw4DAh0FAANBAKi6HRBaNEL5R0n56nvfclQNaXiDT174uf+lojzA4lhVInc0" ++
        "ILwpnZ1izL4MlI9eCSHhVQBHEp2uQdXJB+d5Byg=" ++
        "-----END CERTIFICATE-----";

    var pem = try decode(std.testing.allocator, bytes);
    defer pem.deinit(std.testing.allocator);

    try std.testing.expectEqual(AsnType.certificate, pem.asn_type);
}

test "ASN.1 type CERTIFICATE + Explanatory Text" {
    const bytes =
        "Subject: CN=Atlantis\n" ++
        "Issuer: CN=Atlantis\n" ++
        "Validity: from 7/9/2012 3:10:38 AM UTC to 7/9/2013 3:10:37 AM UTC\n" ++
        "-----BEGIN CERTIFICATE-----\n" ++
        "MIIBmTCCAUegAwIBAgIBKjAJBgUrDgMCHQUAMBMxETAPBgNVBAMTCEF0bGFudGlz" ++
        "MB4XDTEyMDcwOTAzMTAzOFoXDTEzMDcwOTAzMTAzN1owEzERMA8GA1UEAxMIQXRs" ++
        "YW50aXMwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAu+BXo+miabDIHHx+yquqzqNh" ++
        "Ryn/XtkJIIHVcYtHvIX+S1x5ErgMoHehycpoxbErZmVR4GCq1S2diNmRFZCRtQID" ++
        "AQABo4GJMIGGMAwGA1UdEwEB/wQCMAAwIAYDVR0EAQH/BBYwFDAOMAwGCisGAQQB" ++
        "gjcCARUDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAzA1BgNVHQEE" ++
        "LjAsgBA0jOnSSuIHYmnVryHAdywMoRUwEzERMA8GA1UEAxMIQXRsYW50aXOCASow" ++
        "CQYFKw4DAh0FAANBAKi6HRBaNEL5R0n56nvfclQNaXiDT174uf+lojzA4lhVInc0" ++
        "ILwpnZ1izL4MlI9eCSHhVQBHEp2uQdXJB+d5Byg=" ++
        "-----END CERTIFICATE-----";

    var pem = try decode(std.testing.allocator, bytes);
    defer pem.deinit(std.testing.allocator);

    try std.testing.expectEqual(AsnType.certificate, pem.asn_type);
}
