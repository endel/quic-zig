const std = @import("std");
const os = std.os;
const io = std.io;

const packet = @import("../packet.zig");

///
///
pub fn generateRetryToken(
    header: packet.Header,
    new_scid: [packet.CONNECTION_ID_MAX_SIZE]u8,
    addr: os.sockaddr,
) ![]u8 {
    _ = header;
    _ = addr;

    var buf: [512]u8 = undefined;
    var stream = io.fixedBufferStream(&buf);
    var writer = stream.writer();

    try writer.writeAll(encodeAddr(addr));

    // original destination connection id
    try writer.writeByte(@intCast(u8, header.dcid.len));
    try writer.writeAll(header.dcid);

    try writer.writeByte(@intCast(u8, new_scid.len));
    try writer.writeAll(&new_scid);

    return stream.getWritten();

    // buf = Buffer(capacity=512)
    // push_opaque(buf, 1, encode_address(addr))
    // push_opaque(buf, 1, original_destination_connection_id)
    // push_opaque(buf, 1, retry_source_connection_id)
    // return self._key.public_key().encrypt(
    //     buf.data,
    //     padding.OAEP(
    //         mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
    //     ),
    // )

    // data, err := asn1.Marshal(token{
    //     IsRetryToken:             true,
    //     RemoteAddr:               encodeRemoteAddr(raddr),
    //     OriginalDestConnectionID: origDestConnID.Bytes(),
    //     RetrySrcConnectionID:     retrySrcConnID.Bytes(),
    //     Timestamp:                time.Now().UnixNano(),
    // })
    // if err != nil {
    //     return nil, err
    // }
    // return g.tokenProtector.NewToken(data)
}

pub fn defaultTokenValidator(token: []u8, addr: os.sockaddr) bool {
    _ = token;
    _ = addr;
    return true;
}

fn encodeAddr(addr: os.sockaddr) []const u8 {
    return switch (addr.family) {
        os.AF.INET => &addr.data,
        os.AF.INET6 => &addr.data,
        else => unreachable,
    };
}
