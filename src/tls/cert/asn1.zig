//! Decoder for the ASN.1 DER encoding rules.
//! DER encoding contains a tag, length and value for each element.
//! Note: This means it only supports DER encoding rules, not BER and CER
//! as the only use case is for X.509 support.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const BigInt = std.math.big.int.Const;
const testing = std.testing;

/// A subset of ASN.1 tag types as specified by the spec.
/// We only define the tags that are required for PEM certificates.
/// Read more at:
/// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
pub const Tag = enum(u8) {
    integer = 0x02,
    bit_string = 0x03,
    octet_string = 0x04,
    @"null" = 0x05,
    object_identifier = 0x06,
    utf8_string = 0x0C,
    printable_string = 0x13,
    ia5_string = 0x16,
    utc_time = 0x17,
    sequence = 0x30,
    set = 0x31,
    // context = 255, // Used by decoder, but is not a valid Tag.
    _,
};

/// Represents the value of an element that was encoded using ASN.1 DER encoding rules.
pub const Value = union(Tag) {
    integer: BigInt, // can represent integers up to 126 bytes.
    bit_string: BitString,
    octet_string: []const u8,
    object_identifier: struct {
        data: [16]u32,
        len: u5,
    },
    utf8_string: []const u8,
    printable_string: []const u8,
    ia5_string: []const u8,
    utc_time: []const u8,
    sequence: []const Value,
    set: []const Value,
    @"null",

    /// Frees any memory that was allocated while constructed
    /// a given `Value`
    pub fn deinit(self: Value, gpa: Allocator) void {
        switch (self) {
            .integer => |int| gpa.free(int.limbs),
            .sequence => |seq| for (seq) |val| {
                val.deinit(gpa);
            } else gpa.free(seq),
            .set => |set| for (set) |val| {
                val.deinit(gpa);
            } else gpa.free(set),
            else => {},
        }
    }
};

/// Represents a string which may contain unused bits
pub const BitString = struct {
    /// Contains the string as well as the unused bits
    data: []const u8,
    /// The total amount of bits of the string
    bit_length: u8,
};

/// Kind is a union representing each individual element
/// within a schema as to what is expected from the encoded
/// data and how to interpret the data. This allows us
/// to successfully decode asn.1 data that requires information
/// from outside what's available within the data itself.
pub const Kind = union(enum) {
    /// A regular element that should not be ignored,
    /// is mandatory, but does not require special casing.
    tag: Tag,
    /// The element could be an optional or context specific.
    /// Will decode the element according to the given `Tag`,
    /// if the id matches the upper bits of the tag byte.
    /// When the id does not match, the element will be ignored.
    context_specific: struct {
        optional: bool = false,
        id: u8,
        tag: Tag,
    },
    /// Allows the user how to decode the choice
    choice: fn (decoder: *Decoder, id: u8) Decoder.Error!Value,
    /// When the element can be ignored
    none,
};

/// Represents a series of asn.1 elements, where each
/// `Kind` describes how to decode the next element.
/// This is required in cases where the data is ambigious,
/// such as context specific or optional data and the data describing
/// the Tag of the element is omitted.
pub const Schema = []const Kind;

/// Decodes ans.1 binary data into Zig types
pub const Decoder = struct {
    /// Internal index into the data.
    /// Should not be tempered with outside the Decoder.
    index: usize,
    /// The asn.1 binary data that is being decoded by the current instance.
    data: []const u8,
    /// Allocator is used to allocate memory for limbs (as we must swap them due to endianness),
    /// as well as allocate a Value for sets and sequences.
    /// Memory can be freed easily by calling `deinit` on a `Value`.
    gpa: Allocator,
    /// A `Schema` is used to provide a list of ordered elements that tell
    /// the decoder how to decode each individual element, allowing the decoder
    /// to handle context-specific elements.
    schema: ?Schema,
    /// The index into `schema` to determine which element is being decoded.
    /// The field is not used when `schema` is `null`.
    schema_index: usize,

    pub const Error = error{
        /// Tag found is either not supported or incorrect
        InvalidTag,
        OutOfMemory,
        /// Index has reached the end of `data`'s size
        EndOfData,
        /// The length could not be decoded and is malformed
        InvalidLength,
        /// The encoded data contains context specific data,
        /// meaning we cannot infer the Tag without knowing the context.
        /// Use `usingSchema` to define a context and tell the decoder
        /// how to decode the given data.
        ContextSpecific,
    };

    const DecodeOptions = union(enum) {
        no_schema,
        with_schema: Schema,
    };

    /// Initializes a new decoder instance for the given binary data.
    /// Allows the caller to provide a `Schema` which represents the
    /// layout of the encoded data and tells the decoder how it must be decoded.
    ///
    /// Provide `.no_schema` when the data is 'simple' and requires no context-specific handling.
    pub fn init(gpa: Allocator, data: []const u8, options: DecodeOptions) Decoder {
        return .{
            .index = 0,
            .data = data,
            .gpa = gpa,
            .schema = if (options == .no_schema) null else options.with_schema,
            .schema_index = 0,
        };
    }

    /// Decodes the data, interpreting it as the given `Tag`.
    /// The decoder still verifies if the given tag is a valid tag according
    /// to the found tag-byte.
    pub fn decodeTag(self: *Decoder, tag: Tag) Error!Value {
        return try self.decodeMaybeTag(tag);
    }

    /// Decodes from the current index into `data` and returns
    /// a `Value`, representing a type based on the tag found
    /// in the encoded data.
    pub fn decode(self: *Decoder) Error!Value {
        return self.decodeMaybeTag(null);
    }

    fn decodeMaybeTag(self: *Decoder, maybe_tag: ?Tag) Error!Value {
        const tag_byte = try self.nextByte();
        const tag = std.meta.intToEnum(Tag, tag_byte) catch blk: {
            if (tag_byte & 0x80 == 0x80) {
                if (maybe_tag) |wanted_tag| break :blk wanted_tag;

                if (self.element()) |kind| {
                    switch (kind) {
                        .context_specific => |ctx| {
                            const id = @truncate(u3, tag_byte);
                            if (id == ctx.id) {
                                break :blk ctx.tag;
                            } else if (ctx.optional) {
                                self.maybeAdvanceElement();
                                self.index -= 1;
                                return @as(Value, .@"null");
                            }
                            return error.InvalidTag;
                        },
                        .choice => |callback| {
                            // decrease index to make the tag byte available again to the callback
                            self.index -= 1;
                            return callback(self, @truncate(u3, tag_byte));
                        },
                        else => return error.InvalidTag,
                    }
                }
                return error.ContextSpecific;
            }
            return error.InvalidTag;
        };
        self.maybeAdvanceElement();

        return switch (tag) {
            .bit_string => Value{ .bit_string = try self.decodeBitString() },
            .integer => Value{ .integer = try self.decodeInt() },
            .octet_string, .ia5_string, .utf8_string, .printable_string => {
                const string_value = try self.decodeString();
                return @as(Value, switch (tag) {
                    .octet_string => .{ .octet_string = string_value },
                    .ia5_string => .{ .ia5_string = string_value },
                    .utf8_string => .{ .utf8_string = string_value },
                    .printable_string => .{ .printable_string = string_value },
                    .utc_time => .{ .utc_time = string_value },
                    else => unreachable,
                });
            },
            .object_identifier => try self.decodeObjectIdentifier(),
            .sequence, .set => try self.decodeSequence(tag),
            .@"null" => try self.decodeNull(),
            else => unreachable,
        };
    }

    /// Reads the next byte from the data and increments the index.
    /// Returns error.EndOfData if reached the end of the data.
    fn nextByte(self: *Decoder) error{EndOfData}!u8 {
        if (self.index >= self.data.len) return error.EndOfData;
        defer self.index += 1;
        return self.data[self.index];
    }

    /// Returns the current element `Kind`.
    /// Will return `null` when no schema was set, or no element
    /// is present at the current index.
    ///
    /// Note: This does no bound-checking to verify the index advances
    /// past the length of elements. However, `element()` does verify this.
    fn element(self: *Decoder) ?Kind {
        if (self.schema) |schema| {
            if (self.schema_index >= schema.len) return null;
            return schema[self.schema_index];
        }
        return null;
    }

    /// When a `Schema` was set on the `Decoder`, this will
    /// advance the index, allowing us to retrieve the next element's `Kind`
    fn maybeAdvanceElement(self: *Decoder) void {
        self.schema_index += @boolToInt(self.schema != null);
    }

    /// Returns the length of the current element being decoded.
    fn findLength(self: *Decoder) error{InvalidLength}!usize {
        const first_byte = self.data[self.index];
        self.index += 1;
        if (first_byte & 0x80 == 0) {
            return first_byte; // single byte length
        }

        // The first 7 bits of the first byte contain the total
        // amount of bytes that represent the length.
        const byte_length = @truncate(u7, first_byte);
        if (byte_length > self.data[self.index..].len) return error.InvalidLength;
        if (byte_length > @sizeOf(usize)) @panic("TODO: Implement lengths larger than @sizeOf(usize))");
        const length = mem.readIntBig(usize, self.data[self.index..][0..@sizeOf(usize)]);
        self.index += byte_length;
        return length;
    }

    /// Decodes the data into a `BitString`
    pub fn decodeBitString(self: *Decoder) !BitString {
        const tag_byte = try self.nextByte();
        if (tag_byte != @enumToInt(Tag.bit_string)) {
            return error.InvalidTag;
        }
        const length = try self.findLength();
        const extra_bits = try self.nextByte();
        const total_bit_length = (length - 1) * 8 - extra_bits;
        const string_length = std.math.divCeil(usize, total_bit_length, 8) catch unreachable;
        const string = self.data[self.index..][0..string_length];
        self.index += length;
        return BitString{ .data = string, .bit_length = @intCast(u8, total_bit_length) };
    }

    /// Decodes the data into the given string tag.
    /// If the expected data contains a bit string, use `decodeBitString`.
    pub fn decodeString(self: *Decoder) ![]const u8 {
        const length = try self.findLength();
        defer self.index += length;
        return self.data[self.index..][0..length];
    }

    /// Decodes an integer value, while allocating the memory for the limbs
    /// as we must ensure the endianness is correct.
    /// BigInt expects LE bytes, whereas certificates are BE.
    pub fn decodeInt(self: *Decoder) !BigInt {
        const length = try self.findLength();
        const byte = try self.nextByte();
        const is_positive = byte == 0x00 and length > 1;
        const actual_length = length - @boolToInt(is_positive);

        const limb_count = std.math.divCeil(usize, actual_length, @sizeOf(usize)) catch unreachable;
        const limbs = try self.gpa.alloc(usize, limb_count);
        errdefer self.gpa.free(limbs);
        mem.set(usize, limbs, 0);

        const limb_bytes = @ptrCast([*]u8, limbs.ptr)[0..actual_length];
        if (is_positive) {
            mem.copy(u8, limb_bytes, self.data[self.index..][0..actual_length]);
        } else {
            mem.copy(u8, limb_bytes[1..], self.data[self.index - 1 ..][1..actual_length]);
            limb_bytes[0] = byte & ~@as(u8, 0x80);
        }

        mem.reverse(u8, limb_bytes);
        self.index += length - 1;
        return BigInt{
            .limbs = limbs,
            .positive = is_positive or byte & 0x80 == 0x00,
        };
    }

    /// Decodes data into an object identifier
    pub fn decodeObjectIdentifier(self: *Decoder) !Value {
        const length = try self.findLength();
        const initial_byte = try self.nextByte();
        var identifier = Value{ .object_identifier = .{ .data = undefined, .len = 0 } };
        identifier.object_identifier.data[0] = initial_byte / 40;
        identifier.object_identifier.data[1] = initial_byte % 40;

        var out_idx: u5 = 2;
        var index: usize = 0;
        while (index < length - 1) {
            var current: u32 = 0;
            var current_byte = try self.nextByte();
            index += 1;
            while (current_byte & 0x80 == 0x80) : (index += 1) {
                current *= 128;
                current += @as(u32, current_byte & ~@as(u8, 0x80)) * 128;
                current_byte = try self.nextByte();
            } else {
                current += current_byte;
            }
            identifier.object_identifier.data[out_idx] = current;
            out_idx += 1;
        }
        identifier.object_identifier.len = out_idx;
        self.index += length;
        return identifier;
    }

    /// Decodes either a sequence of/set of into a `Value`
    /// Allocates memory for the list of `Value`.
    pub fn decodeSequence(self: *Decoder, tag: Tag) !Value {
        const length = try self.findLength();
        var value_list = std.ArrayList(Value).init(self.gpa);
        errdefer for (value_list.items) |val| {
            val.deinit(self.gpa);
        } else value_list.deinit();

        while (self.index < length) {
            const value = try self.decode();
            errdefer value.deinit(self.gpa);
            try value_list.append(value);
        }

        const final_list = value_list.toOwnedSlice();
        return switch (tag) {
            .sequence => Value{ .sequence = final_list },
            .set => Value{ .sequence = final_list },
            else => unreachable,
        };
    }

    /// Decodes the data into a `@"null"` `Value`
    /// and verifies the length is '0'.
    pub fn decodeNull(self: *Decoder) !Value {
        const length = try self.findLength();
        if (length != 0) return error.InvalidLength;
        return .@"null";
    }
};

test "Decode int" {
    const bytes: []const u8 = &.{ 0x02, 0x09, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    var decoder = Decoder.init(testing.allocator, bytes, .no_schema);
    const value = try decoder.decode();
    defer value.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, (1 << 63) + 1), try value.integer.to(u64));
}

test "Octet string" {
    const bytes: []const u8 = &.{ 0x04, 0x04, 0x03, 0x02, 0x06, 0xA0 };
    var decoder = Decoder.init(testing.allocator, bytes, .no_schema);
    const value = try decoder.decode();
    defer value.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, bytes[2..], value.octet_string);
}

test "Object identifier" {
    const bytes: []const u8 = &.{ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b };
    var decoder = Decoder.init(testing.allocator, bytes, .no_schema);
    const value = try decoder.decode();
    defer value.deinit(testing.allocator);
    try testing.expectEqual(@as(u5, 7), value.object_identifier.len);
    try testing.expectEqualSlices(u32, &.{
        1, 2, 840, 113549, 1, 1, 11,
    }, value.object_identifier.data[0..value.object_identifier.len]);
}

test "Printable string" {
    const bytes: []const u8 = &.{ 0x13, 0x02, 0x68, 0x69 };
    var decoder = Decoder.init(testing.allocator, bytes, .no_schema);
    const value = try decoder.decode();
    defer value.deinit(testing.allocator);
    try testing.expectEqualStrings("hi", value.printable_string);
}

test "Utf8 string" {
    const bytes: []const u8 = &.{ 0x0c, 0x04, 0xf0, 0x9f, 0x98, 0x8e };
    var decoder = Decoder.init(testing.allocator, bytes, .no_schema);
    const value = try decoder.decode();
    defer value.deinit(testing.allocator);
    try testing.expectEqualStrings("😎", value.utf8_string);
}

test "Sequence of" {
    const bytes: []const u8 = &.{ 0x30, 0x09, 0x02, 0x01, 0x07, 0x02, 0x01, 0x08, 0x02, 0x01, 0x09 };
    var decoder = Decoder.init(testing.allocator, bytes, .no_schema);
    const value = try decoder.decode();
    defer value.deinit(testing.allocator);

    const expected: []const u8 = &.{ 7, 8, 9 };
    try testing.expectEqual(expected.len, value.sequence.len);
    for (expected) |expected_value, index| {
        try testing.expectEqual(expected_value, try value.sequence[index].integer.to(u8));
    }
}

test "Choice" {
    const bytes: []const u8 = &.{ 0x82, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d };

    const callback = struct {
        fn decode(decoder: *Decoder, id: u8) Decoder.Error!Value {
            if (id != 2) return error.InvalidTag;
            return try decoder.decodeTag(.ia5_string);
        }
    }.decode;

    var decoder = Decoder.init(
        testing.allocator,
        bytes,
        .{
            .with_schema = &.{
                .{
                    .choice = callback,
                },
            },
        },
    );
    const value = try decoder.decode();
    defer value.deinit(testing.allocator);

    try testing.expectEqualStrings("example.com", value.ia5_string);
}

test "Optional" {
    const bytes: []const u8 = &.{ 0x30, 0x03, 0x80, 0x01, 0x09 };

    var decoder = Decoder.init(testing.allocator, bytes, .{ .with_schema = &.{
        .{ .tag = .sequence }, .{ .context_specific = .{ .id = 0x0, .tag = .integer } },
    } });
    const value = try decoder.decode();
    defer value.deinit(testing.allocator);

    try testing.expectEqual(@as(u8, 9), try value.sequence[0].integer.to(u8));
}

test "Optional with null" {
    const bytes: []const u8 = &.{ 0x30, 0x03, 0x81, 0x01, 0x09 };

    var decoder = Decoder.init(testing.allocator, bytes, .{
        .with_schema = &.{
            .{ .tag = .sequence },
            .{ .context_specific = .{ .optional = true, .id = 0x0, .tag = .integer } },
            .{ .context_specific = .{ .optional = true, .id = 0x1, .tag = .integer } },
        },
    });
    const value = try decoder.decode();
    defer value.deinit(testing.allocator);

    try testing.expect(value.sequence.len == 2);
    try testing.expect(value.sequence[0] == .@"null");
    try testing.expectEqual(@as(u8, 9), try value.sequence[1].integer.to(u8));
}
