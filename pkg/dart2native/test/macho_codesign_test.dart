// Copyright (c) 2026, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:dart2native/macho_codesign.dart';
import 'package:test/test.dart';

/// The fixture is arm64, where signing uses 16 KiB pages.
const _pageSize = 16384;
const _hashSize = 32;

const _lcSegment64 = 0x19;
const _lcCodeSignature = 0x1d;
const _lcUuid = 0x1b;

/// Builds a Mach-O just real enough to sign: a `__LINKEDIT` segment whose tail
/// is reserved for the signature, and the `LC_CODE_SIGNATURE` that points at
/// it. The bytes before `__LINKEDIT` stand in for the loadable image.
Uint8List _syntheticMachO({
  required int imageSize,
  required int reservedSignatureSize,
  Uint8List? uuid,
}) {
  const headerSize = 32;
  const segmentCommandSize = 72;
  const signatureCommandSize = 16;
  const uuidCommandSize = 24;
  final commandsSize =
      segmentCommandSize +
      signatureCommandSize +
      (uuid == null ? 0 : uuidCommandSize);
  final linkEditOffset = imageSize;
  final signatureOffset = linkEditOffset + 64;
  final total = signatureOffset + reservedSignatureSize;

  final bytes = Uint8List(total);
  final data = ByteData.sublistView(bytes);

  data.setUint32(0, 0xfeedfacf, Endian.little); // 64-bit magic
  data.setUint32(4, 0x0100000c, Endian.little); // CPU_TYPE_ARM64
  data.setUint32(8, 0, Endian.little);
  data.setUint32(12, 2, Endian.little); // MH_EXECUTE
  data.setUint32(16, uuid == null ? 2 : 3, Endian.little); // ncmds
  data.setUint32(20, commandsSize, Endian.little);
  data.setUint32(24, 0, Endian.little); // flags

  var offset = headerSize;
  data.setUint32(offset, _lcSegment64, Endian.little);
  data.setUint32(offset + 4, segmentCommandSize, Endian.little);
  bytes.setRange(offset + 8, offset + 8 + 10, '__LINKEDIT'.codeUnits);
  data.setUint64(offset + 32, _pageSize, Endian.little); // vmsize
  data.setUint64(offset + 40, linkEditOffset, Endian.little); // fileoff
  data.setUint64(offset + 48, total - linkEditOffset, Endian.little);
  offset += segmentCommandSize;

  data.setUint32(offset, _lcCodeSignature, Endian.little);
  data.setUint32(offset + 4, signatureCommandSize, Endian.little);
  data.setUint32(offset + 8, signatureOffset, Endian.little);
  data.setUint32(offset + 12, reservedSignatureSize, Endian.little);
  offset += signatureCommandSize;

  if (uuid != null) {
    data.setUint32(offset, _lcUuid, Endian.little);
    data.setUint32(offset + 4, uuidCommandSize, Endian.little);
    bytes.setRange(offset + 8, offset + 24, uuid);
    offset += uuidCommandSize;
  }

  // Fill the image with something that is not all zeroes, so a digest computed
  // over the wrong range is unlikely to accidentally match.
  for (var i = headerSize + commandsSize; i < linkEditOffset; i++) {
    bytes[i] = i & 0xff;
  }
  return bytes;
}

/// Reads back the pieces of an embedded signature the assertions care about.
({
  int codeLimit,
  int flags,
  int codeSlots,
  int hashOffset,
  int specialSlots,
  String identifier,
  Uint8List codeDirectory,
  int superBlobLength,
  int pageSizeLog2,
})
_parse(Uint8List signed) {
  final data = ByteData.sublistView(signed);
  final commandCount = data.getUint32(16, Endian.little);
  var offset = 32;
  var signatureOffset = -1;
  for (var i = 0; i < commandCount; i++) {
    final command = data.getUint32(offset, Endian.little);
    if (command == _lcCodeSignature) {
      signatureOffset = data.getUint32(offset + 8, Endian.little);
    }
    offset += data.getUint32(offset + 4, Endian.little);
  }
  expect(signatureOffset, isNot(-1));

  expect(
    data.getUint32(signatureOffset),
    0xfade0cc0,
    reason: 'superblob magic',
  );
  final superBlobLength = data.getUint32(signatureOffset + 4);
  final blobCount = data.getUint32(signatureOffset + 8);

  var codeDirectoryOffset = -1;
  for (var i = 0; i < blobCount; i++) {
    final slot = data.getUint32(signatureOffset + 12 + 8 * i);
    if (slot == 0) {
      codeDirectoryOffset =
          signatureOffset + data.getUint32(signatureOffset + 16 + 8 * i);
    }
  }
  expect(codeDirectoryOffset, isNot(-1), reason: 'code directory present');

  final cdLength = data.getUint32(codeDirectoryOffset + 4);
  final cd = Uint8List.sublistView(
    signed,
    codeDirectoryOffset,
    codeDirectoryOffset + cdLength,
  );
  final cdData = ByteData.sublistView(cd);
  expect(cdData.getUint32(0), 0xfade0c02, reason: 'code directory magic');

  final identifierOffset = cdData.getUint32(20);
  return (
    pageSizeLog2: cdData.getUint8(39),
    codeLimit: cdData.getUint32(32),
    flags: cdData.getUint32(12),
    codeSlots: cdData.getUint32(28),
    hashOffset: cdData.getUint32(16),
    specialSlots: cdData.getUint32(24),
    identifier: String.fromCharCodes(
      cd,
      identifierOffset,
      cd.indexOf(0, identifierOffset),
    ),
    codeDirectory: cd,
    superBlobLength: superBlobLength,
  );
}

void main() {
  group('adHocSignMachOBytes', () {
    test('digests every page up to the signature', () {
      final image = _syntheticMachO(
        imageSize: 3 * _pageSize,
        reservedSignatureSize: 4096,
      );
      final signed = adHocSignMachOBytes(image, identifier: 'hello');
      final signature = _parse(signed);

      // The signature always sits last, so everything before it is signed.
      expect(
        signature.codeLimit % _pageSize,
        isNot(0),
        reason: 'this fixture deliberately ends mid-page',
      );
      expect(
        signature.codeSlots,
        (signature.codeLimit + _pageSize - 1) ~/ _pageSize,
      );

      for (var slot = 0; slot < signature.codeSlots; slot++) {
        final start = slot * _pageSize;
        final end = start + _pageSize > signature.codeLimit
            ? signature.codeLimit
            : start + _pageSize;
        final expected = sha256
            .convert(Uint8List.sublistView(signed, start, end))
            .bytes;
        final actual = Uint8List.sublistView(
          signature.codeDirectory,
          signature.hashOffset + slot * _hashSize,
          signature.hashOffset + (slot + 1) * _hashSize,
        );
        expect(actual, expected, reason: 'digest of page $slot');
      }
    });

    test('hashes arm64 in 16 KiB pages, like codesign', () {
      final signed = adHocSignMachOBytes(
        _syntheticMachO(imageSize: 3 * _pageSize, reservedSignatureSize: 4096),
        identifier: 'hello',
      );
      expect(_parse(signed).pageSizeLog2, 14);
    });

    test('derives an identifier from LC_UUID when none is given', () {
      final signed = adHocSignMachOBytes(
        _syntheticMachO(
          imageSize: _pageSize,
          reservedSignatureSize: 4096,
          uuid: Uint8List.fromList(List.generate(16, (i) => i)),
        ),
        name: 'prog',
      );
      // "UUID" followed by the LC_UUID payload, hex encoded -- the shape `ld`
      // uses for a binary it signs itself.
      expect(
        _parse(signed).identifier,
        'prog-55554944000102030405060708090a0b0c0d0e0f',
      );
    });

    test('marks the signature ad-hoc and linker-signed', () {
      final signed = adHocSignMachOBytes(
        _syntheticMachO(imageSize: _pageSize, reservedSignatureSize: 4096),
        identifier: 'hello',
      );
      expect(_parse(signed).flags, 0x2 | 0x20000);
    });

    test('uses the requested identifier', () {
      final signed = adHocSignMachOBytes(
        _syntheticMachO(imageSize: _pageSize, reservedSignatureSize: 4096),
        identifier: 'my-binary',
      );
      expect(_parse(signed).identifier, 'my-binary');
    });

    test('reuses the reserved signature area when it is big enough', () {
      final image = _syntheticMachO(
        imageSize: 2 * _pageSize,
        reservedSignatureSize: 200000,
      );
      final signed = adHocSignMachOBytes(image, identifier: 'hello');
      // codesign leaves the linker's reserved area alone, which keeps room for
      // a later re-signing with a real identity, whose CMS blob is far larger.
      expect(signed.length, image.length);
    });

    test('grows the file when the reserved area is too small', () {
      // Too little reserved room: the file and __LINKEDIT must both be
      // extended, or the loader reads past the end of the file.
      final image = _syntheticMachO(
        imageSize: 2 * _pageSize,
        reservedSignatureSize: 16,
      );
      final signed = adHocSignMachOBytes(image, identifier: 'hello');
      final signature = _parse(signed);

      expect(signed.length, greaterThan(image.length));
      expect(
        signature.codeLimit + signature.superBlobLength,
        lessThanOrEqualTo(signed.length),
      );

      final data = ByteData.sublistView(signed);
      final linkEditFileOffset = data.getUint64(32 + 40, Endian.little);
      final linkEditFileSize = data.getUint64(32 + 48, Endian.little);
      expect(
        linkEditFileOffset + linkEditFileSize,
        signed.length,
        reason: '__LINKEDIT must end exactly at the end of the file',
      );

      final signatureOffset = data.getUint32(32 + 72 + 8, Endian.little);
      final signatureSize = data.getUint32(32 + 72 + 12, Endian.little);
      expect(
        signatureOffset + signatureSize,
        signed.length,
        reason: 'the signature must end exactly at the end of the file',
      );
    });

    test('rejects a binary with no LC_CODE_SIGNATURE', () {
      final image = _syntheticMachO(
        imageSize: _pageSize,
        reservedSignatureSize: 4096,
      );
      // Drop the signature command by claiming there is only one.
      ByteData.sublistView(image).setUint32(16, 1, Endian.little);
      expect(
        () => adHocSignMachOBytes(image, identifier: 'hello'),
        throwsA(isA<FormatException>()),
      );
    });

    test('rejects a file that is not a 64-bit Mach-O', () {
      expect(
        () => adHocSignMachOBytes(Uint8List(64), identifier: 'hello'),
        throwsA(isA<FormatException>()),
      );
    });
  });
}
