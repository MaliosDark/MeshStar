/// Gallery picking is optional and needs the `image_picker` plugin, which
/// requires network access at build time (Kotlin/AGP artifacts), so the
/// default offline build ships without it and uses bundled sample images.
///
/// To enable real gallery picking on an ONLINE build:
///   1. Add to pubspec.yaml under dependencies:  image_picker: ^1.1.2
///   2. Replace the body of [pickThumbnail] below with:
///
///        import 'package:image_picker/image_picker.dart';
///        import '../protocol/thumb.dart' as th;
///        ...
///        final x = await ImagePicker().pickImage(
///          source: ImageSource.gallery, maxWidth: 256, maxHeight: 256);
///        if (x == null) return null;
///        final img = await decodeImageFromList(await x.readAsBytes());
///        return th.encodeFromImage(img, edge: 40);
///
/// The rest of the app (encode, send, receive, display, profile photos)
/// already works, only the source of the pixels changes.
library;

import 'dart:typed_data';

/// Returns thumbnail bytes for a picked gallery image, or null. The offline
/// build has no gallery plugin, so this returns null and callers fall back
/// to the bundled sample images.
Future<Uint8List?> pickThumbnail() async => null;

/// Whether real gallery picking is compiled in.
const bool galleryAvailable = false;
