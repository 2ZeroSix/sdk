// Copyright (c) 2016, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

library front_end.compiler_options;

import 'package:_fe_analyzer_shared/src/messages/diagnostic_message.dart'
    show DiagnosticMessageHandler;

import 'package:kernel/default_language_version.dart' as kernel
    show defaultLanguageVersion;

import 'package:kernel/target/targets.dart' show Target;

import '../base/nnbd_mode.dart';

import 'experimental_flags.dart'
    show
        defaultExperimentalFlags,
        ExperimentalFlag,
        expiredExperimentalFlags,
        parseExperimentalFlag;

import 'file_system.dart' show FileSystem;

import 'standard_file_system.dart' show StandardFileSystem;

import '../api_unstable/util.dart';

export 'package:_fe_analyzer_shared/src/messages/diagnostic_message.dart'
    show DiagnosticMessage;

/// Front-end options relevant to compiler back ends.
///
/// Not intended to be implemented or extended by clients.
class CompilerOptions {
  /// The URI of the root of the Dart SDK (typically a "file:" URI).
  ///
  /// If `null`, the SDK will be searched for using
  /// [Platform.resolvedExecutable] as a starting point.
  Uri sdkRoot;

  /// Uri to a platform libraries specification file.
  ///
  /// A libraries specification file is a JSON file that describes how to map
  /// `dart:*` libraries to URIs in the underlying [fileSystem].  See
  /// `package:front_end/src/base/libraries_specification.dart` for details on
  /// the format.
  ///
  /// If a value is not specified and `compileSdk = true`, the compiler will
  /// infer at a default location under [sdkRoot], typically under
  /// `lib/libraries.json`.
  Uri librariesSpecificationUri;

  DiagnosticMessageHandler onDiagnostic;

  /// URI of the ".dart_tool/package_config.json" or ".packages" file
  /// (typically a "file:" URI).
  ///
  /// If a ".packages" file is given and a ".dart_tool/package_config.json" file
  /// exists next to it, the ".dart_tool/package_config.json" file is used
  /// instead.
  ///
  /// If `null`, the file will be found via the standard package_config search
  /// algorithm.
  ///
  /// If the URI's path component is empty (e.g. `new Uri()`), no packages file
  /// will be used.
  Uri packagesFileUri;

  /// URIs of additional dill files.
  ///
  /// These will be loaded and linked into the output.
  ///
  /// The components provided here should be closed: any libraries that they
  /// reference should be defined in a component in [additionalDills] or
  /// [sdkSummary].
  List<Uri> additionalDills = [];

  /// URI of the SDK summary file (typically a "file:" URI).
  ///
  /// This should should be a summary previously generated by this package (and
  /// not the similarly named summary files from `package:analyzer`.)
  ///
  /// If `null` and [compileSdk] is false, the SDK summary will be searched for
  /// at a default location within [sdkRoot].
  Uri sdkSummary;

  /// The declared variables for use by configurable imports and constant
  /// evaluation.
  Map<String, String> declaredVariables;

  /// The [FileSystem] which should be used by the front end to access files.
  ///
  /// All file system access performed by the front end goes through this
  /// mechanism, with one exception: if no value is specified for
  /// [packagesFileUri], the packages file is located using the actual physical
  /// file system.  TODO(paulberry): fix this.
  FileSystem fileSystem = StandardFileSystem.instance;

  /// Whether to generate code for the SDK.
  ///
  /// By default the front end resolves components using a prebuilt SDK summary.
  /// When this option is `true`, [sdkSummary] must be null.
  bool compileSdk = false;

  @Deprecated("Unused internally.")
  bool chaseDependencies;

  /// Patch files to apply on the core libraries for a specific target platform.
  ///
  /// Keys in the map are the name of the library with no `dart:` prefix, for
  /// example:
  ///
  ///      {'core': [
  ///         'file:///location/of/core/patch_file1.dart',
  ///         'file:///location/of/core/patch_file2.dart',
  ///         ]}
  ///
  /// The values can be either absolute or relative URIs. Absolute URIs are read
  /// directly, while relative URIs are resolved from the [sdkRoot].
  // TODO(sigmund): provide also a flag to load this data from a file (like
  // libraries.json)
  @Deprecated("Unused internally.")
  Map<String, List<Uri>> targetPatches = <String, List<Uri>>{};

  /// Enable or disable experimental features. Features mapping to `true` are
  /// explicitly enabled. Features mapping to `false` are explicitly disabled.
  /// Features not mentioned in the map will have their default value.
  Map<ExperimentalFlag, bool> experimentalFlags = <ExperimentalFlag, bool>{};

  /// Environment map used when evaluating `bool.fromEnvironment`,
  /// `int.fromEnvironment` and `String.fromEnvironment` during constant
  /// evaluation. If the map is `null`, all environment constants will be left
  /// unevaluated and can be evaluated by a constant evaluator later.
  Map<String, String> environmentDefines = null;

  /// Report an error if a constant could not be evaluated (either because it
  /// is an environment constant and no environment was specified, or because
  /// it refers to a constructor or variable initializer that is not available).
  bool errorOnUnevaluatedConstant = false;

  /// The target platform that will consume the compiled code.
  ///
  /// Used to provide platform-specific details to the compiler like:
  ///   * the set of libraries are part of a platform's SDK (e.g. dart:html for
  ///     dart2js, dart:ui for flutter).
  ///
  ///   * what kernel transformations should be applied to the component
  ///     (async/await, mixin inlining, etc).
  ///
  ///   * how to deal with non-standard features like `native` extensions.
  ///
  /// If not specified, the default target is the VM.
  Target target;

  /// Deprecated. Has no affect on front-end.
  // TODO(dartbug.com/37514) Remove this field once DDK removes its uses of it.
  @Deprecated("Unused internally.")
  bool enableAsserts = false;

  /// Whether to show verbose messages (mainly for debugging and performance
  /// tracking).
  ///
  /// Messages are printed on stdout.
  // TODO(sigmund): improve the diagnostics API to provide mechanism to
  // intercept verbose data (Issue #30056)
  bool verbose = false;

  /// Whether to run extra verification steps to validate that compiled
  /// components are well formed.
  ///
  /// Errors are reported via the [onDiagnostic] callback.
  bool verify = false;

  /// Whether to dump generated components in a text format (also mainly for
  /// debugging).
  ///
  /// Dumped data is printed in stdout.
  bool debugDump = false;

  /// Whether to omit the platform when serializing the result from a `fasta
  /// compile` run.
  bool omitPlatform = false;

  /// Whether to set the exit code to non-zero if any problem (including
  /// warning, etc.) is encountered during compilation.
  bool setExitCodeOnProblem = false;

  /// Whether to embed the input sources in generated kernel components.
  ///
  /// The kernel `Component` API includes a `uriToSource` map field that is used
  /// to embed the entire contents of the source files. This part of the kernel
  /// API is in flux and it is not necessary for some tools. Today it is used
  /// for translating error locations and stack traces in the VM.
  // TODO(sigmund): change the default.
  bool embedSourceText = true;

  /// Whether the compiler should throw as soon as it encounters a
  /// compilation error.
  ///
  /// Typically used by developers to debug internals of the compiler.
  bool throwOnErrorsForDebugging = false;

  /// Whether the compiler should throw as soon as it encounters a
  /// compilation warning.
  ///
  /// Typically used by developers to debug internals of the compiler.
  bool throwOnWarningsForDebugging = false;

  /// For the [throwOnErrorsForDebugging] or [throwOnWarningsForDebugging]
  /// options, skip this number of otherwise fatal diagnostics without throwing.
  /// I.e. the default value of 0 means throw on the first fatal diagnostic.
  ///
  /// If the value is negative, print a stack trace for every fatal
  /// diagnostic, but do not stop the compilation.
  int skipForDebugging = 0;

  /// Whether to generate bytecode.
  bool bytecode = false;

  /// Whether to write a file (e.g. a dill file) when reporting a crash.
  bool writeFileOnCrashReport = true;

  /// Whether nnbd weak, strong or agnostic mode is used if experiment
  /// 'non-nullable' is enabled.
  NnbdMode nnbdMode = NnbdMode.Weak;

  /// The current sdk version string, e.g. "2.6.0-edge.sha1hash".
  /// For instance used for language versioning (specifying the maximum
  /// version).
  String currentSdkVersion = "${kernel.defaultLanguageVersion.major}"
      "."
      "${kernel.defaultLanguageVersion.minor}";

  bool equivalent(CompilerOptions other,
      {bool ignoreOnDiagnostic: true,
      bool ignoreVerbose: true,
      bool ignoreVerify: true,
      bool ignoreDebugDump: true}) {
    if (sdkRoot != other.sdkRoot) return false;
    if (librariesSpecificationUri != other.librariesSpecificationUri) {
      return false;
    }
    if (!ignoreOnDiagnostic) {
      if (onDiagnostic != other.onDiagnostic) return false;
    }
    if (packagesFileUri != other.packagesFileUri) return false;
    if (!equalLists(additionalDills, other.additionalDills)) return false;
    if (sdkSummary != other.sdkSummary) return false;
    if (!equalMaps(declaredVariables, other.declaredVariables)) return false;
    if (fileSystem != other.fileSystem) return false;
    if (compileSdk != compileSdk) return false;
    // chaseDependencies aren't used anywhere, so ignored here.
    // targetPatches aren't used anywhere, so ignored here.
    if (!equalMaps(experimentalFlags, other.experimentalFlags)) return false;
    if (!equalMaps(environmentDefines, other.environmentDefines)) return false;
    if (errorOnUnevaluatedConstant != other.errorOnUnevaluatedConstant) {
      return false;
    }
    if (target != other.target) {
      if (target.runtimeType != other.target.runtimeType) return false;
      if (target.name != other.target.name) return false;
      if (target.flags != other.target.flags) return false;
    }
    // enableAsserts is not used anywhere, so ignored here.
    if (!ignoreVerbose) {
      if (verbose != other.verbose) return false;
    }
    if (!ignoreVerify) {
      if (verify != other.verify) return false;
    }
    if (!ignoreDebugDump) {
      if (debugDump != other.debugDump) return false;
    }
    if (omitPlatform != other.omitPlatform) return false;
    if (setExitCodeOnProblem != other.setExitCodeOnProblem) return false;
    if (embedSourceText != other.embedSourceText) return false;
    if (throwOnErrorsForDebugging != other.throwOnErrorsForDebugging) {
      return false;
    }
    if (throwOnWarningsForDebugging != other.throwOnWarningsForDebugging) {
      return false;
    }
    if (skipForDebugging != other.skipForDebugging) return false;
    if (bytecode != other.bytecode) return false;
    if (writeFileOnCrashReport != other.writeFileOnCrashReport) return false;
    if (nnbdMode != other.nnbdMode) return false;
    if (currentSdkVersion != other.currentSdkVersion) return false;

    return true;
  }
}

/// Parse experimental flag arguments of the form 'flag' or 'no-flag' into a map
/// from 'flag' to `true` or `false`, respectively.
Map<String, bool> parseExperimentalArguments(List<String> arguments) {
  Map<String, bool> result = {};
  if (arguments != null) {
    for (String argument in arguments) {
      for (String feature in argument.split(',')) {
        if (feature.startsWith('no-')) {
          result[feature.substring(3)] = false;
        } else {
          result[feature] = true;
        }
      }
    }
  }
  return result;
}

/// Parse a map of experimental flags to values that can be passed to
/// [CompilerOptions.experimentalFlags].
/// The returned map is normalized to contain default values for unmentioned
/// flags.
///
/// If an unknown flag is mentioned, or a flag is mentioned more than once,
/// the supplied error handler is called with an error message.
///
/// If an expired flag is set to its non-default value the supplied error
/// handler is called with an error message.
///
/// If an expired flag is set to its default value the supplied warning
/// handler is called with a warning message.
Map<ExperimentalFlag, bool> parseExperimentalFlags(
    Map<String, bool> experiments,
    {void onError(String message),
    void onWarning(String message)}) {
  Map<ExperimentalFlag, bool> flags = <ExperimentalFlag, bool>{};
  if (experiments != null) {
    for (String experiment in experiments.keys) {
      bool value = experiments[experiment];
      ExperimentalFlag flag = parseExperimentalFlag(experiment);
      if (flag == null) {
        onError("Unknown experiment: " + experiment);
      } else if (flags.containsKey(flag)) {
        if (flags[flag] != value) {
          onError(
              "Experiment specified with conflicting values: " + experiment);
        }
      } else {
        if (expiredExperimentalFlags[flag]) {
          if (value != defaultExperimentalFlags[flag]) {
            /// Produce an error when the value is not the default value.
            if (value) {
              onError("Enabling experiment " +
                  experiment +
                  " is no longer supported.");
            } else {
              onError("Disabling experiment " +
                  experiment +
                  " is no longer supported.");
            }
            value = defaultExperimentalFlags[flag];
          } else if (onWarning != null) {
            /// Produce a warning when the value is the default value.
            if (value) {
              onWarning("Experiment " +
                  experiment +
                  " is enabled by default. "
                      "The use of the flag is deprecated.");
            } else {
              onWarning("Experiment " +
                  experiment +
                  " is disabled by default. "
                      "The use of the flag is deprecated.");
            }
          }
          flags[flag] = value;
        } else {
          flags[flag] = value;
        }
      }
    }
  }
  for (ExperimentalFlag flag in ExperimentalFlag.values) {
    assert(defaultExperimentalFlags.containsKey(flag),
        "No default value for $flag.");
    flags[flag] ??= defaultExperimentalFlags[flag];
  }
  return flags;
}
