// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

"use strict";

import {CodeRegion} from "ext:ddsa_lib/region";
import {DDSA, DDSAPrivate} from "ext:ddsa_lib/ddsa";
import {DDSA_Console} from "ext:ddsa_lib/utility";
import {Digraph} from "ext:ddsa_lib/flow/graph";
import {FileContext} from "ext:ddsa_lib/context_file";
import {FileContextGo} from "ext:ddsa_lib/context_file_go";
import {FileContextTerraform, TerraformResource} from "ext:ddsa_lib/context_file_tf";
import {FileContextJavaScript, PackageImport} from "ext:ddsa_lib/context_file_js";
import {Fix} from "ext:ddsa_lib/fix";
import {QueryMatch} from "ext:ddsa_lib/query_match";
import {QueryMatchCompat} from "ext:ddsa_lib/query_match_compat";
import {RootContext} from "ext:ddsa_lib/context_root";
import {RuleContext} from "ext:ddsa_lib/context_rule";
import {TreeSitterFieldChildNode, TreeSitterNode} from "ext:ddsa_lib/ts_node";
import {TsLanguageContext} from "ext:ddsa_lib/context_ts_lang";
import {Violation} from "ext:ddsa_lib/violation";
// TODO(JF): These are only used by the Rust runtime, which currently expects them in global scope, but
//           these should be hidden inside another object, not `globalThis`.
globalThis.CodeRegion = CodeRegion;
globalThis.DDSA_Console = DDSA_Console;
globalThis.DDSA = DDSA;
globalThis.Digraph = Digraph;
globalThis.FileContext = FileContext;
globalThis.FileContextGo = FileContextGo;
globalThis.FileContextJavaScript = FileContextJavaScript;
globalThis.PackageImport = PackageImport;
globalThis.FileContextTerraform = FileContextTerraform;
globalThis.Fix = Fix;
globalThis.TerraformResource = TerraformResource;
globalThis.QueryMatch = QueryMatch;
globalThis.QueryMatchCompat = QueryMatchCompat;
globalThis.RootContext = RootContext;
globalThis.RuleContext = RuleContext;
globalThis.TreeSitterNode = TreeSitterNode;
globalThis.TreeSitterFieldChildNode = TreeSitterFieldChildNode;
globalThis.TsLanguageContext = TsLanguageContext;
globalThis.Violation = Violation;

///////////
// Take all exports from `stella_compat.js` and define them within this scope.
// NOTE: This is temporary scaffolding used during the transition to `ddsa_lib::JsRuntime`.
import * as stellaCompat from "ext:ddsa_lib/stella_compat";
for (const [name, obj] of Object.entries(stellaCompat)) {
    globalThis[name] = obj;
}
///////////

globalThis.console = new DDSA_Console();
globalThis.ddsa = new DDSA();
// Note: The name "private" is just used to communicate intent -- there is no enforcement preventing rules from using this.
globalThis.__ddsaPrivate__ = new DDSAPrivate();
