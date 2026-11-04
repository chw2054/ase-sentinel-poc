"use strict";

const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { PassThrough } = require("node:stream");
const test = require("node:test");
const vm = require("node:vm");

test("activation reads incidents with a POSIX virtual environment", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ase-vscode-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const webapp = path.join(root, "webapp");
  fs.mkdirSync(path.join(webapp, "ase_sentinel_ops"), { recursive: true });
  fs.writeFileSync(path.join(webapp, "ase_sentinel_ops", "__main__.py"), "");
  fs.mkdirSync(path.join(webapp, ".venv", "bin"), { recursive: true });
  const python = path.join(webapp, ".venv", "bin", "python");
  fs.writeFileSync(python, "");
  const settings = {
    subscriptionId: "11111111-2222-3333-4444-555555555555",
    resourceGroup: "rg-test",
    workspaceName: "sentinel-test",
    wafPolicyResourceId: "/subscriptions/test/policy",
  };
  const views = {};
  const calls = [];
  const disposable = { dispose() {} };
  const vscode = {
    EventEmitter: class { event() {} fire() {} },
    TreeItem: class { constructor(label) { this.label = label; } },
    TreeItemCollapsibleState: { None: 0, Expanded: 2 },
    StatusBarAlignment: { Left: 1 },
    window: {
      createTreeView(id, options) {
        views[id] = options.treeDataProvider;
        return disposable;
      },
      createStatusBarItem: () => ({ show() {}, dispose() {} }),
    },
    commands: { registerCommand: () => disposable },
    authentication: {
      getSession: async () => ({ account: { label: "test" }, accessToken: "test-token" }),
      onDidChangeSessions: () => disposable,
    },
    workspace: {
      workspaceFolders: [{ uri: { fsPath: root } }],
      getConfiguration: () => ({ get: (key) => settings[key] }),
      onDidChangeConfiguration: () => disposable,
    },
  };
  function spawn(executable, args, options) {
    calls.push({ executable, args, options });
    const child = new EventEmitter();
    child.stdin = new PassThrough();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = () => {};
    child.stdin.on("finish", () => {
      assert.equal(child.stdin.read().toString(), "test-token\n");
      child.stdout.end(JSON.stringify(args.at(-1) === "list"
        ? { incidents: [{ id: "incident", number: "7", title: "Probe", ips: ["203.0.113.1"] }] }
        : { policies: [{ rules: [{ name: "SentinelAutoBlock", values: ["203.0.113.2"] }] }] }));
      child.emit("close", 0);
    });
    return child;
  }
  const context = {
    module: { exports: {} }, process, setTimeout, clearTimeout,
    require: (name) => name === "vscode" ? vscode
      : name === "child_process" ? { spawn } : require(name),
  };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../src/extension.js"), "utf8"), context);
  context.module.exports.activate({ subscriptions: [] });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(calls.length, 2, "both read commands should run without a configured Python path");
  assert.ok(calls.every((call) => call.executable === python));
  assert.equal(views["aseSentinel.incidents"].getChildren()[0].label, "#7 Probe");
  const rule = views["aseSentinel.blocks"].getChildren()[0];
  assert.equal(views["aseSentinel.blocks"].getChildren(rule)[0].label, "203.0.113.2");
});
